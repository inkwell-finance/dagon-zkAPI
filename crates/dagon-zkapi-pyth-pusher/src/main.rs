//! `dagon-zkapi-pyth-pusher`: keeps the profile's SOL/USD push-oracle account
//! fresh at the profile's cadence. See the library docs for the trust model.

use anyhow::{bail, ensure, Context, Result};
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use base64::Engine;
use clap::Parser;
use dagon_zkapi_profile::{NetworkIdentity, SharedProfile};
use dagon_zkapi_pyth_pusher::{
    close_encoded_vaa, decode_price_account, hermes_binary, parse_update, push_packets,
    OnChainPrice, PythAccounts, SignedUpdate, ENCODED_VAA_HEADER, ENCODED_VAA_SEED,
    MAX_TRANSACTION_FEE,
};
use rand::Rng;
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::{
    collections::HashMap,
    fmt::Write as _,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?)
}

/// The Hermes API key. Read from the environment only, never from argv.
const API_KEY_ENV: &str = "PYTH_HERMES_API_KEY";

#[derive(Parser)]
#[command(
    about = "Push signed Pyth SOL/USD updates from Hermes into the profile's push-oracle account",
    long_about = "Feed, shard, programs, cadence and maximum age come from the compiled shared profile. \
                  The Hermes API key is read from PYTH_HERMES_API_KEY."
)]
struct Args {
    /// Network identity; its pyth_price_account must be the profile's push-oracle account.
    #[arg(long)]
    solana_identity: PathBuf,
    /// Solana RPC endpoint (confirmed and finalized reads, transaction submission).
    #[arg(long)]
    solana_rpc_url: String,
    /// Solana CLI keypair file of the funded fee payer.
    #[arg(long)]
    payer_keypair: PathBuf,
    /// Hermes base URL. HTTPS is required except on loopback.
    #[arg(long, default_value = "https://hermes.pyth.network")]
    hermes_url: String,
    /// Health and Prometheus metrics listener.
    #[arg(long, default_value = "0.0.0.0:3002")]
    listen: SocketAddr,
    /// Compute-unit price of every push packet.
    #[arg(long, default_value_t = 10_000)]
    priority_fee_micro_lamports: u64,
    /// Protected payer reserve; new payments must leave at least this balance.
    #[arg(long, default_value_t = 2_000_000_000)]
    min_balance_lamports: u64,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

/// Exponential backoff with jitter for one retried HTTP call.
async fn backoff(attempt: u32) {
    let base = 250u64 << attempt.min(4);
    let jitter = rand::thread_rng().gen_range(0..=base / 2);
    tokio::time::sleep(Duration::from_millis(base + jitter)).await;
}

const HTTP_ATTEMPTS: u32 = 4;

fn retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

struct Rpc {
    client: reqwest::Client,
    url: String,
}

/// A simulation must preserve the reserve and spend at most the fee ceiling
/// across the payer AND reusable rent account. Rent movements are not spending.
fn check_payment(before: u64, after: u64, payer_after: u64, reserve: u64, fee: u64) -> Result<()> {
    ensure!(
        fee <= MAX_TRANSACTION_FEE,
        "transaction fee exceeds safety ceiling"
    );
    ensure!(
        payer_after >= reserve,
        "payment would consume the protected payer reserve"
    );
    ensure!(
        before.saturating_sub(after) <= MAX_TRANSACTION_FEE,
        "simulated payment exceeds safety ceiling"
    );
    Ok(())
}

/// A blockhash plus the last block height at which a transaction using it can land.
#[derive(Clone, Copy, Default)]
struct RecentBlockhash {
    hash: Hash,
    last_valid_block_height: u64,
}

#[derive(Clone)]
struct PendingPayment {
    signature: String,
    blockhash: RecentBlockhash,
    counted: bool,
}

#[derive(Default)]
struct PaymentGuard {
    attempted: AtomicBool,
    failed_cycles: Mutex<u32>,
    paused: AtomicBool,
    pending: Mutex<Option<PendingPayment>>,
}

impl PaymentGuard {
    fn finish_cycle(&self, success: bool) {
        let attempted = self.attempted.swap(false, Ordering::Relaxed);
        let mut failures = self.failed_cycles.lock().unwrap();
        if success && attempted {
            *failures = 0;
        } else if attempted {
            *failures += 1;
            if *failures >= 3 {
                self.paused.store(true, Ordering::Relaxed);
            }
        }
    }
}

struct PaymentPolicy<'a> {
    guard: &'a PaymentGuard,
    reserve: u64,
    encoded_vaa: Pubkey,
}

impl Rpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut attempt = 0;
        loop {
            let outcome = async {
                let response = self.client.post(&self.url).json(&body).send().await?;
                let status = response.status();
                if !status.is_success() {
                    return Ok::<_, anyhow::Error>(Err((
                        retryable(status),
                        format!("HTTP {status}"),
                    )));
                }
                let value: Value = response.json().await?;
                if let Some(error) = value.get("error") {
                    let rate_limited = error["code"] == 429 || error["code"] == -32429;
                    return Ok(Err((rate_limited, error.to_string())));
                }
                Ok(Ok(value["result"].clone()))
            }
            .await;
            let (retry, message) = match outcome {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(failure)) => failure,
                Err(transport) => (true, transport.to_string()),
            };
            attempt += 1;
            if !retry || attempt >= HTTP_ATTEMPTS {
                bail!("{method}: {message}");
            }
            backoff(attempt).await;
        }
    }

    /// `(lamports, data)` of each account at `commitment`; `None` if absent.
    async fn accounts(
        &self,
        keys: &[Pubkey],
        commitment: &str,
    ) -> Result<Vec<Option<(u64, Vec<u8>, String)>>> {
        let keys: Vec<String> = keys.iter().map(Pubkey::to_string).collect();
        let result = self
            .call(
                "getMultipleAccounts",
                json!([keys, {"encoding": "base64", "commitment": commitment}]),
            )
            .await?;
        result["value"]
            .as_array()
            .context("account list")?
            .iter()
            .map(|account| {
                if account.is_null() {
                    return Ok(None);
                }
                Ok(Some((
                    account["lamports"].as_u64().context("lamports")?,
                    base64::engine::general_purpose::STANDARD
                        .decode(account["data"][0].as_str().context("account data")?)?,
                    account["owner"].as_str().context("owner")?.to_owned(),
                )))
            })
            .collect()
    }

    /// A timed-out submission may still land. Resolve it before signing another
    /// payment, including when sendTransaction's response was lost.
    async fn reconcile_payment(&self, guard: &PaymentGuard) -> Result<()> {
        let pending = guard.pending.lock().unwrap().clone();
        let Some(pending) = pending else {
            return Ok(());
        };
        // Check expiry first, then history: the reverse order could miss a
        // transaction landing between the status read and blockhash expiry.
        // Compare against the finalized height, not isBlockhashValid at
        // finalized: a confirmed blockhash newer than the finalized bank is
        // reported invalid there although the transaction can still land.
        let finalized_height = self
            .call("getBlockHeight", json!([{"commitment": "finalized"}]))
            .await?
            .as_u64()
            .context("finalized block height")?;
        let valid = finalized_height <= pending.blockhash.last_valid_block_height;
        let statuses = self
            .call(
                "getSignatureStatuses",
                json!([[pending.signature], {"searchTransactionHistory": true}]),
            )
            .await?;
        let status = &statuses["value"][0];
        if !status.is_null() && !pending.counted {
            guard.pending.lock().unwrap().as_mut().unwrap().counted = true;
            guard.attempted.store(true, Ordering::Relaxed);
            // This payment belongs to an already failed cycle, not to whatever
            // update the next cycle might successfully push.
            guard.finish_cycle(false);
        }
        if matches!(
            status["confirmationStatus"].as_str(),
            Some("confirmed" | "finalized")
        ) || (status.is_null() && !valid)
        {
            *guard.pending.lock().unwrap() = None;
            return Ok(());
        }
        bail!("previous payment is unresolved; waiting for confirmation or expiry")
    }

    async fn send(
        &self,
        payer: &Keypair,
        instructions: &[Instruction],
        blockhash: &RecentBlockhash,
        deadline: Instant,
        policy: PaymentPolicy<'_>,
    ) -> Result<String> {
        let PaymentPolicy {
            guard,
            reserve,
            encoded_vaa,
        } = policy;
        let message = Message::new_with_blockhash(
            instructions,
            Some(&payer.pubkey()),
            &blockhash.hash,
        )
        .serialize();
        ensure!(
            !guard.paused.load(Ordering::Relaxed),
            "payments paused; investigate and restart"
        );
        ensure!(
            guard.pending.lock().unwrap().is_none(),
            "previous payment is unresolved"
        );
        ensure!(
            Instant::now() < deadline,
            "push deadline elapsed before payment"
        );
        let fee = self
            .call(
                "getFeeForMessage",
                json!([
                    base64::engine::general_purpose::STANDARD.encode(&message),
                    {"commitment": "confirmed"}
                ]),
            )
            .await?["value"]
            .as_u64()
            .context("transaction fee unavailable")?;
        ensure!(
            fee <= MAX_TRANSACTION_FEE,
            "transaction fee exceeds safety ceiling"
        );
        let signed = payer.sign_message(&message);
        let mut transaction = vec![1];
        transaction.extend_from_slice(signed.as_ref());
        transaction.extend_from_slice(&message);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&transaction);
        let keys = [payer.pubkey(), encoded_vaa];
        let before = self.accounts(&keys, "confirmed").await?;
        let equity = before
            .iter()
            .flatten()
            .try_fold(0u64, |sum, a| sum.checked_add(a.0))
            .context("payer equity overflow")?;
        let simulation = self
            .call(
                "simulateTransaction",
                json!([encoded, {
                    "encoding": "base64", "commitment": "confirmed", "sigVerify": true,
                    "accounts": {"encoding": "base64", "addresses": keys.map(|k| k.to_string())}
                }]),
            )
            .await?;
        ensure!(
            simulation["value"]["err"].is_null(),
            "payment simulation failed: {}",
            simulation["value"]["err"]
        );
        let simulated = simulation["value"]["accounts"]
            .as_array()
            .context("simulation accounts")?;
        ensure!(simulated.len() == 2, "simulation account count");
        let payer_after = simulated[0]["lamports"]
            .as_u64()
            .context("simulated payer balance")?;
        let after = payer_after
            .checked_add(if simulated[1].is_null() {
                0
            } else {
                simulated[1]["lamports"]
                    .as_u64()
                    .context("simulated rent balance")?
            })
            .context("simulated equity overflow")?;
        check_payment(equity, after, payer_after, reserve, fee)?;
        ensure!(
            Instant::now() < deadline,
            "push deadline elapsed before payment"
        );
        // Retain the locally known signature before awaiting broadcast: an RPC
        // error or cancellation does not prove the transaction was not sent.
        let signature = signed.to_string();
        *guard.pending.lock().unwrap() = Some(PendingPayment {
            signature: signature.clone(),
            blockhash: *blockhash,
            counted: false,
        });
        self.call(
            "sendTransaction",
            json!([encoded, {"encoding": "base64", "preflightCommitment": "confirmed", "maxRetries": 0}]),
        )
        .await?;
        let mut last_send = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let statuses = self
                .call("getSignatureStatuses", json!([[signature]]))
                .await?;
            let status = &statuses["value"][0];
            if !status.is_null() {
                guard.attempted.store(true, Ordering::Relaxed);
                guard.pending.lock().unwrap().as_mut().unwrap().counted = true;
                if matches!(
                    status["confirmationStatus"].as_str(),
                    Some("confirmed" | "finalized")
                ) {
                    *guard.pending.lock().unwrap() = None;
                }
                ensure!(
                    status["err"].is_null(),
                    "transaction {signature} failed: {}",
                    status["err"]
                );
                if matches!(
                    status["confirmationStatus"].as_str(),
                    Some("confirmed" | "finalized")
                ) {
                    return Ok(signature);
                }
            }
            ensure!(
                Instant::now() < deadline,
                "transaction {signature} not confirmed before the push deadline"
            );
            // Rebroadcast: RPC nodes drop packets under load; the signature dedups.
            if last_send.elapsed() >= Duration::from_secs(2) {
                self.call(
                    "sendTransaction",
                    json!([encoded, {"encoding": "base64", "skipPreflight": true, "maxRetries": 0}]),
                )
                .await
                .ok();
                last_send = Instant::now();
            }
        }
    }
}

#[derive(Debug)]
enum HermesError {
    Auth(String),
    Other(anyhow::Error),
}

struct Hermes {
    client: reqwest::Client,
    url: String,
    api_key: String,
    feed: [u8; 32],
}

impl Hermes {
    async fn latest(&self) -> std::result::Result<SignedUpdate, HermesError> {
        let feed: String = self.feed.iter().map(|b| format!("{b:02x}")).collect();
        let url = format!("{}/v2/updates/price/latest", self.url.trim_end_matches('/'));
        let mut attempt = 0;
        loop {
            let response = self
                .client
                .get(&url)
                .query(&[
                    ("ids[]", format!("0x{feed}").as_str()),
                    ("encoding", "base64"),
                    ("parsed", "false"),
                ])
                .bearer_auth(&self.api_key)
                .send()
                .await;
            let retry = match response {
                Ok(response) if response.status().is_success() => {
                    // Bound untrusted bodies before JSON/PNAU decoding.
                    let mut response = response;
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|e| HermesError::Other(e.without_url().into()))?
                    {
                        if bytes.len() + chunk.len() > 128 * 1024 {
                            return Err(HermesError::Other(anyhow::anyhow!(
                                "Hermes response too large"
                            )));
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    let body: Value =
                        serde_json::from_slice(&bytes).map_err(|e| HermesError::Other(e.into()))?;
                    return hermes_binary(&body)
                        .and_then(|binary| parse_update(&binary, &self.feed))
                        .map_err(HermesError::Other);
                }
                Ok(response) => {
                    let status = response.status();
                    if status == reqwest::StatusCode::UNAUTHORIZED
                        || status == reqwest::StatusCode::FORBIDDEN
                    {
                        return Err(HermesError::Auth(format!(
                            "Hermes refused the API key: HTTP {status}"
                        )));
                    }
                    (retryable(status), anyhow::anyhow!("Hermes HTTP {status}"))
                }
                Err(error) => (true, anyhow::Error::from(error.without_url())),
            };
            attempt += 1;
            if !retry.0 || attempt >= HTTP_ATTEMPTS {
                return Err(HermesError::Other(retry.1));
            }
            backoff(attempt).await;
        }
    }
}

#[derive(Default)]
struct Metrics {
    pushes_landed: u64,
    pushes_skipped: u64,
    failures: HashMap<&'static str, u64>,
    consecutive_failures: u64,
    leftover_vaas_closed: u64,
    last_success: Option<i64>,
    last_push_seconds: f64,
    lamports_spent: u64,
    payer_balance: Option<u64>,
    last_equity: Option<u64>,
    hermes_publish_time: Option<i64>,
    confirmed: Option<OnChainPrice>,
    finalized: Option<OnChainPrice>,
    finalized_observed_at: Option<i64>,
}

struct Shared {
    metrics: Mutex<Metrics>,
    max_age: i64,
    interval: i64,
    min_balance: u64,
    payments: PaymentGuard,
}

impl Shared {
    /// Healthy while the account the server reads (finalized) is within the
    /// profile's max age and was observed recently.
    fn healthy(&self) -> (bool, Value) {
        let m = self.metrics.lock().unwrap();
        let now = now_secs();
        let age = m.finalized.map(|p| now - p.publish_time);
        let observed = m
            .finalized_observed_at
            .is_some_and(|at| (0..=3 * self.interval).contains(&(now - at)));
        let healthy = observed && age.is_some_and(|age| (0..self.max_age).contains(&age));
        (
            healthy,
            json!({
                "status": if healthy { "ok" } else { "stale" },
                "finalized_age_seconds": age,
                "max_age_seconds": self.max_age,
                "consecutive_failures": m.consecutive_failures,
                "payer_balance_lamports": m.payer_balance,
            }),
        )
    }

    fn render(&self) -> String {
        let m = self.metrics.lock().unwrap();
        let now = now_secs();
        let mut out = String::new();
        let mut gauge = |name: &str, help: &str, kind: &str, samples: &[(&str, f64)]| {
            let _ = writeln!(out, "# HELP dagon_pyth_pusher_{name} {help}");
            let _ = writeln!(out, "# TYPE dagon_pyth_pusher_{name} {kind}");
            for (labels, value) in samples {
                let _ = writeln!(out, "dagon_pyth_pusher_{name}{labels} {value}");
            }
        };
        gauge(
            "push_interval_seconds",
            "Profile push cadence.",
            "gauge",
            &[("", self.interval as f64)],
        );
        gauge(
            "max_age_seconds",
            "Profile Pyth max age the server enforces.",
            "gauge",
            &[("", self.max_age as f64)],
        );
        gauge(
            "pushes_total",
            "Push attempts by result.",
            "counter",
            &[
                ("{result=\"landed\"}", m.pushes_landed as f64),
                ("{result=\"not_newer\"}", m.pushes_skipped as f64),
            ],
        );
        let failures: Vec<(String, f64)> = ["hermes_auth", "hermes", "rpc", "transaction"]
            .iter()
            .map(|stage| {
                (
                    format!("{{stage=\"{stage}\"}}"),
                    *m.failures.get(stage).unwrap_or(&0) as f64,
                )
            })
            .collect();
        let failures: Vec<(&str, f64)> = failures.iter().map(|(l, v)| (l.as_str(), *v)).collect();
        gauge(
            "failures_total",
            "Failed push cycles by stage.",
            "counter",
            &failures,
        );
        gauge(
            "payments_paused",
            "Payments latched off after three failed paid cycles; operator restart required.",
            "gauge",
            &[(
                "",
                u8::from(self.payments.paused.load(Ordering::Relaxed)) as f64,
            )],
        );
        gauge(
            "consecutive_failures",
            "Failed push cycles since the last success.",
            "gauge",
            &[("", m.consecutive_failures as f64)],
        );
        gauge(
            "leftover_vaas_closed_total",
            "Encoded-VAA accounts of interrupted pushes reclaimed.",
            "counter",
            &[("", m.leftover_vaas_closed as f64)],
        );
        gauge(
            "last_push_duration_seconds",
            "Duration of the last landed push.",
            "gauge",
            &[("", m.last_push_seconds)],
        );
        gauge(
            "lamports_spent_total",
            "Payer lamports spent on pushes (fees net of reclaimed rent).",
            "counter",
            &[("", m.lamports_spent as f64)],
        );
        let mut optional = |name: &str, help: &str, samples: Vec<(&str, Option<i64>)>| {
            let samples: Vec<(&str, f64)> = samples
                .into_iter()
                .filter_map(|(labels, v)| v.map(|v| (labels, v as f64)))
                .collect();
            gauge(name, help, "gauge", &samples);
        };
        optional(
            "last_success_timestamp_seconds",
            "Unix time of the last successful cycle.",
            vec![("", m.last_success)],
        );
        optional(
            "payer_balance_lamports",
            "Fee payer balance.",
            vec![("", m.payer_balance.map(|v| v as i64))],
        );
        optional(
            "payer_balance_low",
            "1 when the payer balance is below --min-balance-lamports.",
            vec![("", m.payer_balance.map(|v| i64::from(v < self.min_balance)))],
        );
        optional(
            "hermes_publish_time_seconds",
            "Publish time of the newest Hermes update.",
            vec![("", m.hermes_publish_time)],
        );
        optional(
            "onchain_publish_time_seconds",
            "Publish time stored in the price account.",
            vec![
                (
                    "{commitment=\"confirmed\"}",
                    m.confirmed.map(|p| p.publish_time),
                ),
                (
                    "{commitment=\"finalized\"}",
                    m.finalized.map(|p| p.publish_time),
                ),
            ],
        );
        optional(
            "onchain_age_seconds",
            "Age of the price account's update; finalized is what the server reads.",
            vec![
                (
                    "{commitment=\"confirmed\"}",
                    m.confirmed.map(|p| now - p.publish_time),
                ),
                (
                    "{commitment=\"finalized\"}",
                    m.finalized.map(|p| now - p.publish_time),
                ),
            ],
        );
        out
    }
}

enum Outcome {
    Landed {
        publish_time: i64,
        signatures: Vec<String>,
    },
    NotNewer,
}

struct Failure(&'static str, anyhow::Error);

struct Pusher {
    rpc: Rpc,
    hermes: Hermes,
    payer: Keypair,
    accounts: PythAccounts,
    priority: u64,
    deadline: Duration,
    rent: Mutex<HashMap<usize, u64>>,
    shared: Arc<Shared>,
}

impl Pusher {
    fn rpc_failure(error: anyhow::Error) -> Failure {
        Failure("rpc", error)
    }

    async fn rent(&self, space: usize) -> Result<u64> {
        if let Some(rent) = self.rent.lock().unwrap().get(&space) {
            return Ok(*rent);
        }
        let rent = self
            .rpc
            .call("getMinimumBalanceForRentExemption", json!([space]))
            .await?
            .as_u64()
            .context("rent")?;
        self.rent.lock().unwrap().insert(space, rent);
        Ok(rent)
    }

    async fn blockhash(&self) -> Result<RecentBlockhash> {
        let latest = self
            .rpc
            .call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))
            .await?;
        Ok(RecentBlockhash {
            hash: Hash::from_str(latest["value"]["blockhash"].as_str().context("blockhash")?)?,
            last_valid_block_height: latest["value"]["lastValidBlockHeight"]
                .as_u64()
                .context("last valid block height")?,
        })
    }

    fn price(&self, account: &Option<(u64, Vec<u8>, String)>) -> Result<Option<OnChainPrice>> {
        let Some((_, data, owner)) = account else {
            return Ok(None);
        };
        ensure!(
            *owner == self.accounts.receiver.to_string(),
            "price account owner is not the Pyth receiver"
        );
        decode_price_account(data, &self.accounts.feed_id).map(Some)
    }

    async fn cycle(&self) -> std::result::Result<Outcome, Failure> {
        let started = Instant::now();
        let deadline = started + self.deadline;
        let payer = self.payer.pubkey();
        let encoded = self.accounts.encoded_vaa(&payer);
        let state = self
            .rpc
            .accounts(&[self.accounts.price_account, encoded, payer], "confirmed")
            .await
            .map_err(Self::rpc_failure)?;
        let confirmed = self.price(&state[0]).map_err(Self::rpc_failure)?;
        let balance_before = state[2].as_ref().map_or(0, |a| a.0);
        {
            let mut m = self.shared.metrics.lock().unwrap();
            m.confirmed = confirmed;
            m.payer_balance = Some(balance_before);
            let equity = balance_before.saturating_add(state[1].as_ref().map_or(0, |a| a.0));
            if let Some(previous) = m.last_equity {
                m.lamports_spent += previous.saturating_sub(equity);
            }
            m.last_equity = Some(equity);
        }
        let finalized = self
            .rpc
            .accounts(&[self.accounts.price_account], "finalized")
            .await
            .and_then(|state| self.price(&state[0]))
            .map_err(Self::rpc_failure)?;
        {
            let mut m = self.shared.metrics.lock().unwrap();
            m.finalized = finalized;
            m.finalized_observed_at = Some(now_secs());
        }
        self.rpc
            .reconcile_payment(&self.shared.payments)
            .await
            .map_err(|e| Failure("transaction", e))?;
        if self.shared.payments.paused.load(Ordering::Relaxed) {
            return Err(Failure(
                "transaction",
                anyhow::anyhow!("payments paused; investigate and restart"),
            ));
        }
        if let Some((lamports, data, owner)) = &state[1] {
            // Anyone can pre-fund this predictable address. The base signer
            // can recover an empty system account with transfer_with_seed;
            // Wormhole close is only valid after a VAA has been initialized.
            let close = [
                if *owner == solana_system_interface::program::ID.to_string() && data.is_empty() {
                    solana_system_interface::instruction::transfer_with_seed(
                        &encoded,
                        &payer,
                        ENCODED_VAA_SEED.to_owned(),
                        &self.accounts.wormhole,
                        &payer,
                        *lamports,
                    )
                } else {
                    close_encoded_vaa(&self.accounts.wormhole, &payer, &encoded)
                },
            ];
            let blockhash = self.blockhash().await.map_err(Self::rpc_failure)?;
            self.rpc
                .send(
                    &self.payer,
                    &close,
                    &blockhash,
                    deadline,
                    PaymentPolicy {
                        guard: &self.shared.payments,
                        reserve: self.shared.min_balance,
                        encoded_vaa: encoded,
                    },
                )
                .await
                .map_err(|e| Failure("transaction", e))?;
            self.shared.metrics.lock().unwrap().leftover_vaas_closed += 1;
            tracing::warn!(%encoded, "closed the encoded VAA of an interrupted push");
        }
        let update = self.hermes.latest().await.map_err(|error| match error {
            HermesError::Auth(message) => Failure("hermes_auth", anyhow::anyhow!(message)),
            HermesError::Other(error) => Failure("hermes", error),
        })?;
        self.shared.metrics.lock().unwrap().hermes_publish_time = Some(update.publish_time);
        // The push oracle ignores updates that are not newer; do not pay for them.
        if confirmed.is_some_and(|price| update.publish_time <= price.publish_time) {
            return Ok(Outcome::NotNewer);
        }
        if !(0..=self.shared.max_age).contains(&now_secs().saturating_sub(update.publish_time)) {
            return Err(Failure(
                "hermes",
                anyhow::anyhow!("Hermes publication is future or expired"),
            ));
        }
        let rent = self
            .rent(ENCODED_VAA_HEADER + update.vaa.len())
            .await
            .map_err(Self::rpc_failure)?;
        let treasury_id = rand::thread_rng().gen();
        let packets = push_packets(
            &self.accounts,
            &payer,
            &update,
            treasury_id,
            rent,
            self.priority,
        )
        .map_err(|e| Failure("transaction", e))?;
        let blockhash = self.blockhash().await.map_err(Self::rpc_failure)?;
        let mut signatures = Vec::with_capacity(packets.len());
        for packet in &packets {
            signatures.push(
                self.rpc
                    .send(
                        &self.payer,
                        packet,
                        &blockhash,
                        deadline,
                        PaymentPolicy {
                            guard: &self.shared.payments,
                            reserve: self.shared.min_balance,
                            encoded_vaa: encoded,
                        },
                    )
                    .await
                    .map_err(|e| Failure("transaction", e))?,
            );
        }
        self.shared.metrics.lock().unwrap().last_push_seconds = started.elapsed().as_secs_f64();
        Ok(Outcome::Landed {
            publish_time: update.publish_time,
            signatures,
        })
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

fn check_hermes_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid Hermes URL")?;
    ensure!(
        parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "Hermes URL must not contain credentials, query or fragment"
    );
    let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    ensure!(
        parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback),
        "the Hermes API key is only sent over HTTPS (or plain HTTP to loopback)"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let profile = SharedProfile::embedded();
    let identity = NetworkIdentity::load(&args.solana_identity)?;
    // Fail closed unless the identity pins exactly the account this pusher writes.
    identity.pyth_price_account(profile)?;
    let accounts = PythAccounts::from_profile(profile);
    let api_key = std::env::var(API_KEY_ENV)
        .ok()
        .filter(|key| !key.is_empty())
        .with_context(|| format!("{API_KEY_ENV} must hold the Hermes API key"))?;
    check_hermes_url(&args.hermes_url)?;
    let bytes: Vec<u8> = serde_json::from_slice(
        &std::fs::read(&args.payer_keypair).context("reading the payer keypair")?,
    )
    .context("payer keypair must be a Solana CLI JSON keypair")?;
    let payer = Keypair::try_from(bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("invalid payer keypair: {e}"))?;
    let client = http_client()?;
    let rpc = Rpc {
        client: client.clone(),
        url: args.solana_rpc_url,
    };
    ensure!(
        rpc.call("getGenesisHash", json!([])).await? == identity.genesis_hash,
        "RPC genesis differs from the identity"
    );
    let interval = profile.pyth.push_interval_seconds;
    let max_age = profile.pyth.max_age_seconds;
    let shared = Arc::new(Shared {
        metrics: Mutex::new(Metrics::default()),
        max_age: max_age as i64,
        interval: interval as i64,
        min_balance: args.min_balance_lamports,
        payments: PaymentGuard::default(),
    });
    let pusher = Pusher {
        rpc,
        hermes: Hermes {
            client,
            url: args.hermes_url,
            api_key,
            feed: accounts.feed_id,
        },
        payer,
        priority: args.priority_fee_micro_lamports,
        // A push older than this is superseded by a fresher Hermes update.
        deadline: Duration::from_secs(3 * interval),
        accounts,
        rent: Mutex::new(HashMap::new()),
        shared: shared.clone(),
    };
    let app = Router::new()
        .route(
            "/health",
            get(|State(shared): State<Arc<Shared>>| async move {
                let (healthy, body) = shared.healthy();
                let status = if healthy {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                (status, axum::Json(body)).into_response()
            }),
        )
        .route(
            "/metrics",
            get(|State(shared): State<Arc<Shared>>| async move {
                (
                    [("content-type", "text/plain; version=0.0.4")],
                    shared.render(),
                )
            }),
        )
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(
        listen = %listener.local_addr()?,
        price_account = %pusher.accounts.price_account,
        payer = %pusher.payer.pubkey(),
        interval_seconds = interval,
        "Pyth pusher started"
    );
    tokio::spawn(async move { axum::serve(listener, app).await });

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut next = Instant::now();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep_until(next.into()) => {}
        }
        let started = Instant::now();
        let outcome = tokio::select! {
            _ = &mut shutdown => break,
            outcome = tokio::time::timeout(pusher.deadline + Duration::from_secs(5), pusher.cycle()) => outcome
                .unwrap_or_else(|_| Err(Failure("rpc", anyhow::anyhow!("push cycle timed out")))),
        };
        shared
            .payments
            .finish_cycle(matches!(&outcome, Ok(Outcome::Landed { .. })));
        let failures = {
            let mut m = shared.metrics.lock().unwrap();
            match &outcome {
                Ok(outcome) => {
                    m.consecutive_failures = 0;
                    m.last_success = Some(now_secs());
                    match outcome {
                        Outcome::Landed { .. } => m.pushes_landed += 1,
                        Outcome::NotNewer => m.pushes_skipped += 1,
                    }
                }
                Err(Failure(stage, _)) => {
                    m.consecutive_failures += 1;
                    *m.failures.entry(stage).or_default() += 1;
                }
            }
            m.consecutive_failures
        };
        match outcome {
            Ok(Outcome::Landed {
                publish_time,
                signatures,
            }) => tracing::info!(
                publish_time,
                age_seconds = now_secs() - publish_time,
                ?signatures,
                "pushed a fully verified SOL/USD update"
            ),
            Ok(Outcome::NotNewer) => tracing::debug!("on-chain update is already as new as Hermes"),
            Err(Failure(stage, error)) => {
                tracing::warn!(
                    stage,
                    consecutive_failures = failures,
                    "push failed: {error:#}"
                )
            }
        }
        // Keep the profile cadence; back off on repeated failures, never past
        // half the max age.
        let factor = 1u64 << failures.saturating_sub(1).min(3);
        let delay = Duration::from_secs((interval * factor).min((max_age / 2).max(interval)));
        let jitter = rand::thread_rng().gen_range(0.9..=1.1);
        next = started + delay.mul_f64(if failures > 0 { jitter } else { 1.0 });
    }
    tracing::info!("Pyth pusher stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn fee_and_equity_limits_preserve_rent_and_reserve() {
        assert!(check_payment(3_000_000, 2_995_000, 2_000_000, 2_000_000, 5000).is_ok());
        assert!(check_payment(3_000_000, 2_995_000, 1_999_999, 2_000_000, 5000).is_err());
        assert!(check_payment(3_000_000, 2_949_999, 2_949_999, 0, 5000).is_err());
        assert!(
            check_payment(3_000_000, 3_000_000, 3_000_000, 0, MAX_TRANSACTION_FEE + 1).is_err()
        );
        // Closing an orphan refunds rent rather than spending it.
        assert!(check_payment(3_000_000, 2_995_000, 2_995_000, 2_000_000, 5000).is_ok());
    }

    #[test]
    fn failed_paid_cycles_latch_even_across_unpaid_successes() {
        let guard = PaymentGuard::default();
        for i in 0..3 {
            guard.attempted.store(true, Ordering::Relaxed);
            guard.finish_cycle(false);
            guard.finish_cycle(true); // a not-newer response cannot reset failures
            assert_eq!(guard.paused.load(Ordering::Relaxed), i == 2);
        }
        guard.finish_cycle(true);
        assert!(guard.paused.load(Ordering::Relaxed));
    }

    #[test]
    fn hermes_urls_cannot_embed_secrets_or_use_remote_http() {
        for url in [
            "https://user:secret@hermes.example",
            "https://hermes.example?key=secret",
            "https://hermes.example#secret",
            "http://hermes.example",
        ] {
            assert!(check_hermes_url(url).is_err());
        }
        assert!(check_hermes_url("https://hermes.pyth.network").is_ok());
        assert!(check_hermes_url("http://127.0.0.1:1234").is_ok());
    }

    #[tokio::test]
    async fn hermes_does_not_follow_redirects_with_the_bearer_key() {
        let followed = Arc::new(AtomicUsize::new(0));
        let count = followed.clone();
        let app = Router::new()
            .route(
                "/v2/updates/price/latest",
                get(|| async { (StatusCode::FOUND, [("location", "/capture")]) }),
            )
            .route(
                "/capture",
                get(move || {
                    count.fetch_add(1, Ordering::Relaxed);
                    async { "must not receive the key" }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let hermes = Hermes {
            client: http_client().unwrap(),
            url,
            api_key: "secret".into(),
            feed: [0; 32],
        };
        let error = hermes.latest().await.unwrap_err();
        assert!(!format!("{error:?}").contains("secret"));
        assert_eq!(followed.load(Ordering::Relaxed), 0);
        task.abort();
    }

    #[tokio::test]
    async fn payment_gate_rejects_before_broadcast_and_accepts_safe_close() {
        for (fee, balance, simulation_error, allowed) in [
            (MAX_TRANSACTION_FEE + 1, 3_000_000, false, false),
            (5000, 1_999_999, false, false),
            (5000, 2_995_000, true, false),
            (5000, 2_995_000, false, true),
        ] {
            let sends = Arc::new(AtomicUsize::new(0));
            let count = sends.clone();
            let app = Router::new().route("/", post(move |Json(body): Json<Value>| {
                let count = count.clone();
                async move {
                    Json(json!({"result": match body["method"].as_str().unwrap() {
                        "getFeeForMessage" => json!({"value": fee}),
                        "getMultipleAccounts" => json!({"value": [
                            {"lamports": 1_000_000, "data": ["", "base64"], "owner": ""},
                            {"lamports": 2_000_000, "data": ["", "base64"], "owner": ""}
                        ]}),
                        "simulateTransaction" => json!({"value": {
                            "err": if simulation_error { json!("invalid signature") } else { Value::Null },
                            "accounts": [{"lamports": balance}, null]
                        }}),
                        "sendTransaction" => {
                            count.fetch_add(1, Ordering::Relaxed);
                            json!("test-signature")
                        },
                        "getSignatureStatuses" => json!({"value": [{
                            "err": null, "confirmationStatus": "confirmed"
                        }]}),
                        other => panic!("unexpected RPC {other}")
                    }}))
                }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let rpc = Rpc {
                client: http_client().unwrap(),
                url,
            };
            let guard = PaymentGuard::default();
            let result = rpc
                .send(
                    &Keypair::new(),
                    &[],
                    &RecentBlockhash::default(),
                    Instant::now() + Duration::from_secs(5),
                    PaymentPolicy {
                        guard: &guard,
                        reserve: 2_000_000,
                        encoded_vaa: Pubkey::new_unique(),
                    },
                )
                .await;
            assert_eq!(result.is_ok(), allowed, "{result:?}");
            assert_eq!(sends.load(Ordering::Relaxed), usize::from(allowed));
            task.abort();
        }
    }

    #[tokio::test]
    async fn ambiguous_payments_block_until_resolved_and_late_landings_latch() {
        for lost_response in [false, true] {
            for lands_late in [false, true] {
                // 0: pending, 1: processed, 2: confirmed, 3: expired unseen.
                let phase = Arc::new(AtomicUsize::new(0));
                let sends = Arc::new(AtomicUsize::new(0));
                let rpc_phase = phase.clone();
                let rpc_sends = sends.clone();
                let app = Router::new().route("/", post(move |Json(body): Json<Value>| {
                    let phase = rpc_phase.clone();
                    let sends = rpc_sends.clone();
                    async move {
                        let phase = phase.load(Ordering::Relaxed);
                        let result = match body["method"].as_str().unwrap() {
                            "getFeeForMessage" => json!({"value": 5000}),
                            "getMultipleAccounts" => json!({"value": [
                                {"lamports": 3_000_000, "data": ["", "base64"], "owner": ""}, null
                            ]}),
                            "simulateTransaction" => json!({"value": {
                                "err": null, "accounts": [{"lamports": 2_995_000}, null]
                            }}),
                            "sendTransaction" => {
                                sends.fetch_add(1, Ordering::Relaxed);
                                if lost_response {
                                    return Json(json!({"error": {"code": -32000, "message": "ambiguous submission"}}));
                                }
                                json!("rpc-signature-is-not-used")
                            },
                            "getBlockHeight" => {
                                assert_eq!(body["params"][0]["commitment"], "finalized");
                                json!(if phase == 3 { 1 } else { 0 })
                            },
                            "getSignatureStatuses" => {
                                if phase != 0 {
                                    assert_eq!(body["params"][1]["searchTransactionHistory"], true);
                                }
                                let error = if lost_response { Value::Null } else { json!("failed") };
                                json!({"value": [match phase {
                                    1 => json!({"err": error, "confirmationStatus": "processed"}),
                                    2 => json!({"err": error, "confirmationStatus": "confirmed"}),
                                    _ => Value::Null,
                                }]})
                            },
                            other => panic!("unexpected RPC {other}"),
                        };
                        Json(json!({"result": result}))
                    }
                }));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
                let rpc = Rpc {
                    client: http_client().unwrap(),
                    url,
                };
                let guard = PaymentGuard::default();
                let payer = Keypair::new();
                let encoded_vaa = Pubkey::new_unique();
                for cycle in 0..3 {
                    phase.store(0, Ordering::Relaxed);
                    let policy = || PaymentPolicy {
                        guard: &guard,
                        reserve: 2_000_000,
                        encoded_vaa,
                    };
                    assert!(rpc
                        .send(
                            &payer,
                            &[],
                            &RecentBlockhash::default(),
                            Instant::now() + Duration::from_secs(1),
                            policy(),
                        )
                        .await
                        .is_err());
                    assert!(guard.pending.lock().unwrap().is_some());
                    assert!(!guard.attempted.load(Ordering::Relaxed));
                    guard.finish_cycle(false);
                    assert!(rpc.reconcile_payment(&guard).await.is_err());
                    // No second transaction may simulate against a balance
                    // that does not yet reflect the unresolved payment.
                    assert!(rpc
                        .send(
                            &payer,
                            &[],
                            &RecentBlockhash::default(),
                            Instant::now() + Duration::from_secs(1),
                            policy(),
                        )
                        .await
                        .is_err());
                    assert_eq!(sends.load(Ordering::Relaxed), cycle + 1);
                    if lands_late {
                        phase.store(1, Ordering::Relaxed);
                        assert!(rpc.reconcile_payment(&guard).await.is_err());
                        assert!(rpc.reconcile_payment(&guard).await.is_err());
                        assert_eq!(*guard.failed_cycles.lock().unwrap(), (cycle + 1) as u32);
                        phase.store(2, Ordering::Relaxed);
                    } else {
                        phase.store(3, Ordering::Relaxed);
                    }
                    rpc.reconcile_payment(&guard).await.unwrap();
                    assert!(guard.pending.lock().unwrap().is_none());
                    guard.finish_cycle(true); // unpaid skips must not reset failures
                    assert_eq!(guard.paused.load(Ordering::Relaxed), lands_late && cycle == 2);
                    if !lands_late {
                        assert_eq!(*guard.failed_cycles.lock().unwrap(), 0);
                    }
                }
                task.abort();
            }
        }
    }

    #[tokio::test]
    async fn only_transactions_with_a_status_count_as_paid_attempts() {
        for (status, paid) in [
            (Value::Null, false),
            (
                json!({"err": {"InstructionError": [2, {"Custom": 1}]}, "confirmationStatus": "processed"}),
                true,
            ),
        ] {
            let app = Router::new().route(
                "/",
                post(move |Json(body): Json<Value>| {
                    let status = status.clone();
                    async move {
                        Json(json!({"result": match body["method"].as_str().unwrap() {
                            "getFeeForMessage" => json!({"value": 5000}),
                            "getMultipleAccounts" => json!({"value": [
                                {"lamports": 3_000_000, "data": ["", "base64"], "owner": ""}, null
                            ]}),
                            "simulateTransaction" => json!({"value": {
                                "err": null, "accounts": [{"lamports": 2_995_000}, null]
                            }}),
                            "sendTransaction" => json!("test-signature"),
                            "getBlockHeight" => json!(0),
                            "getSignatureStatuses" => json!({"value": [status]}),
                            other => panic!("unexpected RPC {other}")
                        }}))
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let rpc = Rpc {
                client: http_client().unwrap(),
                url,
            };
            let guard = PaymentGuard::default();
            let policy = PaymentPolicy {
                guard: &guard,
                reserve: 2_000_000,
                encoded_vaa: Pubkey::new_unique(),
            };
            let deadline = Instant::now() + Duration::from_millis(1500);
            assert!(rpc
                .send(&Keypair::new(), &[], &RecentBlockhash::default(), deadline, policy)
                .await
                .is_err());
            assert_eq!(guard.attempted.load(Ordering::Relaxed), paid);
            guard.finish_cycle(false);
            assert!(rpc.reconcile_payment(&guard).await.is_err());
            assert_eq!(*guard.failed_cycles.lock().unwrap(), u32::from(paid));
            assert!(guard.pending.lock().unwrap().is_some());
            task.abort();
        }
    }
}
