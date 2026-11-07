//! Explicit local-validator test of the server's Pyth freshness on the parity
//! stack, whose price account is written only by the replay of Pyth's
//! sponsored SOL/USD feed (`scripts/localnet/pyth-replay.mjs`): real signed
//! mainnet updates, posted exactly when the sponsor would (60 s heartbeat or a
//! 0.5% move), so the local price ages as under the sponsor alone.
//!
//! Start `scripts/localnet/stack.mjs` with `ZKAPI_STATE_SEED` and
//! `ZKAPI_CLEAR_SEED`, then run, with the same seeds and the stack's printed
//! `identityPath`, `rpcUrl` and `replayControlUrl`:
//! `DAGON_SOLANA_IDENTITY=… DAGON_SOLANA_RPC_URL=… DAGON_PYTH_REPLAY_CONTROL_URL=…
//! cargo test --release -p zkapi-serverd --test localnet_pyth -- --ignored --nocapture`.
//! It runs alongside the `localnet` lifecycle test of `dagon-zkapi-solana-ledger`.
//!
//! 1. Sponsor cadence: the real startup gate passes, and every quote the
//!    server's oracle reads across two consecutive replayed updates is within
//!    the profile's 90 s maximum age. An older observed quote stays acceptable
//!    only within the newest-observed conservative-price tolerance.
//! 2. Sponsor stall: with the replay stalled, the account keeps its last price
//!    until that price is older than the maximum age. From then on the oracle
//!    refuses to quote, lease admission refuses the last observed quote, and
//!    server startup fails: fail closed, never a stale price.
//! 3. Recovery: once the replay resumes, quoting and startup succeed again.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use dagon_zkapi_profile::{NetworkIdentity, SharedProfile};
use serde_json::{json, Value};
use zkapi_serverd::{
    billing::{BillingPriceSource, BillingQuote},
    config::{OpenRouterLeaseSourceConfig, ServerConfig},
    error::ServerError,
    routes::prepare_solana_backends,
    signer::ServerSigner,
    sol_billing::PythBillingOracle,
};
use zkapi_types::Felt252;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required; see the module docs"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn sleep(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

struct Stack {
    http: reqwest::Client,
    rpc_url: String,
    control_url: String,
    price_account: String,
}

impl Stack {
    /// Drive the replay through the stack's loopback control endpoint.
    async fn control(&self, method: reqwest::Method, path: &str) -> Value {
        let response = self
            .http
            .request(method, format!("{}{path}", self.control_url))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "replay control {path}: {}",
            response.status()
        );
        response.json().await.unwrap()
    }

    /// Publish time and verification level of the finalized price account,
    /// read without the oracle (which refuses a stale account).
    async fn finalized_price(&self) -> (u64, u8) {
        let response: Value = self
            .http
            .post(&self.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"getAccountInfo",
                "params":[self.price_account, {"encoding":"base64","commitment":"finalized"}]}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let data = base64::engine::general_purpose::STANDARD
            .decode(response["result"]["value"]["data"][0].as_str().unwrap())
            .unwrap();
        assert_eq!(data.len(), 134, "PriceUpdateV2 account");
        let publish_time = i64::from_le_bytes(data[93..101].try_into().unwrap());
        (u64::try_from(publish_time).unwrap(), data[40])
    }
}

#[tokio::test]
#[ignore = "requires scripts/localnet/stack.mjs and its replay control URL"]
async fn sponsored_cadence_keeps_quotes_fresh_and_a_stall_fails_closed() {
    let profile = SharedProfile::embedded();
    let max_age = profile.pyth.max_age_seconds;
    let identity = NetworkIdentity::load(Path::new(&env("DAGON_SOLANA_IDENTITY"))).unwrap();
    let seed = |name: &str| Felt252::from_hex(&env(name)).unwrap();
    let config = ServerConfig::new(
        identity.network.clone(),
        identity.resolve(profile).unwrap(),
        env("DAGON_SOLANA_RPC_URL"),
        OpenRouterLeaseSourceConfig::OpenRouter {
            management_key: "not-used-by-this-test".into(),
            api_base: "http://127.0.0.1:9".into(),
        },
        seed("ZKAPI_STATE_SEED"),
        seed("ZKAPI_CLEAR_SEED"),
    );
    let signer = ServerSigner::new(&config.state_seed, &config.clear_seed);
    let oracle = PythBillingOracle::new(&config).unwrap();
    let stack = Stack {
        http: reqwest::Client::new(),
        rpc_url: config.rpc_url.clone(),
        control_url: env("DAGON_PYTH_REPLAY_CONTROL_URL"),
        price_account: config.billing_pins().feed_account,
    };
    assert_eq!(
        stack.control(reqwest::Method::GET, "/status").await["stalled"],
        false
    );

    // ---- 1. Sponsor cadence: startup and every quote across two new updates.
    prepare_solana_backends(&config, &signer)
        .await
        .expect("server startup passes on the sponsored feed");
    let deadline = now() + 300;
    let mut publishes: Vec<u64> = Vec::new();
    let mut previous: Option<BillingQuote> = None;
    let (mut samples, mut oldest) = (0, 0);
    while publishes.len() < 3 {
        assert!(
            now() < deadline,
            "the replay posted too few updates in 300 s: {publishes:?}"
        );
        let read_at = now();
        let quote = oracle.quote(read_at).await.unwrap_or_else(|error| {
            panic!("quote refused under the sponsored cadence after {publishes:?}: {error}")
        });
        oldest = oldest.max(read_at.saturating_sub(quote.publish_time));
        if publishes.last() != Some(&quote.publish_time) {
            if let Some(older) = previous.as_ref() {
                // Admission refreshes the account; a fast drop may supersede
                // this still-unexpired quote while the newer read is in flight.
                let at = now();
                let admitted = oracle.validate(older, at).await;
                match oracle.assert_admissible(older, at) {
                    Ok(()) => admitted.expect("observed quote within policy survives"),
                    Err(ServerError::NativeQuoteSuperseded) => {
                        assert!(matches!(admitted, Err(ServerError::NativeQuoteSuperseded)));
                    }
                    Err(ServerError::NativeQuoteExpired) => {
                        assert!(matches!(admitted, Err(ServerError::NativeQuoteExpired)));
                    }
                    Err(error) => panic!("unexpected admission policy failure: {error}"),
                }
            }
            publishes.push(quote.publish_time);
        }
        previous = Some(quote);
        samples += 1;
        sleep(2).await;
    }
    let intervals: Vec<u64> = publishes.windows(2).map(|w| w[1] - w[0]).collect();
    println!(
        "sponsored cadence: {samples} quotes accepted, update intervals {intervals:?} s, \
         oldest price quoted {oldest} s (maximum {max_age} s)"
    );
    assert!(oldest < max_age);

    // ---- 2. Sponsor stall: the last price ages out, then everything refuses.
    let stalled = stack.control(reqwest::Method::POST, "/stall").await;
    assert_eq!(stalled["stalled"], true);
    let posted = stalled["last_publish_time"]
        .as_u64()
        .expect("the replay posted");
    let deadline = now() + 60;
    let last = loop {
        // The last replayed update may still be finalizing.
        let quote = oracle.quote(now()).await.unwrap();
        if quote.publish_time == posted {
            break quote;
        }
        assert!(now() < deadline, "the last replayed update never finalized");
        sleep(1).await;
    };
    while now() + 2 < last.expires_at {
        // No writer while stalled: the same price is quoted until it expires.
        assert_eq!(oracle.quote(now()).await.unwrap(), last);
        sleep(2).await;
    }
    while now() <= last.expires_at {
        sleep(1).await;
    }
    let (publish_time, verification) = stack.finalized_price().await;
    assert_eq!(
        publish_time, last.publish_time,
        "nothing landed while stalled"
    );
    assert_eq!(verification, 1, "the stale price is still fully verified");
    let age = now() - publish_time;
    assert!(age > max_age, "the price is {age} s old");
    assert!(
        matches!(
            oracle.quote(now()).await,
            Err(ServerError::NativeQuoteExpired)
        ),
        "a {age} s old price must not be quoted"
    );
    assert!(
        matches!(
            oracle.validate(&last, now()).await,
            Err(ServerError::NativeQuoteExpired)
        ),
        "lease admission refuses the last observed quote"
    );
    let startup = prepare_solana_backends(&config, &signer)
        .await
        .err()
        .expect("server startup fails closed on a stale price")
        .to_string();
    assert!(startup.contains("expired"), "{startup}");
    println!(
        "sponsor stall: price {age} s old (maximum {max_age} s): quote, lease admission \
         and startup refused"
    );

    // ---- 3. Recovery: the next replayed update makes the feed usable again.
    assert_eq!(
        stack.control(reqwest::Method::POST, "/resume").await["stalled"],
        false
    );
    let deadline = now() + 180;
    let recovered = loop {
        match oracle.quote(now()).await {
            Ok(quote) => break quote,
            Err(ServerError::NativeQuoteExpired) => {
                assert!(now() < deadline, "the replay did not recover in 180 s");
                sleep(2).await;
            }
            Err(error) => panic!("unexpected oracle failure while recovering: {error}"),
        }
    };
    assert!(recovered.publish_time > last.publish_time);
    oracle.validate(&recovered, now()).await.unwrap();
    prepare_solana_backends(&config, &signer)
        .await
        .expect("server startup passes again after the sponsor recovers");
    println!(
        "sponsor recovered: publish_time {} quoted at age {} s",
        recovered.publish_time,
        now() - recovered.publish_time
    );
}
