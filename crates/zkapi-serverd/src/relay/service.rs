//! The relay: fee-paying, rent-paying helper for emergency-key (ek) users.
//!
//! Threat model and the defences here:
//!
//! * **Malicious user griefing the SOL float.** No debt is ever extended:
//!   every charged relayer spend is collected by a USDC fee transfer signed
//!   by the ek *in the same transaction* (close, escape, deposit execute,
//!   burn, sweep), so the spend and its payment land or fail together.
//!   Ek-co-signed transactions are prepared unsigned with a sealed ticket;
//!   the relay signs, reserves float/loss budget and broadcasts only when
//!   the ek-signed bytes are submitted back ([`Relay::submit`]), so an
//!   unsubmitted preparation holds nothing. At most one submission per ek
//!   is executable at a time, and each failure must be covered by a
//!   one-failure sponsorship credential (an attested minted inbound transfer
//!   or a relayed exit); uncredentialed work has its own small loss budget.
//!   A fallback receive is the one uncharged subsidy (no fee fits the
//!   packet next to the 312-byte inbound hook): it needs a valid attested
//!   zkAPI message and an existing `ATA(ek)`, so the relayer only funds the
//!   never-closable `used_nonce`, once per message. Deposits are atomic:
//!   ek owns the buffer, the relay advances rent and gets the buffer rent
//!   back in the same signed message. No standalone staging is broadcast.
//!   Per-owner and global rate limits bound the rest.
//! * **Malicious third party.** The relayer signs only messages built here
//!   or by the ledger, and only after [`crate::relay::tx`]'s audit: it is
//!   fee/rent payer and never a token authority. Prepared transactions need
//!   the ek's signature, so nobody else can spend ek funds; finalize and
//!   release are relayer-paid only for escapes the relayer itself funded.
//! * **Circle pause.** Burns and receives read the MessageTransmitter and
//!   TokenMinter `paused` flags and fail with `cctp_paused`.
//! * **Relayer float exhausted.** Below the SOL floor every operation fails
//!   with `relayer_unavailable` before spending anything.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dagon_zkapi_ledger::{
    CreditLedger, FinalizeEscapeRequest, LedgerAccount, LedgerCommitment, LedgerError,
    LedgerTransactionStatus, PreparedLedgerOperation, ReleaseEscapePayoutRequest,
    SignedLedgerTransaction, WithdrawalRequest,
};
use dagon_zkapi_solana_ledger::{
    cctp, deposit_operation_account_len, note_account_len, pending_withdrawal_account_len,
    used_nullifier_account_len, AddressLookupTableAccount, RelayedDepositRequest,
    SolanaCreditLedger, SolanaMessage as Message, SolanaPubkey as Pubkey, PENDING_STAGE_OPEN,
    PENDING_STAGE_PAYOUT_PARKED, SIGNED_TRANSACTION_FORMAT, TOKEN_ACCOUNT_SPACE, USDC_MINT,
};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zkapi_types::wire::Groth16ProofWire;
use zkapi_types::{Felt252, WithdrawalPublicInputsV2, MERKLE_DEPTH};

use super::config::RelayConfig;
use super::fees::{self, RelayKind, RentTable, SIGNATURE_LAMPORTS};
use super::iris::{decode_hex, IrisClient};
use super::store::{self, RelayStore};
use super::ticket::{message_digest, Ticket, TicketEvent, TicketKey, TicketKind};
use super::tx::{self, SignedTransaction};

/// Authenticated submissions per owner per window.
const PER_KEY_LIMIT: usize = 6;
/// Requests per kind per window across all callers.
const GLOBAL_LIMIT: usize = 120;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);
const CONFIRM_POLL: Duration = Duration::from_millis(500);
/// `MessageSent` space without hook data: 8 + 32 + 8 + 4 + header + body.
const MESSAGE_SENT_BASE_SPACE: usize = 8 + 32 + 8 + 4 + 148 + 228;
/// `relay_meta` key of the relay's address lookup table.
const LOOKUP_TABLE_META_KEY: &str = "lookup_table";
/// Largest burn hook the relay prepares (the burn must fit one packet).
pub const MAX_HOOK_BYTES: usize = 192;
const RECLAIM_RETRY_MS: u64 = 3_600_000;
const RECLAIM_SLACK_SECONDS: i64 = 60;
/// A cached receive transaction is handed out again only while it has at
/// least this many blocks (~12 s) of validity left.
const RECEIVE_REUSE_MARGIN_BLOCKS: u64 = 30;

/// `{error: {code, message}}` with the HTTP status of the code.
#[derive(Debug)]
pub struct RelayError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl RelayError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn disabled() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "relay_disabled",
            "this server has no relay configured",
        )
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    fn insufficient(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "insufficient_funds", message)
    }

    fn above_cap(fee: u64, max_fee: u64) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "relay_fee_above_cap",
            format!("relay fee {fee} exceeds max_fee {max_fee}"),
        )
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "relayer_unavailable",
            message,
        )
    }

    fn paused(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "cctp_paused", message)
    }

    fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "relayer_unavailable",
            message,
        )
    }
}

impl From<LedgerError> for RelayError {
    fn from(error: LedgerError) -> Self {
        match error {
            LedgerError::Rejected(_) | LedgerError::Unsupported { .. } => {
                Self::invalid(error.to_string())
            }
            other => Self::unavailable(other.to_string()),
        }
    }
}

impl From<store::StoreError> for RelayError {
    fn from(error: store::StoreError) -> Self {
        Self::internal(error.to_string())
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": {"code": self.code, "message": self.message}
            })),
        )
            .into_response()
    }
}

pub type RelayResult<T> = Result<T, RelayError>;

/// Sliding-window request limiter keyed by caller-chosen strings.
struct RateLimiter {
    windows: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Admit one request against every `(key, limit)` or none of them.
    fn admit(&self, keys: &[(String, usize)], now: Instant) -> bool {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if windows.len() > 50_000 {
            windows.retain(|_, hits| {
                hits.back()
                    .is_some_and(|last| now.duration_since(*last) < RATE_WINDOW)
            });
        }
        for (key, limit) in keys {
            let hits = windows.entry(key.clone()).or_default();
            while hits
                .front()
                .is_some_and(|first| now.duration_since(*first) >= RATE_WINDOW)
            {
                hits.pop_front();
            }
            if hits.len() >= *limit {
                return false;
            }
        }
        for (key, _) in keys {
            windows.entry(key.clone()).or_default().push_back(now);
        }
        true
    }
}

// ----- request and response bodies ------------------------------------

/// An attested inbound CCTP transfer that funded `ATA(owner)`: a costly,
/// unique sponsorship credential (see [`Relay::submit`]).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundCredential {
    pub source_domain: u32,
    pub message: String,
    pub attestation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositBody {
    pub depositor: String,
    pub expected_note_id: u32,
    pub commitment: Felt252,
    pub amount: String,
    pub zero_path: Vec<Felt252>,
    pub max_fee: String,
    #[serde(default)]
    pub inbound: Option<InboundCredential>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveBody {
    pub source_domain: u32,
    pub transaction_hash: String,
    /// The emergency key named by the inbound hook (signs the fee).
    pub owner: String,
    pub max_fee: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitKind {
    Mutual,
    Escape,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitBody {
    pub kind: ExitKind,
    pub destination_owner: String,
    pub public_inputs: WithdrawalPublicInputsV2,
    pub proof: Groth16ProofWire,
    pub max_fee: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeBody {
    pub note_id: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurnBody {
    pub owner: String,
    pub destination_domain: u32,
    pub mint_recipient: String,
    #[serde(default)]
    pub destination_caller: Option<String>,
    pub max_cctp_fee: String,
    pub min_finality_threshold: u32,
    #[serde(default)]
    pub hook_data: String,
    pub max_fee: String,
    #[serde(default)]
    pub inbound: Option<InboundCredential>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SweepBody {
    pub owner: String,
    pub destination: String,
    pub max_fee: String,
    #[serde(default)]
    pub inbound: Option<InboundCredential>,
}

/// The ek-signed transaction of a prepare, with its ticket.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitBody {
    pub token: String,
    pub transaction: Vec<u8>,
}

/// Wire format of a v0 transaction resolved through `lookup_tables`.
pub const V0_TRANSACTION_FORMAT: &str = "solana-v0-transaction-v1";

/// A relayer-owned address lookup table a v0 transaction uses.
#[derive(Debug, Clone, Serialize)]
pub struct LookupTableWire {
    pub address: String,
    pub addresses: Vec<String>,
}

/// A wire transaction: unsigned when prepared for the ek, complete when the
/// relay signed it (receive, submit).
#[derive(Debug, Serialize)]
pub struct TransactionWire {
    pub format: &'static str,
    pub bytes: Vec<u8>,
    pub last_valid_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_tables: Option<Vec<LookupTableWire>>,
}

impl TransactionWire {
    fn new(bytes: &[u8], last_valid_height: u64) -> Self {
        Self {
            format: SIGNED_TRANSACTION_FORMAT,
            bytes: bytes.to_vec(),
            last_valid_height,
            lookup_tables: None,
        }
    }

    fn v0(bytes: &[u8], last_valid_height: u64, table: &AddressLookupTableAccount) -> Self {
        Self {
            format: V0_TRANSACTION_FORMAT,
            bytes: bytes.to_vec(),
            last_valid_height,
            lookup_tables: Some(vec![LookupTableWire {
                address: table.key.to_string(),
                addresses: table.addresses.iter().map(ToString::to_string).collect(),
            }]),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Quotes {
    pub deposit: String,
    pub receive: String,
    pub close: String,
    pub escape: String,
    pub burn: String,
    pub sweep: String,
}

#[derive(Debug, Serialize)]
pub struct RelayInfo {
    pub relayer: String,
    pub fee_account: String,
    pub margin_bps: u32,
    pub sol_usd_micros: String,
    pub usdc_mint: String,
    pub quotes: Quotes,
    pub iris_url: String,
    /// Smallest relayed CCTP burn after the relay fee (USDC base units).
    pub burn_minimum: String,
}

#[derive(Debug, Serialize)]
pub struct DepositResponse {
    pub fee: String,
    pub operation: String,
    pub note: String,
    pub operation_rent: String,
    pub note_rent: String,
    pub transaction: TransactionWire,
    pub submit_token: String,
}

#[derive(Debug, Serialize)]
pub struct ReceiveResponse {
    pub fee: String,
    pub nonce: String,
    pub recipient_token_account: String,
    /// `None` when the message's nonce is already used (received by Circle's
    /// Forwarding Service or anyone else).
    pub transaction: Option<TransactionWire>,
}

#[derive(Debug, Serialize)]
pub struct ExitResponse {
    pub fee: String,
    pub destination: String,
    pub transaction: TransactionWire,
    pub submit_token: String,
}

#[derive(Debug, Serialize)]
pub struct FinalizeResponse {
    pub signature: String,
    pub action: &'static str,
}

#[derive(Debug, Serialize)]
pub struct BurnResponse {
    pub fee: String,
    pub amount: String,
    pub message_sent_event_account: String,
    pub transaction: TransactionWire,
    pub submit_token: String,
}

#[derive(Debug, Serialize)]
pub struct SweepResponse {
    pub fee: String,
    pub amount: String,
    pub transaction: TransactionWire,
    pub submit_token: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub signature: String,
    pub transaction: TransactionWire,
}

// ----- parsing ----------------------------------------------------------

fn parse_amount(value: &str, label: &str) -> RelayResult<u64> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RelayError::invalid(format!(
            "{label} must be a decimal string of base units"
        )));
    }
    value
        .parse()
        .map_err(|_| RelayError::invalid(format!("{label} exceeds u64")))
}

fn parse_hex(value: &str, label: &str, max_len: usize) -> RelayResult<Vec<u8>> {
    let bytes =
        decode_hex(value).ok_or_else(|| RelayError::invalid(format!("{label} must be hex")))?;
    if bytes.len() > max_len {
        return Err(RelayError::invalid(format!(
            "{label} exceeds {max_len} bytes"
        )));
    }
    Ok(bytes)
}

fn parse_hex32(value: &str, label: &str) -> RelayResult<[u8; 32]> {
    parse_hex(value, label, 32)?
        .try_into()
        .map_err(|_| RelayError::invalid(format!("{label} must be 32 bytes of hex")))
}

fn ata(owner: &Pubkey) -> Pubkey {
    Pubkey::new_from_array(dagon_zkapi_profile::usdc_associated_token_address(
        &owner.to_bytes(),
    ))
}

fn decode_message(bytes: &[u8]) -> RelayResult<Message> {
    let message: Message = bincode::deserialize(bytes)
        .map_err(|error| RelayError::internal(format!("prepared message: {error}")))?;
    if message.serialize() != bytes {
        return Err(RelayError::internal("prepared message is not canonical"));
    }
    Ok(message)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// The network fee a transaction costs its fee payer (no priority fee).
fn signature_lamports(bytes: &[u8]) -> RelayResult<u64> {
    bytes
        .first()
        .copied()
        .filter(|count| (1..=3).contains(count))
        .map(|count| u64::from(count) * SIGNATURE_LAMPORTS)
        .ok_or_else(|| RelayError::internal("invalid relay signature count"))
}

/// Anchor code of the vault's `StaleNoteId` (another deposit took the note id).
const VAULT_STALE_NOTE_ID: u64 = 6006;

/// Whether a failure `reason` (`getSignatureStatuses` `err` JSON) is the
/// vault's note-id contention at the deposit's `execute_deposit`: any landed
/// deposit causes it, so it is nobody's fault. With one executable
/// submission per ek, causing it on purpose costs a real deposit.
fn note_id_contention(reason: &str, contended: Option<u8>) -> bool {
    let Some(contended) = contended else {
        return false;
    };
    let Ok(error) = serde_json::from_str::<serde_json::Value>(reason) else {
        return false;
    };
    let failed = &error["InstructionError"];
    failed[0].as_u64() == Some(u64::from(contended))
        && failed[1]["Custom"].as_u64() == Some(VAULT_STALE_NOTE_ID)
}

/// Whether a reservation was newly made (`false`: already outstanding).
fn admitted(admission: store::RiskAdmission) -> RelayResult<bool> {
    use store::RiskAdmission;
    let refused = |code, message| {
        Err(RelayError::new(
            StatusCode::TOO_MANY_REQUESTS,
            code,
            message,
        ))
    };
    match admission {
        RiskAdmission::Accepted => Ok(true),
        RiskAdmission::AlreadyReserved => Ok(false),
        RiskAdmission::LossBudgetExhausted => refused("relay_loss_budget_exhausted",
            "daily failed-fee budget plus outstanding reservations is exhausted; use your own SOL"),
        RiskAdmission::AddressBlocked => refused("relay_failure_limited",
            "source or emergency key has three unreimbursed failures in 24 hours; use your own SOL"),
        RiskAdmission::BurnFloatExhausted => refused("relay_burn_float_exhausted",
            "outstanding MessageSent rent allowance exhausted; use your own SOL or sweep"),
        RiskAdmission::SubmissionPending => refused("relay_submission_pending",
            "another relay transaction of this emergency key is still executable; retry after it lands or expires"),
        RiskAdmission::BackingSpent => refused("relay_backing_spent",
            "this emergency key's sponsorship credential already covered a failed transaction; use your own SOL"),
    }
}

/// Authenticate before any user-selected lookup-table extension spends SOL.
/// Circle's receive instruction remains the final on-chain authority.
fn verify_receive_attestation(state: &[u8], message: &[u8], attestation: &[u8]) -> RelayResult<()> {
    use sha3::{Digest, Keccak256};
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    let invalid = || RelayError::invalid("invalid CCTP attestation");
    if state.len() < 161 || !state.starts_with(&cctp::MESSAGE_TRANSMITTER_ACCOUNT) {
        return Err(invalid());
    }
    let threshold = u32::from_le_bytes(state[145..149].try_into().map_err(|_| invalid())?) as usize;
    let count = u32::from_le_bytes(state[149..153].try_into().map_err(|_| invalid())?) as usize;
    if threshold == 0
        || threshold > count
        || count > (state.len() - 161) / 32
        || state.len() != 161 + 32 * count
        || attestation.len() != threshold * 65
    {
        return Err(invalid());
    }
    let digest = Keccak256::digest(message);
    let mut previous = [0u8; 32];
    for signature in attestation.as_chunks::<65>().0 {
        if ![27, 28].contains(&signature[64]) || signature[32..64] > HALF_N[..] {
            return Err(invalid());
        }
        let key = solana_secp256k1_recover::secp256k1_recover(
            &digest,
            signature[64] - 27,
            &signature[..64],
        )
        .map_err(|_| invalid())?;
        let hash = Keccak256::digest(key.to_bytes());
        let mut address = [0u8; 32];
        address[12..].copy_from_slice(&hash[12..]);
        if address <= previous
            || !state[153..153 + 32 * count]
                .as_chunks::<32>()
                .0
                .contains(&address)
        {
            return Err(invalid());
        }
        previous = address;
    }
    Ok(())
}

// ----- the relay --------------------------------------------------------

pub struct Relay {
    config: RelayConfig,
    relayer: Pubkey,
    vault_program: Pubkey,
    ledger: Arc<SolanaCreditLedger>,
    store: RelayStore,
    iris: IrisClient,
    rent: RentTable,
    limiter: RateLimiter,
    /// Serializes creation and extension of the relay's lookup table.
    lookup_table: tokio::sync::Mutex<()>,
    /// Serializes receive issuance: one outstanding transaction per nonce.
    receive_lock: tokio::sync::Mutex<()>,
    /// Keeps a duplicate submit from exposing signatures while the first
    /// broadcast can still reject and release its fresh reservation.
    submit_lock: tokio::sync::Mutex<()>,
    /// Seals prepare tickets and derives burn event keys.
    tickets: TicketKey,
}

impl Relay {
    /// Fail-closed relay startup against the server's validated deployment:
    /// the relayer key must be dedicated, the fee account an existing USDC
    /// account, and rent is read from the cluster.
    pub async fn start(
        config: RelayConfig,
        server: &crate::config::ServerConfig,
    ) -> anyhow::Result<Arc<Self>> {
        let ledger = Arc::new(SolanaCreditLedger::new(server.ledger_config())?);
        let identity = &server.identity;
        let mut others: Vec<(&str, [u8; 32])> = vec![
            ("vault authority", identity.vault_authority),
            ("vault state", identity.vault_state),
            ("treasury token account", identity.treasury_token_account),
            ("vault program", server.profile.program_id()),
        ];
        let treasury = Pubkey::new_from_array(identity.treasury_token_account);
        if let Some(account) = ledger.token_account_state(treasury).await? {
            others.push(("treasury owner", account.owner.to_bytes()));
        }
        if let Ok(path) = std::env::var("ZKAPI_CHALLENGE_SOLANA_KEYPAIR") {
            if let Ok(challenger) = solana_keypair::read_keypair_file(&path) {
                others.push(("challenge keypair", challenger.pubkey().to_bytes()));
            }
        }
        config.check_distinct(&others)?;
        let fee_account = ledger
            .token_account_state(config.fee_account)
            .await?
            .filter(|account| account.creditable(&USDC_MINT));
        anyhow::ensure!(
            fee_account.is_some(),
            "ZKAPI_RELAYER_FEE_ACCOUNT {} is not an unfrozen classic USDC token account",
            config.fee_account
        );
        let rent = RentTable {
            note: ledger.rent_exempt_minimum(note_account_len()).await?,
            used_nullifier: ledger
                .rent_exempt_minimum(used_nullifier_account_len())
                .await?,
            token_account: ledger.rent_exempt_minimum(TOKEN_ACCOUNT_SPACE).await?,
            used_nonce: ledger
                .rent_exempt_minimum(cctp::USED_NONCE_ACCOUNT_LEN)
                .await?,
        };
        for (kind, quoted) in
            fees::kinds_above_caps(&rent, config.sol_usd_micros, config.margin_bps)
        {
            tracing::warn!(
                ?kind,
                quoted,
                cap = kind.sdk_cap(),
                "relay quote exceeds the SDK fee cap; wallets will refuse it"
            );
        }
        let relayer = config.relayer();
        let balance = ledger.lamports(relayer).await?;
        if balance < config.min_lamports {
            tracing::warn!(
                %relayer,
                balance,
                floor = config.min_lamports,
                "relayer SOL balance is below the floor; the relay refuses work until refilled"
            );
        }
        let store = RelayStore::open(&server.db_path)?;
        let iris = IrisClient::new(&config.iris_url)?;
        tracing::info!(%relayer, fee_account = %config.fee_account, "CCTP relay enabled");
        let relay = Self {
            vault_program: ledger.program_id(),
            relayer,
            tickets: TicketKey::new(&config.keypair),
            config,
            ledger,
            store,
            iris,
            rent,
            limiter: RateLimiter::new(),
            lookup_table: tokio::sync::Mutex::new(()),
            receive_lock: tokio::sync::Mutex::new(()),
            submit_lock: tokio::sync::Mutex::new(()),
        };
        if let Err(error) = relay.warm_lookup_table().await {
            tracing::warn!(
                code = error.code,
                "relay lookup table not prepared at startup (retried on first use): {}",
                error.message
            );
        }
        Ok(Arc::new(relay))
    }

    fn fee_of(&self, lamports: u64) -> u64 {
        fees::fee_usdc(lamports, self.config.sol_usd_micros, self.config.margin_bps)
    }

    fn quote(&self, kind: RelayKind, creates_ata: bool) -> u64 {
        self.fee_of(fees::cost_lamports(kind, &self.rent, creates_ata))
    }

    pub fn info(&self) -> RelayInfo {
        let quote = |kind| {
            fees::quote(
                kind,
                &self.rent,
                self.config.sol_usd_micros,
                self.config.margin_bps,
            )
            .to_string()
        };
        RelayInfo {
            relayer: self.relayer.to_string(),
            fee_account: self.config.fee_account.to_string(),
            margin_bps: self.config.margin_bps,
            sol_usd_micros: self.config.sol_usd_micros.to_string(),
            usdc_mint: USDC_MINT.to_string(),
            quotes: Quotes {
                deposit: quote(RelayKind::Deposit),
                receive: quote(RelayKind::Receive),
                close: quote(RelayKind::Close),
                escape: quote(RelayKind::Escape),
                burn: quote(RelayKind::Burn),
                sweep: quote(RelayKind::Sweep),
            },
            iris_url: self.config.iris_url.clone(),
            burn_minimum: self.config.burn_minimum_amount.to_string(),
        }
    }

    /// A user key: canonical base58, nonzero, not the relayer.
    fn user_account(&self, value: &str, label: &str) -> RelayResult<Pubkey> {
        let bytes: [u8; 32] = bs58::decode(value)
            .into_vec()
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| RelayError::invalid(format!("{label} must be a base58 32-byte key")))?;
        let key = Pubkey::new_from_array(bytes);
        if bytes == [0; 32] || key == self.relayer {
            return Err(RelayError::invalid(format!(
                "{label} cannot be the zero account or the relayer"
            )));
        }
        Ok(key)
    }

    fn admit(&self, kind: &str, authenticated_owner: Option<&str>) -> RelayResult<()> {
        let keys = [match authenticated_owner {
            Some(owner) => (format!("{kind}:{owner}"), PER_KEY_LIMIT),
            None => (format!("{kind}:*"), GLOBAL_LIMIT),
        }];
        if self.limiter.admit(&keys, Instant::now()) {
            Ok(())
        } else {
            Err(RelayError::rate_limited(format!(
                "too many {kind} requests; retry in a minute"
            )))
        }
    }

    /// Refuse work below the SOL floor (plus what this operation spends).
    async fn ensure_float(&self, spend: u64) -> RelayResult<()> {
        let balance = self.ledger.lamports(self.relayer).await?;
        let needed = self.config.min_lamports.saturating_add(spend);
        if balance < needed {
            return Err(RelayError::unavailable(format!(
                "relayer SOL balance {balance} is below the floor {needed} lamports"
            )));
        }
        Ok(())
    }

    /// Refuse burns and receives while Circle has paused CCTP on Solana.
    async fn ensure_cctp_live(&self) -> RelayResult<()> {
        let accounts = cctp::CctpAccounts::new(USDC_MINT);
        for (address, program, decode, label) in [
            (
                accounts.message_transmitter,
                cctp::MESSAGE_TRANSMITTER_V2,
                cctp::message_transmitter_paused as fn(&[u8]) -> Result<bool, cctp::CctpError>,
                "MessageTransmitter",
            ),
            (
                accounts.token_minter,
                cctp::TOKEN_MESSENGER_MINTER_V2,
                cctp::token_minter_paused,
                "TokenMinter",
            ),
        ] {
            let account = self
                .ledger
                .raw_account(address, LedgerCommitment::Confirmed)
                .await?
                .filter(|account| account.owner == program)
                .ok_or_else(|| {
                    RelayError::unavailable(format!("CCTP {label} is not deployed on this cluster"))
                })?;
            let paused = decode(&account.data)
                .map_err(|error| RelayError::unavailable(error.to_string()))?;
            if paused {
                return Err(RelayError::paused(format!(
                    "Circle has paused the CCTP {label}"
                )));
            }
        }
        Ok(())
    }

    /// The balance of an existing unfrozen USDC account owned by `owner`.
    async fn usdc_balance(&self, owner: &Pubkey) -> RelayResult<u64> {
        let address = ata(owner);
        let account = self
            .ledger
            .token_account_state(address)
            .await?
            .ok_or_else(|| RelayError::insufficient(format!("{address} does not exist")))?;
        if !account.creditable(&USDC_MINT) || account.owner != *owner {
            return Err(RelayError::insufficient(format!(
                "{address} is not an unfrozen USDC account of {owner}"
            )));
        }
        Ok(account.amount)
    }

    fn sign(&self, message: &Message, others: &[&Keypair]) -> RelayResult<SignedTransaction> {
        tx::sign(message, &self.config.keypair, others, &self.vault_program)
            .map_err(|error| RelayError::internal(format!("relayer refused to sign: {error}")))
    }

    /// Audit an ek-facing legacy message and serialize it unsigned.
    fn unsigned(&self, message: &Message) -> RelayResult<Vec<u8>> {
        tx::unsigned(message, &self.relayer, &self.vault_program)
            .map_err(|error| RelayError::internal(format!("relayer refused to sign: {error}")))
    }

    /// Seal the ticket of an unsigned prepared transaction.
    #[allow(clippy::too_many_arguments)]
    fn ticket(
        &self,
        kind: TicketKind,
        bytes: &[u8],
        owner: &Pubkey,
        last_valid_height: u64,
        table: Option<&AddressLookupTableAccount>,
        event: Option<TicketEvent>,
        backing: Option<String>,
    ) -> RelayResult<String> {
        let message = tx::message_bytes(bytes).map_err(RelayError::internal)?;
        Ok(self.tickets.seal(&Ticket {
            kind,
            message: message_digest(message),
            owner: owner.to_string(),
            source: ata(owner).to_string(),
            last_valid_height,
            table: table.map(|table| table.key.to_string()),
            event,
            backing,
        }))
    }

    /// The sponsorship credential covering a failure of `owner`'s next
    /// transaction: a verified inbound credential (recorded once), else any
    /// unspent one on record; `None` means the work is unbacked.
    async fn backing(
        &self,
        owner: &Pubkey,
        inbound: Option<&InboundCredential>,
    ) -> RelayResult<Option<String>> {
        let owner_key = owner.to_string();
        let mut preferred = None;
        if let Some(credential) = inbound {
            // An unverifiable credential is ignored, never an error: the
            // operation is then served from the unbacked budget.
            match self.inbound_backing(owner, credential).await {
                Ok(Some(key)) if self.store.add_backing(&key, &owner_key)? => preferred = Some(key),
                Ok(_) => {}
                Err(error) => {
                    tracing::debug!(%owner, "inbound credential not verified: {}", error.message)
                }
            }
        }
        Ok(self
            .store
            .unspent_backing(&owner_key, preferred.as_deref())?)
    }

    /// `nonce:<hex>` of an attested, already minted zkAPI inbound transfer of
    /// any amount to `ATA(owner)`: a real source-chain burn plus its mint
    /// (gas and the forward fee or `used_nonce` rent, whatever the amount)
    /// costs its sender far more than the one failure it can cover, and every
    /// inbound CCTP user, including a first deposit, holds one.
    async fn inbound_backing(
        &self,
        owner: &Pubkey,
        credential: &InboundCredential,
    ) -> RelayResult<Option<String>> {
        let (Some(message), Some(attestation)) = (
            decode_hex(&credential.message).filter(|bytes| bytes.len() <= 2_048),
            decode_hex(&credential.attestation).filter(|bytes| bytes.len() <= 1_024),
        ) else {
            return Ok(None);
        };
        let Some(inbound) = InboundMessage::parse(&message, credential.source_domain)
            .filter(|inbound| inbound.owner == *owner)
        else {
            return Ok(None);
        };
        let Some(transmitter) = self
            .ledger
            .raw_account(
                cctp::CctpAccounts::new(USDC_MINT).message_transmitter,
                LedgerCommitment::Confirmed,
            )
            .await?
            .filter(|account| account.owner == cctp::MESSAGE_TRANSMITTER_V2)
        else {
            return Ok(None);
        };
        if verify_receive_attestation(&transmitter.data, &message, &attestation).is_err()
            || !self.nonce_used(&inbound.nonce).await?
        {
            return Ok(None);
        }
        Ok(Some(format!("nonce:{}", hex::encode(inbound.nonce))))
    }

    /// A prefunded PDA is not a mint: only Circle can create UsedNonce state.
    async fn nonce_used(&self, nonce: &[u8; 32]) -> RelayResult<bool> {
        Ok(self
            .ledger
            .raw_account(cctp::used_nonce(nonce), LedgerCommitment::Confirmed)
            .await?
            .is_some_and(|account| {
                account.owner == cctp::MESSAGE_TRANSMITTER_V2
                    && account.data == [212, 222, 157, 252, 130, 71, 179, 238, 1]
            }))
    }

    // ----- POST /v2/relay/submit ------------------------------------------

    /// Sign and broadcast an ek-signed transaction this relay prepared. All
    /// risk (loss budget, burn float, one executable submission per ek, the
    /// sponsorship credential) is reserved here, for transactions the relay
    /// itself broadcasts; an unsubmitted preparation holds nothing.
    /// Idempotent: the relay's (and event key's) Ed25519 signatures are
    /// deterministic, so a resubmission returns the same transaction.
    pub async fn submit(&self, body: SubmitBody) -> RelayResult<SubmitResponse> {
        let ticket = self
            .tickets
            .open(&body.token)
            .ok_or_else(|| RelayError::invalid("the submit token was not issued by this relay"))?;
        ticket
            .owner
            .parse::<Pubkey>()
            .map_err(|_| RelayError::internal("ticket owner is invalid"))?;
        self.admit("submit", None)?;
        let message = tx::message_bytes(&body.transaction).map_err(RelayError::invalid)?;
        if message_digest(message) != ticket.message {
            return Err(RelayError::invalid(
                "the transaction differs from the prepared one",
            ));
        }
        let event = match &ticket.event {
            None => None,
            Some(event) => Some(
                self.tickets
                    .event_keypair(&event.nonce)
                    .filter(|keypair| keypair.pubkey().to_string() == event.address)
                    .ok_or_else(|| RelayError::internal("ticket event key mismatch"))?,
            ),
        };
        let others: Vec<&Keypair> = event.iter().collect();
        let signed = tx::complete(&body.transaction, &self.config.keypair, &others)
            .map_err(RelayError::invalid)?;
        let wire = self.submitted_wire(&ticket, &signed).await?;
        // A resubmission of a transaction already on chain: nothing to do.
        if !matches!(
            self.ledger
                .transaction_status(signed.signature.clone().into_bytes())
                .await?,
            LedgerTransactionStatus::Unknown
        ) {
            return Ok(SubmitResponse {
                signature: signed.signature,
                transaction: wire,
            });
        }
        let height = self
            .ledger
            .transaction_height(LedgerCommitment::Confirmed)
            .await?;
        if height > ticket.last_valid_height {
            return Err(RelayError::new(
                StatusCode::CONFLICT,
                "relay_transaction_expired",
                "the prepared transaction expired; prepare it again",
            ));
        }
        // With every signature present: verifies the ek's signature and that
        // the funds are still there before anything is reserved.
        self.ledger
            .simulate_transaction(&signed.bytes, true)
            .await?;
        self.admit("submit", Some(&ticket.owner))?;
        let _submission = self.submit_lock.lock().await;
        let fresh = self.reserve_submission(&ticket, &signed).await?;
        // `submit` only labels the bytes; versioned bytes are sent as they are.
        match self
            .ledger
            .submit(SignedLedgerTransaction {
                format: SIGNED_TRANSACTION_FORMAT.into(),
                bytes: signed.bytes.clone(),
            })
            .await
        {
            Ok(_) => {}
            // Never left the relay: it cannot land, so nothing stays reserved.
            Err(LedgerError::Rejected(reason)) if fresh => {
                self.store.release_unbroadcast(&signed.signature)?;
                return Err(RelayError::invalid(format!(
                    "the transaction was rejected: {reason}"
                )));
            }
            // Possibly sent: the reservation stays until reconciliation.
            Err(error) => {
                tracing::warn!(signature = %signed.signature, "relay submission may not have been sent: {error}")
            }
        }
        Ok(SubmitResponse {
            signature: signed.signature,
            transaction: wire,
        })
    }

    /// Reserve a submission; first settles the ek's earlier submissions that
    /// finalized since the last maintenance tick.
    async fn reserve_submission(
        &self,
        ticket: &Ticket,
        signed: &SignedTransaction,
    ) -> RelayResult<bool> {
        let unbacked = ticket.backing.is_none();
        let issued = store::IssuedTransaction {
            signature: signed.signature.clone(),
            owner: ticket.owner.clone(),
            source: ticket.source.clone(),
            last_valid_height: ticket.last_valid_height,
            fee_lamports: signature_lamports(&signed.bytes)?,
            backing: ticket.backing.clone(),
            unbacked,
            contended_instruction: (ticket.kind == TicketKind::Deposit)
                .then(|| tx::last_program_instruction(&signed.bytes, &self.vault_program))
                .flatten(),
        };
        let budget = if unbacked {
            self.config.unbacked_daily_loss_lamports
        } else {
            self.config.daily_loss_lamports
        };
        let event = ticket.event.as_ref().map(|event| {
            (
                event.address.as_str(),
                event.rent,
                self.config.burn_float_lamports,
            )
        });
        let reserve = || {
            self.store
                .reserve_submission(&issued, now_ms(), budget, event)
        };
        let mut admission = reserve()?;
        if admission == store::RiskAdmission::SubmissionPending {
            let finalized = self
                .ledger
                .transaction_height(LedgerCommitment::Finalized)
                .await?;
            for pending in self.store.pending_submissions(&ticket.owner)? {
                self.settle(&pending, finalized).await?;
            }
            admission = reserve()?;
        }
        admitted(admission)
    }

    /// The complete transaction on the wire (v0: with the relay's table).
    async fn submitted_wire(
        &self,
        ticket: &Ticket,
        signed: &SignedTransaction,
    ) -> RelayResult<TransactionWire> {
        let Some(address) = &ticket.table else {
            return Ok(TransactionWire::new(
                &signed.bytes,
                ticket.last_valid_height,
            ));
        };
        let key: Pubkey = address
            .parse()
            .map_err(|_| RelayError::internal("ticket table is invalid"))?;
        let table = self
            .read_lookup_table(key)
            .await?
            .ok_or_else(|| RelayError::unavailable("the relay lookup table is not readable"))?;
        Ok(TransactionWire::v0(
            &signed.bytes,
            ticket.last_valid_height,
            &AddressLookupTableAccount {
                key,
                addresses: table.addresses,
            },
        ))
    }

    /// Send a fully signed relayer transaction and wait for confirmation.
    /// The bytes are persisted before broadcast; a timed-out send stays in
    /// flight for [`Self::reconcile_in_flight`] instead of being forgotten.
    async fn send_and_confirm(
        &self,
        label: &str,
        signed: &SignedTransaction,
        last_valid_height: u64,
    ) -> RelayResult<()> {
        self.reserve_issued(
            signed,
            last_valid_height,
            &self.relayer,
            "relay-internal",
            None,
        )?;
        self.store.insert_in_flight(&store::InFlight {
            signature: signed.signature.clone(),
            label: label.into(),
            bytes: signed.bytes.clone(),
            last_valid_height,
        })?;
        let submitted = self
            .ledger
            .submit(SignedLedgerTransaction {
                format: SIGNED_TRANSACTION_FORMAT.into(),
                bytes: signed.bytes.clone(),
            })
            .await;
        if let Err(error) = submitted {
            // A failed preflight was never broadcast; anything else may
            // have been and stays in flight.
            if matches!(error, LedgerError::Rejected(_)) {
                self.store.remove_in_flight(&signed.signature)?;
            }
            return Err(error.into());
        }
        let started = Instant::now();
        loop {
            match self
                .ledger
                .transaction_status(signed.signature.clone().into_bytes())
                .await?
            {
                LedgerTransactionStatus::Confirmed { .. }
                | LedgerTransactionStatus::Finalized { .. } => {
                    self.store.remove_in_flight(&signed.signature)?;
                    return Ok(());
                }
                LedgerTransactionStatus::Failed { reason } => {
                    self.store.remove_in_flight(&signed.signature)?;
                    return Err(RelayError::invalid(format!(
                        "transaction {} failed: {reason}",
                        signed.signature
                    )));
                }
                LedgerTransactionStatus::Unknown | LedgerTransactionStatus::Pending => {}
            }
            let height = self
                .ledger
                .transaction_height(LedgerCommitment::Confirmed)
                .await?;
            if height > last_valid_height || started.elapsed() > CONFIRM_TIMEOUT {
                return Err(RelayError::unavailable(format!(
                    "transaction {} is not confirmed yet; it stays tracked",
                    signed.signature
                )));
            }
            tokio::time::sleep(CONFIRM_POLL).await;
        }
    }

    /// Sign, simulate (all signatures present) and send one relayer-only
    /// prepared ledger transaction.
    async fn run_prepared(
        &self,
        label: &str,
        operation: PreparedLedgerOperation,
    ) -> RelayResult<String> {
        let [prepared] = <[_; 1]>::try_from(operation.transactions)
            .map_err(|_| RelayError::internal("expected one prepared transaction"))?;
        let message = decode_message(&prepared.bytes)?;
        let last_valid_height = prepared
            .last_valid_height
            .ok_or_else(|| RelayError::internal("prepared transaction has no expiry"))?;
        let signed = self.sign(&message, &[])?;
        self.ledger
            .simulate_transaction(&signed.bytes, true)
            .await?;
        self.send_and_confirm(label, &signed, last_valid_height)
            .await?;
        Ok(signed.signature)
    }

    /// Reconcile relayer transactions left in flight (timed out, or sent
    /// before a restart): drop them once they confirmed, failed or expired,
    /// and rebroadcast the same bytes while their blockhash is still valid.
    async fn reconcile_in_flight(&self) -> RelayResult<()> {
        let in_flight = self.store.in_flight()?;
        if in_flight.is_empty() {
            return Ok(());
        }
        let height = self
            .ledger
            .transaction_height(LedgerCommitment::Confirmed)
            .await?;
        for send in in_flight {
            match self
                .ledger
                .transaction_status(send.signature.clone().into_bytes())
                .await?
            {
                LedgerTransactionStatus::Confirmed { .. }
                | LedgerTransactionStatus::Finalized { .. }
                | LedgerTransactionStatus::Failed { .. } => {
                    self.store.remove_in_flight(&send.signature)?
                }
                LedgerTransactionStatus::Unknown if height > send.last_valid_height => {
                    self.store.remove_in_flight(&send.signature)?
                }
                LedgerTransactionStatus::Unknown => {
                    let resent = self
                        .ledger
                        .submit(SignedLedgerTransaction {
                            format: SIGNED_TRANSACTION_FORMAT.into(),
                            bytes: send.bytes.clone(),
                        })
                        .await;
                    if matches!(resent, Err(LedgerError::Rejected(_))) {
                        self.store.remove_in_flight(&send.signature)?;
                    }
                }
                LedgerTransactionStatus::Pending => {}
            }
        }
        Ok(())
    }

    /// The relayer's active lookup table, if `address` is one.
    async fn read_lookup_table(&self, address: Pubkey) -> RelayResult<Option<cctp::LookupTable>> {
        Ok(self
            .ledger
            .raw_account(address, LedgerCommitment::Confirmed)
            .await?
            .filter(|account| account.owner == cctp::ADDRESS_LOOKUP_TABLE_PROGRAM)
            .and_then(|account| cctp::LookupTable::parse(&account.data).ok())
            .filter(|table| {
                table.authority == Some(self.relayer) && table.deactivation_slot == u64::MAX
            }))
    }

    /// The relay's lookup table holding every address in `required` (created
    /// or extended by the relayer as needed, and warmed up for use).
    async fn lookup_table(
        &self,
        required: &[Pubkey],
        subsidy: Option<(&InboundMessage, u32)>,
    ) -> RelayResult<AddressLookupTableAccount> {
        let _guard = self.lookup_table.lock().await;
        let stored = self
            .store
            .meta(LOOKUP_TABLE_META_KEY)?
            .and_then(|value| value.parse::<Pubkey>().ok());
        let mut current = match stored {
            Some(address) => self
                .read_lookup_table(address)
                .await?
                .map(|table| (address, table)),
            None => None,
        };
        let mut missing: Vec<Pubkey> = Vec::new();
        for address in required {
            let known = current
                .as_ref()
                .is_some_and(|(_, table)| table.addresses.contains(address));
            if !known && !missing.contains(address) {
                missing.push(*address);
            }
        }
        let entries = current
            .as_ref()
            .map_or(0, |(_, table)| table.addresses.len());
        if entries + missing.len() > 256 {
            return Err(RelayError::internal("the relay lookup table is full"));
        }
        let rent = if missing.is_empty() {
            0
        } else {
            self.ledger
                .rent_exempt_minimum(cctp::LOOKUP_TABLE_META_SIZE + 32 * (entries + missing.len()))
                .await?
        };
        if let Some((inbound, source_domain)) = subsidy {
            let extension_cost = if missing.is_empty() {
                0
            } else {
                let before = if current.is_some() {
                    self.ledger
                        .rent_exempt_minimum(cctp::LOOKUP_TABLE_META_SIZE + 32 * entries)
                        .await?
                } else {
                    0
                };
                rent.saturating_sub(before)
                    .saturating_add(SIGNATURE_LAMPORTS)
            };
            self.reserve_receive_subsidy(
                inbound,
                source_domain,
                fees::cost_lamports(RelayKind::Receive, &self.rent, false),
                extension_cost,
            )?;
        }
        if !missing.is_empty() {
            self.ensure_float(rent + SIGNATURE_LAMPORTS).await?;
            let (blockhash, last_valid_height) = self.ledger.recent_blockhash().await?;
            let (message, address) = match &current {
                Some((address, _)) => (
                    tx::extend_lookup_table_message(&self.relayer, address, &missing, &blockhash),
                    *address,
                ),
                None => tx::create_lookup_table_message(
                    &self.relayer,
                    self.ledger.recent_ancestor_slot().await?,
                    &missing,
                    &blockhash,
                ),
            };
            let signed = self.sign(&message, &[])?;
            self.send_and_confirm("lookup_table", &signed, last_valid_height)
                .await?;
            self.store
                .set_meta(LOOKUP_TABLE_META_KEY, &address.to_string())?;
            let table = self.read_lookup_table(address).await?.ok_or_else(|| {
                RelayError::unavailable("the relay lookup table is not visible yet")
            })?;
            current = Some((address, table));
        }
        let (address, table) = current.ok_or_else(|| RelayError::internal("no lookup table"))?;
        // Addresses appended in a slot are usable from the next slot on.
        let started = Instant::now();
        while self.ledger.confirmed_slot().await? <= table.last_extended_slot {
            if started.elapsed() > CONFIRM_TIMEOUT {
                return Err(RelayError::unavailable(
                    "the relay lookup table did not warm up",
                ));
            }
            tokio::time::sleep(CONFIRM_POLL).await;
        }
        Ok(AddressLookupTableAccount {
            key: address,
            addresses: table.addresses,
        })
    }

    // ----- POST /v2/relay/deposits/prepare --------------------------------

    pub async fn prepare_deposit(&self, body: DepositBody) -> RelayResult<DepositResponse> {
        let depositor = self.user_account(&body.depositor, "depositor")?;
        self.admit("deposit", None)?;
        let amount = parse_amount(&body.amount, "amount")?;
        let max_fee = parse_amount(&body.max_fee, "max_fee")?.min(RelayKind::Deposit.sdk_cap());
        if amount == 0 || body.commitment == Felt252::ZERO {
            return Err(RelayError::invalid(
                "deposit amount and commitment must be nonzero",
            ));
        }
        let zero_path: [Felt252; MERKLE_DEPTH] =
            body.zero_path.try_into().map_err(|values: Vec<Felt252>| {
                RelayError::invalid(format!(
                    "zero_path must contain {MERKLE_DEPTH} field elements, got {}",
                    values.len()
                ))
            })?;
        let fee = self.quote(RelayKind::Deposit, false);
        if fee > max_fee {
            return Err(RelayError::above_cap(fee, max_fee));
        }
        let required = amount
            .checked_add(fee)
            .ok_or_else(|| RelayError::invalid("amount plus fee exceeds u64"))?;
        let balance = self.usdc_balance(&depositor).await?;
        if balance < required {
            return Err(RelayError::insufficient(format!(
                "ATA(depositor) holds {balance}, the deposit needs {required} (amount {amount} + fee {fee})"
            )));
        }
        let operation_rent = self
            .ledger
            .rent_exempt_minimum(deposit_operation_account_len())
            .await?;
        self.ensure_float(
            operation_rent + fees::cost_lamports(RelayKind::Deposit, &self.rent, false),
        )
        .await?;
        let staged = self
            .ledger
            .prepare_relayed_deposit(RelayedDepositRequest {
                depositor: LedgerAccount::new(depositor.to_bytes()),
                expected_note_id: body.expected_note_id,
                commitment: body.commitment,
                amount: u128::from(amount),
                zero_path,
                required_source_balance: required,
                execute_suffix: tx::fee_transfer(&depositor, &self.config.fee_account, fee)
                    .into_iter()
                    .collect(),
            })
            .await?;
        let stages = staged
            .operation
            .transactions
            .iter()
            .map(|stage| decode_message(&stage.bytes))
            .collect::<RelayResult<Vec<_>>>()?;
        let table = self
            .lookup_table(&self.exit_lookup_addresses(), None)
            .await?;
        let (blockhash, last_valid_height) = self.ledger.recent_blockhash().await?;
        let bytes = tx::unsigned_deposit(
            &self.relayer,
            &depositor,
            &stages,
            operation_rent,
            self.rent.note,
            &table,
            &blockhash,
            &self.vault_program,
        )
        .map_err(RelayError::internal)?;
        self.ledger.simulate_transaction(&bytes, false).await?;
        let backing = self.backing(&depositor, body.inbound.as_ref()).await?;
        let submit_token = self.ticket(
            TicketKind::Deposit,
            &bytes,
            &depositor,
            last_valid_height,
            Some(&table),
            None,
            backing,
        )?;
        Ok(DepositResponse {
            fee: fee.to_string(),
            operation: staged.operation_address.to_string(),
            note: staged.note_address.to_string(),
            operation_rent: operation_rent.to_string(),
            note_rent: self.rent.note.to_string(),
            transaction: TransactionWire::v0(&bytes, last_valid_height, &table),
            submit_token,
        })
    }

    // ----- POST /v2/relay/burns/prepare -----------------------------------

    pub async fn prepare_burn(&self, body: BurnBody) -> RelayResult<BurnResponse> {
        let owner = self.user_account(&body.owner, "owner")?;
        self.admit("burn", None)?;
        if body.destination_domain == cctp::SOLANA_DOMAIN {
            return Err(RelayError::invalid("destination_domain cannot be Solana"));
        }
        let mint_recipient = parse_hex32(&body.mint_recipient, "mint_recipient")?;
        if mint_recipient == [0; 32] {
            return Err(RelayError::invalid("mint_recipient cannot be zero"));
        }
        let destination_caller = match body.destination_caller.as_deref() {
            None | Some("") => [0; 32],
            Some(value) => parse_hex32(value, "destination_caller")?,
        };
        let max_cctp_fee = parse_amount(&body.max_cctp_fee, "max_cctp_fee")?;
        if ![cctp::FINALITY_FAST, cctp::FINALITY_STANDARD].contains(&body.min_finality_threshold) {
            return Err(RelayError::invalid(
                "min_finality_threshold must be 1000 (Fast) or 2000 (Standard)",
            ));
        }
        let hook_data = parse_hex(&body.hook_data, "hook_data", MAX_HOOK_BYTES)?;
        let max_fee = parse_amount(&body.max_fee, "max_fee")?.min(RelayKind::Burn.sdk_cap());
        self.ensure_cctp_live().await?;
        let remote = cctp::remote_token_messenger(body.destination_domain);
        if self
            .ledger
            .raw_account(remote, LedgerCommitment::Confirmed)
            .await?
            .is_none_or(|account| account.owner != cctp::TOKEN_MESSENGER_MINTER_V2)
        {
            return Err(RelayError::invalid(format!(
                "CCTP domain {} is not a supported destination",
                body.destination_domain
            )));
        }
        if self
            .ledger
            .raw_account(cctp::denylist_account(&owner), LedgerCommitment::Confirmed)
            .await?
            .is_some_and(|account| !account.data.is_empty())
        {
            return Err(RelayError::invalid("Circle has denylisted this owner"));
        }
        let event_rent = self
            .ledger
            .rent_exempt_minimum(MESSAGE_SENT_BASE_SPACE + hook_data.len())
            .await?;
        let burn_cost = event_rent.saturating_add(3 * SIGNATURE_LAMPORTS);
        let fee = fees::fee_usdc(
            fees::cost_lamports(RelayKind::Burn, &self.rent, false),
            self.config.sol_usd_micros,
            self.config.margin_bps,
        );
        if fee > max_fee {
            return Err(RelayError::above_cap(fee, max_fee));
        }
        let balance = self.usdc_balance(&owner).await?;
        let amount = balance.saturating_sub(fee);
        if amount <= max_cctp_fee {
            return Err(RelayError::insufficient(format!(
                "ATA(owner) holds {balance}: after the relay fee {fee} the burn amount {amount} \
                 must exceed max_cctp_fee {max_cctp_fee}"
            )));
        }
        self.check_burn_minimum(amount)?;
        self.ensure_float(burn_cost).await?;
        // The event keypair is re-derived from the ticket nonce at submit;
        // nobody else learns it, and nothing is reserved until then.
        let nonce = hex::encode(Keypair::new().secret_bytes());
        let event = self
            .tickets
            .event_keypair(&nonce)
            .ok_or_else(|| RelayError::internal("event key derivation failed"))?;
        let (blockhash, last_valid_height) = self.ledger.recent_blockhash().await?;
        let message = tx::burn_message(
            &self.relayer,
            &owner,
            &event.pubkey(),
            &self.config.fee_account,
            fee,
            &cctp::BurnParams {
                amount,
                destination_domain: body.destination_domain,
                mint_recipient,
                destination_caller,
                max_fee: max_cctp_fee,
                min_finality_threshold: body.min_finality_threshold,
                hook_data,
            },
            &blockhash,
        );
        let bytes = self.unsigned(&message)?;
        self.ledger.simulate_transaction(&bytes, false).await?;
        let backing = self.backing(&owner, body.inbound.as_ref()).await?;
        let submit_token = self.ticket(
            TicketKind::Burn,
            &bytes,
            &owner,
            last_valid_height,
            None,
            Some(TicketEvent {
                nonce,
                address: event.pubkey().to_string(),
                rent: event_rent,
            }),
            backing,
        )?;
        Ok(BurnResponse {
            fee: fee.to_string(),
            amount: amount.to_string(),
            message_sent_event_account: event.pubkey().to_string(),
            transaction: TransactionWire::new(&bytes, last_valid_height),
            submit_token,
        })
    }

    // ----- POST /v2/relay/sweeps/prepare ----------------------------------

    pub async fn prepare_sweep(&self, body: SweepBody) -> RelayResult<SweepResponse> {
        let owner = self.user_account(&body.owner, "owner")?;
        self.admit("sweep", None)?;
        let destination = self.user_account(&body.destination, "destination")?;
        let max_fee = parse_amount(&body.max_fee, "max_fee")?.min(RelayKind::Sweep.sdk_cap());
        if destination == ata(&owner) {
            return Err(RelayError::invalid(
                "destination is the owner's own account",
            ));
        }
        if !self
            .ledger
            .token_account_state(destination)
            .await?
            .is_some_and(|account| account.creditable(&USDC_MINT))
        {
            return Err(RelayError::invalid(
                "destination must be an existing unfrozen classic USDC token account",
            ));
        }
        let fee = self.quote(RelayKind::Sweep, false);
        if fee > max_fee {
            return Err(RelayError::above_cap(fee, max_fee));
        }
        let balance = self.usdc_balance(&owner).await?;
        let amount = balance.saturating_sub(fee);
        if amount == 0 {
            return Err(RelayError::insufficient(format!(
                "ATA(owner) holds {balance}, not more than the relay fee {fee}"
            )));
        }
        self.ensure_float(fees::cost_lamports(RelayKind::Sweep, &self.rent, false))
            .await?;
        let (blockhash, last_valid_height) = self.ledger.recent_blockhash().await?;
        let message = tx::sweep_message(
            &self.relayer,
            &owner,
            &destination,
            &self.config.fee_account,
            fee,
            amount,
            &blockhash,
        );
        let bytes = self.unsigned(&message)?;
        self.ledger.simulate_transaction(&bytes, false).await?;
        let backing = self.backing(&owner, body.inbound.as_ref()).await?;
        let submit_token = self.ticket(
            TicketKind::Sweep,
            &bytes,
            &owner,
            last_valid_height,
            None,
            None,
            backing,
        )?;
        Ok(SweepResponse {
            fee: fee.to_string(),
            amount: amount.to_string(),
            transaction: TransactionWire::new(&bytes, last_valid_height),
            submit_token,
        })
    }

    // ----- POST /v2/relay/receives/prepare --------------------------------

    /// A free fallback receive signed by the relay for the client to broadcast.
    /// Only used_nonce rent is subsidized; ATA(ek) must already exist.
    pub async fn prepare_receive(&self, body: ReceiveBody) -> RelayResult<ReceiveResponse> {
        if body.source_domain == cctp::SOLANA_DOMAIN {
            return Err(RelayError::invalid("source_domain cannot be Solana"));
        }
        let hash = body.transaction_hash.trim();
        if hash.is_empty()
            || hash.len() > 130
            || !hash.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(RelayError::invalid("transaction_hash is malformed"));
        }
        let owner = self.user_account(&body.owner, "owner")?;
        // Validated for wire compatibility; a fallback receive is not charged.
        parse_amount(&body.max_fee, "max_fee")?;
        self.admit("receive", None)?;
        self.ensure_cctp_live().await?;
        let messages = self
            .iris
            .messages(body.source_domain, hash)
            .await
            .map_err(|error| RelayError::unavailable(format!("Iris: {error}")))?;
        let mut pending = false;
        let mut candidate = None;
        for entry in &messages {
            let Some(inbound) = InboundMessage::parse(&entry.message, body.source_domain)
                .filter(|inbound| inbound.owner == owner)
            else {
                continue;
            };
            match &entry.attestation {
                Some(attestation) if entry.complete => {
                    candidate = Some((inbound, attestation.clone(), entry.message.clone()));
                    break;
                }
                _ => pending = true,
            }
        }
        let Some((inbound, attestation, message)) = candidate else {
            return Err(if pending {
                RelayError::new(
                    StatusCode::CONFLICT,
                    "invalid_request",
                    "the attestation is still pending; retry shortly",
                )
            } else {
                RelayError::invalid(
                    "the transaction has no zkAPI inbound CCTP message to Solana for this owner",
                )
            });
        };
        self.check_receive_minimum(&inbound)?;
        // Authenticate before any user-controlled lookup-table extension can
        // spend SOL. Simulation below still checks all live Circle state.
        let mt = self
            .ledger
            .raw_account(
                cctp::CctpAccounts::new(USDC_MINT).message_transmitter,
                LedgerCommitment::Confirmed,
            )
            .await?
            .filter(|account| account.owner == cctp::MESSAGE_TRANSMITTER_V2)
            .ok_or_else(|| RelayError::unavailable("CCTP MessageTransmitter is missing"))?;
        verify_receive_attestation(&mt.data, &message, &attestation)?;
        let nonce = hex::encode(inbound.nonce);
        let recipient = inbound.recipient;
        if self.nonce_used(&inbound.nonce).await? {
            return Ok(ReceiveResponse {
                fee: "0".into(),
                nonce,
                recipient_token_account: recipient.to_string(),
                transaction: None,
            });
        }
        if inbound.expiration_block != 0
            && inbound.expiration_block <= self.ledger.confirmed_slot().await?
        {
            return Err(RelayError::invalid(
                "the attested message expired; it must be re-attested",
            ));
        }
        // Never create ATA(ek): its rent would be the ek's to reclaim by
        // closing it. Circle's forwarder (ATA-creation hook) creates it.
        if !self
            .ledger
            .token_account_state(recipient)
            .await?
            .is_some_and(|account| account.creditable(&USDC_MINT) && account.owner == owner)
        {
            return Err(RelayError::insufficient(
                "ATA(ek) does not exist: a fallback receive needs the account the forwarding \
                 service creates, or a self-funded receive",
            ));
        }
        // No fee fits next to the hook. The durable subsidy reservation below
        // bounds every preparation, including ALT rent/signatures, before spend.
        let fee = 0u64;
        let cost = fees::cost_lamports(RelayKind::Receive, &self.rent, false);
        let messenger = self
            .ledger
            .raw_account(
                cctp::CctpAccounts::new(USDC_MINT).token_messenger,
                LedgerCommitment::Confirmed,
            )
            .await?
            .ok_or_else(|| RelayError::unavailable("CCTP TokenMessenger is missing"))?;
        let fee_recipient = cctp::token_messenger_fee_recipient(&messenger.data)
            .map_err(|error| RelayError::unavailable(error.to_string()))?;
        self.ensure_float(cost).await?;
        let fee_recipient_account = ata(&fee_recipient);
        let mut addresses = cctp::receive_lookup_addresses(
            &cctp::CctpAccounts::new(USDC_MINT),
            &fee_recipient_account,
        );
        addresses.extend(
            cctp::receive_domain_addresses(&message)
                .map_err(|error| RelayError::invalid(error.to_string()))?,
        );
        // One outstanding transaction per attested message: concurrent or
        // repeated preparations (anyone can ask for a public message) get the
        // same bytes while they are executable, so they cannot multiply relay
        // signature-fee failures or the message's subsidy reservation.
        let _receive = self.receive_lock.lock().await;
        let table = self
            .lookup_table(&addresses, Some((&inbound, body.source_domain)))
            .await?;
        if let Some(issued) = self.store.receive_transaction(&nonce)? {
            let height = self
                .ledger
                .transaction_height(LedgerCommitment::Confirmed)
                .await?;
            if issued.last_valid_height > height.saturating_add(RECEIVE_REUSE_MARGIN_BLOCKS) {
                return Ok(ReceiveResponse {
                    fee: fee.to_string(),
                    nonce,
                    recipient_token_account: recipient.to_string(),
                    transaction: Some(TransactionWire::v0(
                        &issued.bytes,
                        issued.last_valid_height,
                        &table,
                    )),
                });
            }
        }
        let (blockhash, last_valid_height) = self.ledger.recent_blockhash().await?;
        let message = tx::receive_message(
            &self.relayer,
            &owner,
            &message,
            &attestation,
            &fee_recipient_account,
            &table,
            &blockhash,
        )
        .map_err(RelayError::invalid)?;
        let signed = self.sign_v0(&message, &table)?;
        self.ledger
            .simulate_transaction(&signed.bytes, true)
            .await?;
        self.reserve_issued(
            &signed,
            last_valid_height,
            &owner,
            &format!(
                "{}:{}",
                body.source_domain,
                hex::encode(inbound.source_sender)
            ),
            None,
        )?;
        self.store.set_receive_transaction(
            &nonce,
            &store::InFlight {
                signature: signed.signature.clone(),
                label: "receive".into(),
                bytes: signed.bytes.clone(),
                last_valid_height,
            },
        )?;
        Ok(ReceiveResponse {
            fee: fee.to_string(),
            nonce,
            recipient_token_account: recipient.to_string(),
            transaction: Some(TransactionWire::v0(
                &signed.bytes,
                last_valid_height,
                &table,
            )),
        })
    }

    fn sign_v0(
        &self,
        message: &dagon_zkapi_solana_ledger::solana_v0::Message,
        table: &AddressLookupTableAccount,
    ) -> RelayResult<SignedTransaction> {
        tx::sign_v0(
            message,
            std::slice::from_ref(table),
            &self.config.keypair,
            &self.vault_program,
        )
        .map_err(|error| RelayError::internal(format!("relayer refused to sign: {error}")))
    }

    /// Accounts of every relayed exit a lookup table can hold.
    fn exit_lookup_addresses(&self) -> Vec<Pubkey> {
        let vault = self.ledger.vault_address();
        vec![
            vault,
            Pubkey::new_from_array(dagon_zkapi_profile::vault_token_address(
                &self.vault_program.to_bytes(),
                &vault.to_bytes(),
            )),
            USDC_MINT,
            Pubkey::default(),
            self.config.fee_account,
        ]
    }

    /// Create the lookup table with every request-independent address at
    /// startup, so no user request makes the relayer create or extend it
    /// (only a new CCTP source domain extends it, after a valid attestation).
    async fn warm_lookup_table(&self) -> RelayResult<()> {
        let mut addresses = self.exit_lookup_addresses();
        let accounts = cctp::CctpAccounts::new(USDC_MINT);
        if let Some(messenger) = self
            .ledger
            .raw_account(accounts.token_messenger, LedgerCommitment::Confirmed)
            .await?
            .filter(|account| account.owner == cctp::TOKEN_MESSENGER_MINTER_V2)
        {
            let fee_recipient = cctp::token_messenger_fee_recipient(&messenger.data)
                .map_err(|error| RelayError::unavailable(error.to_string()))?;
            addresses.extend(cctp::receive_lookup_addresses(
                &accounts,
                &ata(&fee_recipient),
            ));
        }
        self.lookup_table(&addresses, None).await.map(|_| ())
    }

    // ----- POST /v2/relay/exits/prepare -----------------------------------

    /// A mutual close or escape with the relayer as vault `owner`, returned
    /// for the ek to sign and broadcast. The relayer's rent (nullifiers,
    /// pending, `ATA(ek)` for a close) and its fee are in one transaction
    /// with the ek's fee transfer: a close pays the fee from the payout, an
    /// escape from a prepaid `ATA(ek)` balance. Nothing is broadcast by the
    /// relayer, and an invalid proof fails simulation before it is returned.
    pub async fn prepare_exit(&self, body: ExitBody) -> RelayResult<ExitResponse> {
        let owner = self.user_account(&body.destination_owner, "destination_owner")?;
        self.admit("exit", None)?;
        let max_fee = parse_amount(&body.max_fee, "max_fee")?;
        let destination = ata(&owner);
        let existing = self.ledger.token_account_state(destination).await?;
        if existing.is_some_and(|account| !account.creditable(&USDC_MINT) || account.owner != owner)
        {
            return Err(RelayError::invalid(
                "ATA(destination_owner) is frozen or not its USDC account",
            ));
        }
        let close = body.kind == ExitKind::Mutual;
        let creates_ata = close && existing.is_none();
        let kind = if close {
            RelayKind::Close
        } else {
            RelayKind::Escape
        };
        let cost = fees::cost_lamports(kind, &self.rent, creates_ata);
        let fee = self.fee_of(cost);
        let max_fee = max_fee.min(kind.sdk_cap());
        if fee > max_fee {
            return Err(RelayError::above_cap(fee, max_fee));
        }
        let held = existing.map_or(0, |account| account.amount);
        let available = if close {
            body.public_inputs
                .final_balance
                .saturating_add(u128::from(held))
        } else {
            u128::from(held)
        };
        if available < u128::from(fee) {
            return Err(RelayError::insufficient(if close {
                format!("the close payout plus ATA(ek) balance does not cover the relay fee {fee}")
            } else {
                format!(
                    "a relayed escape is prepaid: ATA(ek) must exist and hold the relay fee {fee}"
                )
            }));
        }
        let float = if close {
            0
        } else {
            self.ledger
                .rent_exempt_minimum(pending_withdrawal_account_len())
                .await?
        };
        self.ensure_float(cost + float).await?;
        let note_id = body.public_inputs.note_id;
        let exit = self
            .ledger
            .relayed_withdrawal_instruction(
                WithdrawalRequest {
                    payer: LedgerAccount::new(self.relayer.to_bytes()),
                    destination: LedgerAccount::new(destination.to_bytes()),
                    public_inputs: body.public_inputs,
                    proof: body.proof,
                },
                close,
                close,
            )
            .await?;
        let table = self
            .lookup_table(&self.exit_lookup_addresses(), None)
            .await?;
        let (blockhash, last_valid_height) = self.ledger.recent_blockhash().await?;
        let message = tx::exit_message(
            &self.relayer,
            &owner,
            // Always present on a close (a no-op if ATA(ek) exists) so the
            // shape is deterministic; its rent is charged only when created.
            close,
            exit,
            &self.config.fee_account,
            fee,
            &table,
            &blockhash,
        )
        .map_err(RelayError::invalid)?;
        let bytes = tx::unsigned_v0(
            &message,
            std::slice::from_ref(&table),
            &self.relayer,
            &self.vault_program,
        )
        .map_err(|error| RelayError::internal(format!("relayer refused to sign: {error}")))?;
        self.ledger.simulate_transaction(&bytes, false).await?;
        // A valid proof of an unspent note (the simulation above) is a costly,
        // unique credential; it also covers this ek's later burn or sweep.
        let note = format!("note:{note_id}");
        self.store.add_backing(&note, &owner.to_string())?;
        let backing = self
            .store
            .unspent_backing(&owner.to_string(), Some(&note))?;
        let submit_token = self.ticket(
            if close {
                TicketKind::Close
            } else {
                TicketKind::Escape
            },
            &bytes,
            &owner,
            last_valid_height,
            Some(&table),
            None,
            backing,
        )?;
        Ok(ExitResponse {
            fee: fee.to_string(),
            destination: destination.to_string(),
            transaction: TransactionWire::v0(&bytes, last_valid_height, &table),
            submit_token,
        })
    }

    // ----- POST /v2/relay/escapes/finalize --------------------------------

    pub async fn finalize_escape(&self, body: FinalizeBody) -> RelayResult<FinalizeResponse> {
        self.admit("finalize", None)?;
        let pending = self.ledger.pending_escape(body.note_id).await?;
        if pending.rent_payer != self.relayer {
            return Err(RelayError::invalid(
                "this escape was not submitted by the relay",
            ));
        }
        let request_payer = LedgerAccount::new(self.relayer.to_bytes());
        self.ensure_float(SIGNATURE_LAMPORTS).await?;
        let (prepared, action) = match pending.stage {
            PENDING_STAGE_OPEN => (
                self.ledger
                    .prepare_finalize_escape(FinalizeEscapeRequest {
                        payer: request_payer,
                        note_id: body.note_id,
                    })
                    .await?,
                "finalize",
            ),
            PENDING_STAGE_PAYOUT_PARKED => (
                self.ledger
                    .prepare_release_escape_payout(ReleaseEscapePayoutRequest {
                        payer: request_payer,
                        note_id: body.note_id,
                    })
                    .await?,
                "release",
            ),
            _ => {
                return Err(RelayError::invalid(
                    "the escape has no payout left to finalize or release",
                ))
            }
        };
        let signature = self.run_prepared(action, prepared).await?;
        Ok(FinalizeResponse { signature, action })
    }

    // ----- background maintenance ----------------------------------------

    /// Reconcile in-flight relayer transactions and reclaim `MessageSent`
    /// rent. Errors are logged and retried next tick.
    pub async fn maintain(&self) {
        if let Err(error) = self.reconcile_issuances().await {
            tracing::warn!(
                code = error.code,
                "relay risk reconciliation failed: {}",
                error.message
            );
        }
        if let Err(error) = self.reconcile_in_flight().await {
            tracing::warn!(
                code = error.code,
                "relay in-flight reconciliation failed: {}",
                error.message
            );
        }
        if let Err(error) = self.reclaim_event_accounts().await {
            tracing::warn!(
                code = error.code,
                "relay reclaim sweep failed: {}",
                error.message
            );
        }
    }

    fn check_burn_minimum(&self, amount: u64) -> RelayResult<()> {
        if amount < self.config.burn_minimum_amount {
            return Err(RelayError::new(
                StatusCode::CONFLICT,
                "burn_below_minimum",
                format!("CCTP exits below {} USDC after the relay fee are not relayed; exit on Solana, sweep, or burn with your own SOL",
                    self.config.burn_minimum_amount as f64 / 1_000_000.0),
            ));
        }
        Ok(())
    }

    /// Reserve a relay-only transaction (receive, relay-internal work).
    fn reserve_issued(
        &self,
        signed: &SignedTransaction,
        height: u64,
        owner: &Pubkey,
        source: &str,
        event: Option<(&str, u64, u64)>,
    ) -> RelayResult<()> {
        let issued = store::IssuedTransaction {
            signature: signed.signature.clone(),
            owner: owner.to_string(),
            source: source.into(),
            last_valid_height: height,
            fee_lamports: signature_lamports(&signed.bytes)?,
            ..Default::default()
        };
        admitted(self.store.reserve_issuance(
            &issued,
            now_ms(),
            self.config.daily_loss_lamports,
            event,
        )?)
        .map(|_| ())
    }

    async fn reconcile_issuances(&self) -> RelayResult<()> {
        let outstanding = self.store.outstanding_issuances()?;
        if outstanding.is_empty() {
            return Ok(());
        }
        let height = self
            .ledger
            .transaction_height(LedgerCommitment::Finalized)
            .await?;
        for issued in outstanding {
            self.settle(&issued, height).await?;
        }
        Ok(())
    }

    /// Settle one reservation from its on-chain status.
    async fn settle(
        &self,
        issued: &store::IssuedTransaction,
        finalized_height: u64,
    ) -> RelayResult<()> {
        match self
            .ledger
            .transaction_status(issued.signature.clone().into_bytes())
            .await?
        {
            LedgerTransactionStatus::Finalized { .. } => {
                self.store
                    .settle_issuance(&issued.signature, true, now_ms())?
            }
            LedgerTransactionStatus::Failed { reason } => {
                if note_id_contention(&reason, issued.contended_instruction) {
                    self.store
                        .settle_contention_failure(&issued.signature, now_ms())?
                } else {
                    self.store
                        .settle_issuance(&issued.signature, false, now_ms())?
                }
            }
            // Finalized height past validity plus full-history Unknown proves
            // this transaction never executed. No fee or user failure exists.
            LedgerTransactionStatus::Unknown if finalized_height > issued.last_valid_height => self
                .store
                .settle_issuance(&issued.signature, true, now_ms())?,
            _ => {}
        }
        Ok(())
    }

    fn check_receive_minimum(&self, inbound: &InboundMessage) -> RelayResult<()> {
        if inbound.amount < self.config.receive.minimum_amount {
            return Err(RelayError::new(StatusCode::CONFLICT, "receive_below_minimum",
                "burn amount is below the subsidized receive minimum; use Circle forwarding or a self-funded receive"));
        }
        Ok(())
    }

    fn reserve_receive_subsidy(
        &self,
        inbound: &InboundMessage,
        source_domain: u32,
        cost: u64,
        extension: u64,
    ) -> RelayResult<()> {
        self.check_receive_minimum(inbound)?;
        let source = format!("{source_domain}:{}", hex::encode(inbound.source_sender));
        let admission = self.store.reserve_receive(
            now_ms() / 86_400_000,
            &hex::encode(inbound.nonce),
            &source,
            &inbound.owner.to_string(),
            cost,
            extension,
            &self.config.receive,
        )?;
        use super::store::ReceiveAdmission;
        match admission {
            ReceiveAdmission::Accepted => Ok(()),
            ReceiveAdmission::BudgetExhausted => Err(RelayError::new(StatusCode::TOO_MANY_REQUESTS,
                "receive_budget_exhausted", "daily receive SOL budget exhausted; use Circle forwarding or a self-funded receive")),
            ReceiveAdmission::SourceLimited | ReceiveAdmission::OwnerLimited => Err(RelayError::new(
                StatusCode::TOO_MANY_REQUESTS, "receive_address_limited",
                "daily source-address or emergency-key receive limit exhausted; use Circle forwarding or a self-funded receive")),
        }
    }

    async fn reclaim_event_accounts(&self) -> RelayResult<()> {
        let events = self.store.event_accounts()?;
        let now = now_ms();
        if events.iter().all(|event| event.next_attempt_ms > now) {
            return Ok(());
        }
        let height = self
            .ledger
            .transaction_height(LedgerCommitment::Finalized)
            .await?;
        for event in events
            .into_iter()
            .filter(|event| event.next_attempt_ms <= now)
        {
            let address: Pubkey = event
                .address
                .parse()
                .map_err(|_| RelayError::internal("stored event account is invalid"))?;
            let account = self
                .ledger
                .raw_account(address, LedgerCommitment::Finalized)
                .await?
                .filter(|account| account.owner == cctp::MESSAGE_TRANSMITTER_V2);
            let Some(account) = account else {
                // Never broadcast (blockhash expired) or already reclaimed.
                if height > event.last_valid_height {
                    self.store.remove_event_account(&event.address)?;
                }
                continue;
            };
            if !event.landed {
                self.store.mark_event_landed(&event.address)?;
            }
            let Ok(sent) = cctp::MessageSentAccount::parse(&account.data) else {
                self.store
                    .defer_event(&event.address, now + RECLAIM_RETRY_MS)?;
                continue;
            };
            if sent.rent_payer != self.relayer {
                self.store
                    .defer_event(&event.address, now + RECLAIM_RETRY_MS)?;
                continue;
            }
            let due_seconds = sent
                .created_at
                .saturating_add(cctp::EVENT_ACCOUNT_WINDOW_SECONDS + RECLAIM_SLACK_SECONDS);
            let due_ms = u64::try_from(due_seconds)
                .unwrap_or(0)
                .saturating_mul(1_000);
            if now < due_ms {
                self.store.defer_event(&event.address, due_ms)?;
                continue;
            }
            let reclaimed = self.reclaim(&address, &sent, &event.signature).await;
            if let Err(error) = reclaimed {
                tracing::info!(event = %address, "MessageSent reclaim deferred: {}", error.message);
                self.store
                    .defer_event(&event.address, now + RECLAIM_RETRY_MS)?;
            } else {
                // Release float only after finalized absence, not a reorgable confirmation.
                self.store.defer_event(&event.address, now + 15_000)?;
            }
        }
        Ok(())
    }

    async fn reclaim(
        &self,
        address: &Pubkey,
        sent: &cctp::MessageSentAccount,
        signature: &str,
    ) -> RelayResult<()> {
        self.ensure_cctp_live().await?;
        let messages = self
            .iris
            .messages(cctp::SOLANA_DOMAIN, signature)
            .await
            .map_err(|error| RelayError::unavailable(format!("Iris: {error}")))?;
        let (attestation, destination) = messages
            .iter()
            .find_map(|entry| {
                let attestation = entry.attestation.as_ref().filter(|_| entry.complete)?;
                cctp::same_source_fields(&sent.message, &entry.message)
                    .then(|| (attestation.clone(), entry.message.clone()))
            })
            .ok_or_else(|| RelayError::unavailable("no attested destination message yet"))?;
        let (blockhash, last_valid_height) = self.ledger.recent_blockhash().await?;
        let message = tx::reclaim_message(
            &self.relayer,
            address,
            &attestation,
            &destination,
            &blockhash,
        );
        let signed = self.sign(&message, &[])?;
        self.ledger
            .simulate_transaction(&signed.bytes, true)
            .await?;
        self.send_and_confirm("reclaim", &signed, last_valid_height)
            .await
    }
}

/// A zkAPI inbound CCTP message to Solana: Circle's forward hook requesting
/// `ATA(ek)` creation, then our `DGNZK-IN` intent naming the same ek, minting
/// to exactly that ATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundMessage {
    pub nonce: [u8; 32],
    pub owner: Pubkey,
    pub recipient: Pubkey,
    pub amount: u64,
    pub source_sender: [u8; 32],
    /// Amount minted to the recipient (after Circle's executed fee).
    pub net_amount: u64,
    pub expiration_block: u64,
}

impl InboundMessage {
    pub fn parse(bytes: &[u8], source_domain: u32) -> Option<Self> {
        let message = cctp::MessageV2::parse(bytes).ok()?;
        if message.version != 1
            || message.source_domain != source_domain
            || message.destination_domain != cctp::SOLANA_DOMAIN
            || message.recipient != cctp::TOKEN_MESSENGER_MINTER_V2.to_bytes()
            || message.destination_caller != [0; 32]
        {
            return None;
        }
        let burn = cctp::BurnMessageV2::parse(message.body).ok()?;
        let hook = cctp::ForwardHook::parse(burn.hook_data).ok()?;
        let owner = Pubkey::new_from_array(hook.create_ata_owner?);
        let intent = cctp::InboundIntentHead::parse(hook.developer_data).ok()?;
        let recipient = Pubkey::new_from_array(burn.mint_recipient);
        if intent.emergency_owner != owner.to_bytes() || recipient != ata(&owner) {
            return None;
        }
        Some(Self {
            nonce: message.nonce,
            owner,
            recipient,
            amount: burn.amount,
            source_sender: burn.message_sender,
            net_amount: burn.amount.checked_sub(burn.fee_executed)?,
            expiration_block: burn.expiration_block,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use dagon_zkapi_solana_ledger::SolanaHash;
    use serde_json::{json, Value};

    #[test]
    fn attestation_admission_rejects_forgery_before_lookup_spending() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../sdk/test/fixtures/cctp-vectors.json"
        ))
        .unwrap();
        let mainnet = &fixture["mainnet"];
        let bytes =
            |value: &Value| hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap();
        let message = bytes(&mainnet["receive_message"]["message"]);
        let attestation = bytes(&mainnet["receive_message"]["attestation"]);
        let mut state = vec![0; 225];
        state[..8].copy_from_slice(&cctp::MESSAGE_TRANSMITTER_ACCOUNT);
        state[145..149].copy_from_slice(&2u32.to_le_bytes());
        state[149..153].copy_from_slice(&2u32.to_le_bytes());
        for (index, key) in mainnet["attesters"].as_array().unwrap().iter().enumerate() {
            state[165 + index * 32..185 + index * 32].copy_from_slice(&bytes(key));
        }
        verify_receive_attestation(&state, &message, &attestation).unwrap();
        let mut tampered = message.clone();
        tampered[7] ^= 1; // Forged source domain would otherwise extend the ALT.
        assert!(verify_receive_attestation(&state, &tampered, &attestation).is_err());
        assert!(verify_receive_attestation(&state, &message, &attestation[..65]).is_err());
        let reversed = [&attestation[65..], &attestation[..65]].concat();
        assert!(verify_receive_attestation(&state, &message, &reversed).is_err());
        state[165..185].fill(0); // Rotation: old signatures fail closed.
        assert!(verify_receive_attestation(&state, &message, &attestation).is_err());
    }

    type Handler = Arc<dyn Fn(&str, &Value) -> Value + Send + Sync>;

    /// A JSON-RPC endpoint answering each `method` from `handler`.
    async fn mock_rpc(handler: Handler) -> String {
        let router = axum::Router::new().route(
            "/",
            axum::routing::post(move |Json(request): Json<Value>| {
                let handler = handler.clone();
                async move {
                    let method = request["method"].as_str().unwrap_or_default().to_string();
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": handler(&method, &request["params"]),
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{address}")
    }

    fn account(owner: &Pubkey, data: &[u8]) -> Value {
        json!({"context": {"slot": 7}, "value": {
            "owner": owner.to_string(),
            "executable": false,
            "lamports": 1_000_000,
            "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
        }})
    }

    fn token_account(owner: &Pubkey, amount: u64) -> Value {
        let mut data = vec![0u8; 165];
        data[..32].copy_from_slice(USDC_MINT.as_ref());
        data[32..64].copy_from_slice(owner.as_ref());
        data[64..72].copy_from_slice(&amount.to_le_bytes());
        data[108] = 1;
        account(&dagon_zkapi_solana_ledger::CLASSIC_TOKEN_PROGRAM_ID, &data)
    }

    const ABSENT: fn() -> Value = || json!({"context": {"slot": 7}, "value": null});

    #[tokio::test]
    async fn a_prefunded_nonce_pda_is_not_a_minted_transfer() {
        let state = Arc::new(Mutex::new(ABSENT()));
        let observed = state.clone();
        let url = mock_rpc(Arc::new(move |method, _| match method {
            "getGenesisHash" => json!(SolanaHash::new_from_array([3; 32]).to_string()),
            "getAccountInfo" => observed.lock().unwrap().clone(),
            other => panic!("unexpected RPC {other}"),
        }))
        .await;
        let relay = relay(url);
        for (owner, data, expected) in [
            (Pubkey::default(), vec![], false),
            (
                Pubkey::default(),
                vec![212, 222, 157, 252, 130, 71, 179, 238, 1],
                false,
            ),
            (cctp::MESSAGE_TRANSMITTER_V2, vec![1], false),
            (
                cctp::MESSAGE_TRANSMITTER_V2,
                vec![212, 222, 157, 252, 130, 71, 179, 238, 0],
                false,
            ),
            (
                cctp::MESSAGE_TRANSMITTER_V2,
                vec![212, 222, 157, 252, 130, 71, 179, 238, 1],
                true,
            ),
        ] {
            *state.lock().unwrap() = account(&owner, &data);
            assert_eq!(relay.nonce_used(&[7; 32]).await.unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn expired_unsettled_failure_spends_credential_before_next_submission() {
        let url = mock_rpc(Arc::new(move |method, params| match method {
            "getGenesisHash" => json!(SolanaHash::new_from_array([3; 32]).to_string()),
            "getBlockHeight" => json!(101),
            "getSignatureStatuses" => {
                assert_eq!(params[0][0], "old");
                json!({"value": [{"err": "InsufficientFunds", "confirmationStatus": "finalized"}]})
            }
            other => panic!("unexpected RPC {other}"),
        }))
        .await;
        let relay = relay(url);
        relay.store.add_backing("nonce:aa", "ek").unwrap();
        let old = store::IssuedTransaction {
            signature: "old".into(),
            owner: "ek".into(),
            source: "ata".into(),
            last_valid_height: 100,
            fee_lamports: 10_000,
            backing: Some("nonce:aa".into()),
            ..Default::default()
        };
        relay
            .store
            .reserve_submission(&old, now_ms(), 100_000, None)
            .unwrap();
        let ticket = Ticket {
            kind: TicketKind::Sweep,
            message: String::new(),
            owner: old.owner,
            source: old.source,
            last_valid_height: 250,
            table: None,
            event: None,
            backing: old.backing,
        };
        let signed = SignedTransaction {
            bytes: vec![2],
            signature: "new".into(),
        };
        assert_eq!(
            relay
                .reserve_submission(&ticket, &signed)
                .await
                .unwrap_err()
                .code,
            "relay_backing_spent"
        );
        assert_eq!(relay.store.unspent_backing("ek", None).unwrap(), None);
    }

    #[tokio::test]
    async fn duplicate_submit_cannot_escape_a_rejected_broadcast_reservation() {
        let first_send = Arc::new(tokio::sync::Notify::new());
        let reject_first = Arc::new(tokio::sync::Notify::new());
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (started, release, count) = (first_send.clone(), reject_first.clone(), sends.clone());
        let router = axum::Router::new().route("/", axum::routing::post(move |Json(request): Json<Value>| {
            let (started, release, count) = (started.clone(), release.clone(), count.clone());
            async move {
                let result = match request["method"].as_str().unwrap() {
                    "getGenesisHash" => json!(SolanaHash::new_from_array([3; 32]).to_string()),
                    "getBlockHeight" => json!(100),
                    "getSignatureStatuses" => json!({"value": [null]}),
                    "simulateTransaction" => json!({"value": {"err": null, "logs": []}}),
                    "sendTransaction" => {
                        if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                            started.notify_one();
                            release.notified().await;
                            return Json(json!({"jsonrpc": "2.0", "id": 1,
                                "error": {"code": -32002, "message": "preflight rejected", "data": {"err": "InsufficientFunds"}}}));
                        }
                        let bytes = base64::engine::general_purpose::STANDARD.decode(request["params"][0].as_str().unwrap()).unwrap();
                        json!(bs58::encode(&bytes[1..65]).into_string())
                    }
                    other => panic!("unexpected RPC {other}"),
                };
                Json(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let relay = Arc::new(relay(format!("http://{address}")));
        let ek = Keypair::new();
        let message = tx::sweep_message(
            &relay.relayer,
            &ek.pubkey(),
            &Pubkey::new_unique(),
            &relay.config.fee_account,
            1,
            100,
            &SolanaHash::new_unique(),
        );
        let bytes = relay.unsigned(&message).unwrap();
        let token = relay
            .ticket(
                TicketKind::Sweep,
                &bytes,
                &ek.pubkey(),
                250,
                None,
                None,
                None,
            )
            .unwrap();
        let signed = tx::complete(&bytes, &ek, &[]).unwrap().bytes;
        let submit = |relay: Arc<Relay>| {
            let body = SubmitBody {
                token: token.clone(),
                transaction: signed.clone(),
            };
            tokio::spawn(async move { relay.submit(body).await })
        };
        let first = submit(relay.clone());
        first_send.notified().await;
        let mut second = submit(relay.clone());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut second)
                .await
                .is_err(),
            "a duplicate cannot broadcast or expose signed bytes before the first resolves"
        );
        reject_first.notify_one();
        assert_eq!(first.await.unwrap().unwrap_err().code, "invalid_request");
        second.await.unwrap().unwrap();
        assert_eq!(relay.store.outstanding_issuances().unwrap().len(), 1);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn receive_subsidy_refuses_dust_and_stops_at_the_durable_budget() {
        let mut relay = relay("http://127.0.0.1:9".into());
        assert_eq!(
            relay.check_burn_minimum(4_999_999).unwrap_err().code,
            "burn_below_minimum"
        );
        relay.check_burn_minimum(5_000_000).unwrap();
        let mut inbound = InboundMessage {
            nonce: [1; 32],
            owner: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            amount: 999_999,
            source_sender: [2; 32],
            net_amount: 900_000,
            expiration_block: 0,
        };
        assert_eq!(
            relay
                .reserve_receive_subsidy(&inbound, 6, 958_520, 0)
                .unwrap_err()
                .code,
            "receive_below_minimum"
        );
        inbound.amount = 1_000_000;
        relay.config.receive.daily_lamports = 958_520;
        relay
            .reserve_receive_subsidy(&inbound, 6, 958_520, 0)
            .unwrap();
        relay
            .reserve_receive_subsidy(&inbound, 6, 958_520, 0)
            .expect("the same message's used_nonce rent is never charged twice");
        assert_eq!(
            relay
                .reserve_receive_subsidy(&inbound, 6, 958_520, 1)
                .unwrap_err()
                .code,
            "receive_budget_exhausted",
            "new lookup-table rent is still charged"
        );
        inbound.nonce = [3; 32];
        assert_eq!(
            relay
                .reserve_receive_subsidy(&inbound, 6, 1, 0)
                .unwrap_err()
                .code,
            "receive_budget_exhausted"
        );
    }

    /// Deposit note-id contention is recognised only at the deposit's own
    /// vault instruction with the vault's StaleNoteId code.
    #[test]
    fn only_deposit_note_id_contention_is_forgivable() {
        assert_eq!(
            u64::from(u32::from(dagon_zkapi_vault::VaultError::StaleNoteId)),
            VAULT_STALE_NOTE_ID
        );
        let reason =
            |ix: u8, code: u64| json!({"InstructionError": [ix, {"Custom": code}]}).to_string();
        assert!(note_id_contention(&reason(5, 6006), Some(5)));
        assert!(
            !note_id_contention(&reason(4, 6006), Some(5)),
            "another program's 6006"
        );
        assert!(!note_id_contention(&reason(5, 6007), Some(5)));
        assert!(!note_id_contention(&reason(5, 6006), None), "not a deposit");
        assert!(!note_id_contention("\"AccountInUse\"", Some(5)));
    }

    /// A fallback receive for a victim's public attested message can be
    /// requested by anyone. Repeating it must not spend the victim's daily
    /// emergency-key and source-address allowances (or the global budget).
    #[test]
    fn repeated_preparations_of_a_public_message_cannot_exhaust_a_victims_allowance() {
        let mut relay = relay("http://127.0.0.1:9".into());
        relay.config.receive.daily_lamports = 10 * 958_520;
        relay.config.receive.per_address_daily = 2;
        let mut victim = InboundMessage {
            nonce: [1; 32],
            owner: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            amount: 1_000_000,
            source_sender: [2; 32],
            net_amount: 900_000,
            expiration_block: 0,
        };
        for _ in 0..20 {
            relay
                .reserve_receive_subsidy(&victim, 6, 958_520, 0)
                .expect("an attacker repeating the victim's message");
        }
        // The victim's next transfer (new nonce, same ek and EVM sender) is still served.
        victim.nonce = [4; 32];
        relay
            .reserve_receive_subsidy(&victim, 6, 958_520, 0)
            .unwrap();
        victim.nonce = [5; 32];
        assert_eq!(
            relay
                .reserve_receive_subsidy(&victim, 6, 958_520, 0)
                .unwrap_err()
                .code,
            "receive_address_limited",
            "distinct messages still count against the per-address allowance"
        );
    }

    /// The hold-without-submit attack: preparations are unsigned and reserve
    /// nothing however many are requested (the float here fits ONE burn);
    /// only a transaction the relay itself signs and broadcasts at submit
    /// reserves loss budget and float, once, and one per ek at a time.
    #[tokio::test]
    async fn unsubmitted_preparations_hold_nothing_and_submission_reserves_once() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};
        let ek = Keypair::new();
        let owner = ek.pubkey();
        let accounts = cctp::CctpAccounts::new(USDC_MINT);
        let height = Arc::new(AtomicU64::new(100));
        let sends = Arc::new(AtomicUsize::new(0));
        let verified = Arc::new(AtomicUsize::new(0));
        let (current, sent, checked) = (height.clone(), sends.clone(), verified.clone());
        let url = mock_rpc(Arc::new(move |method, params| match method {
            "getGenesisHash" => json!(SolanaHash::new_from_array([3; 32]).to_string()),
            "getAccountInfo" => {
                let address: Pubkey = params[0].as_str().unwrap().parse().unwrap();
                if address == accounts.message_transmitter {
                    let mut data = cctp::MESSAGE_TRANSMITTER_ACCOUNT.to_vec();
                    data.resize(225, 0);
                    account(&cctp::MESSAGE_TRANSMITTER_V2, &data)
                } else if address == accounts.token_minter {
                    let mut data = cctp::TOKEN_MINTER_ACCOUNT.to_vec();
                    data.resize(74, 0);
                    account(&cctp::TOKEN_MESSENGER_MINTER_V2, &data)
                } else if address == cctp::remote_token_messenger(6) {
                    account(&cctp::TOKEN_MESSENGER_MINTER_V2, &[0; 44])
                } else if address == ata(&owner) {
                    token_account(&owner, 10_000_000)
                } else {
                    ABSENT()
                }
            }
            "getMinimumBalanceForRentExemption" => {
                json!((128 + params[0].as_u64().unwrap()) * 6_960)
            }
            "getBalance" => json!({"context": {"slot": 7}, "value": 10_000_000_000u64}),
            "getLatestBlockhash" => json!({"context": {"slot": 100}, "value": {
                "blockhash": SolanaHash::new_unique().to_string(),
                "lastValidBlockHeight": 250,
            }}),
            "getBlockHeight" => json!(current.load(SeqCst)),
            "getSignatureStatuses" => json!({"value": [null]}),
            "simulateTransaction" => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(params[0].as_str().unwrap())
                    .unwrap();
                let slots = &bytes[1..1 + 64 * usize::from(bytes[0])];
                if params[1]["sigVerify"] == true {
                    assert!(slots.chunks(64).all(|slot| slot != [0u8; 64]));
                    checked.fetch_add(1, SeqCst);
                } else {
                    assert!(slots.iter().all(|byte| *byte == 0), "prepared unsigned");
                }
                json!({"context": {"slot": 100}, "value": {"err": null, "logs": []}})
            }
            "sendTransaction" => {
                sent.fetch_add(1, SeqCst);
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(params[0].as_str().unwrap())
                    .unwrap();
                json!(bs58::encode(&bytes[1..65]).into_string())
            }
            other => panic!("unexpected RPC {other} {params}"),
        }))
        .await;
        let mut relay = relay(url);
        relay.config.burn_minimum_amount = 1;
        relay.config.burn_float_lamports = (128 + MESSAGE_SENT_BASE_SPACE as u64) * 6_960;
        let mut burns = Vec::new();
        for _ in 0..PER_KEY_LIMIT {
            burns.push(relay.prepare_burn(burn_body(&owner)).await.unwrap());
        }
        assert!(
            relay.store.outstanding_issuances().unwrap().is_empty(),
            "no loss budget held"
        );
        assert!(
            relay.store.event_accounts().unwrap().is_empty(),
            "no float held"
        );
        assert_eq!(sends.load(SeqCst), 0);
        let sign = |wire: &TransactionWire| {
            let mut bytes = wire.bytes.clone();
            let message = tx::message_bytes(&bytes).unwrap().to_vec();
            let decoded: Message = bincode::deserialize(&message).unwrap();
            let index = decoded
                .account_keys
                .iter()
                .position(|key| *key == owner)
                .unwrap();
            bytes[1 + 64 * index..1 + 64 * (index + 1)]
                .copy_from_slice(ek.sign_message(&message).as_ref());
            bytes
        };
        let submit = |index: usize, transaction: Vec<u8>| SubmitBody {
            token: burns[index].submit_token.clone(),
            transaction,
        };
        // A forged ticket, a different message, another prepare's ticket.
        let mut forged = submit(0, sign(&burns[0].transaction));
        forged.token.push('0');
        assert_eq!(
            relay.submit(forged).await.unwrap_err().code,
            "invalid_request"
        );
        let mut changed = sign(&burns[0].transaction);
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            relay.submit(submit(0, changed)).await.unwrap_err().code,
            "invalid_request"
        );
        assert_eq!(
            relay
                .submit(submit(1, sign(&burns[0].transaction)))
                .await
                .unwrap_err()
                .code,
            "invalid_request"
        );
        assert_eq!(sends.load(SeqCst), 0);

        let submitted = relay
            .submit(submit(0, sign(&burns[0].transaction)))
            .await
            .unwrap();
        assert_eq!((sends.load(SeqCst), verified.load(SeqCst)), (1, 1));
        assert_eq!(
            submitted.signature,
            bs58::encode(&submitted.transaction.bytes[1..65]).into_string()
        );
        assert_eq!(relay.store.outstanding_issuances().unwrap().len(), 1);
        assert_eq!(relay.store.event_accounts().unwrap().len(), 1);
        // Idempotent: the same signature, reserved once.
        let again = relay
            .submit(submit(0, sign(&burns[0].transaction)))
            .await
            .unwrap();
        assert_eq!(again.signature, submitted.signature);
        assert_eq!(again.transaction.bytes, submitted.transaction.bytes);
        assert_eq!(relay.store.outstanding_issuances().unwrap().len(), 1);
        // One executable submission per ek: one ek transfer can fail one relay tx.
        assert_eq!(
            relay
                .submit(submit(1, sign(&burns[1].transaction)))
                .await
                .unwrap_err()
                .code,
            "relay_submission_pending"
        );
        // Past its validity a prepared transaction is never signed.
        height.store(251, SeqCst);
        assert_eq!(
            relay
                .submit(submit(2, sign(&burns[2].transaction)))
                .await
                .unwrap_err()
                .code,
            "relay_transaction_expired"
        );
        assert_eq!(relay.store.outstanding_issuances().unwrap().len(), 1);
        assert_eq!(sends.load(SeqCst), 2);
    }

    #[tokio::test]
    async fn unsigned_expired_preparations_cannot_ban_a_victim_or_consume_loss_budget() {
        use store::{IssuedTransaction, RiskAdmission};
        let height = Arc::new(std::sync::atomic::AtomicU64::new(100));
        let current = height.clone();
        let url = mock_rpc(Arc::new(move |method, params| match method {
            "getGenesisHash" => json!(bs58::encode([3u8; 32]).into_string()),
            "getBlockHeight" => {
                assert_eq!(params[0]["commitment"], "finalized");
                json!(current.load(std::sync::atomic::Ordering::SeqCst))
            }
            "getSignatureStatuses" => {
                assert_eq!(params[1]["searchTransactionHistory"], true);
                json!({"value": [null]})
            }
            _ => panic!("unexpected RPC {method}"),
        }))
        .await;
        let relay = relay(url);
        let issued = |signature: String| IssuedTransaction {
            signature,
            owner: "victim".into(),
            source: "victim-ata".into(),
            last_valid_height: 100,
            fee_lamports: 10_000,
            ..Default::default()
        };
        for index in 0..3 {
            assert_eq!(
                relay
                    .store
                    .reserve_issuance(&issued(format!("unsigned-{index}")), now_ms(), 30_000, None)
                    .unwrap(),
                RiskAdmission::Accepted
            );
        }
        relay.reconcile_issuances().await.unwrap();
        assert_eq!(
            relay.store.outstanding_issuances().unwrap().len(),
            3,
            "not released while still executable"
        );
        height.store(101, std::sync::atomic::Ordering::SeqCst);
        relay.reconcile_issuances().await.unwrap();
        assert!(relay.store.outstanding_issuances().unwrap().is_empty());
        for index in 0..3 {
            assert_eq!(
                relay
                    .store
                    .reserve_issuance(&issued(format!("retry-{index}")), now_ms(), 30_000, None)
                    .unwrap(),
                RiskAdmission::Accepted,
                "no victim ban and the complete unused budget is available"
            );
        }
    }

    #[tokio::test]
    async fn failed_permissionless_receives_cost_the_global_budget_but_do_not_ban_recipients() {
        use store::{IssuedTransaction, RiskAdmission};
        let url = mock_rpc(Arc::new(|method, _| match method {
            "getGenesisHash" => json!(bs58::encode([3u8; 32]).into_string()),
            "getBlockHeight" => json!(101),
            "getSignatureStatuses" => json!({"value": [{
                "slot": 99, "confirmationStatus": "finalized",
                "err": {"InstructionError": [1, {"Custom": 6000}]}
            }]}),
            _ => panic!("unexpected RPC {method}"),
        }))
        .await;
        let mut relay = relay(url);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("risk.db");
        relay.store = RelayStore::open(&path).unwrap();
        let issued = |signature: String, fee_lamports| IssuedTransaction {
            signature,
            owner: "victim".into(),
            source: "attested-source".into(),
            last_valid_height: 100,
            fee_lamports,
            ..Default::default()
        };
        for index in 0..3 {
            assert_eq!(
                relay
                    .store
                    .reserve_issuance(
                        &issued(format!("receive-{index}"), 5_000),
                        now_ms(),
                        15_000,
                        None
                    )
                    .unwrap(),
                RiskAdmission::Accepted
            );
        }
        relay.reconcile_issuances().await.unwrap();
        relay.store = RelayStore::open(&path).unwrap();
        let next = issued("victim-paid".into(), 10_000);
        assert_eq!(
            relay
                .store
                .reserve_issuance(&next, now_ms(), 15_000, None)
                .unwrap(),
            RiskAdmission::LossBudgetExhausted,
            "actual receive failures remain durable losses"
        );
        assert_eq!(
            relay
                .store
                .reserve_issuance(&next, now_ms(), 25_000, None)
                .unwrap(),
            RiskAdmission::Accepted,
            "permissionless failures cannot ban the victim"
        );
    }

    /// A relay over `rpc_url` with Solana rent and a fresh in-memory store.
    fn relay(rpc_url: String) -> Relay {
        let config = crate::test_support::config(crate::test_support::oa_source());
        let ledger = Arc::new(
            SolanaCreditLedger::new(dagon_zkapi_solana_ledger::SolanaLedgerConfig {
                rpc_url,
                ..config.ledger_config()
            })
            .unwrap(),
        );
        let rent = |bytes: u64| (128 + bytes) * 6_960;
        let keypair = Keypair::new();
        Relay {
            tickets: TicketKey::new(&keypair),
            config: RelayConfig {
                keypair,
                fee_account: Pubkey::new_unique(),
                margin_bps: 2_000,
                sol_usd_micros: 88_890_000,
                iris_url: "http://127.0.0.1:9".into(),
                min_lamports: 50_000_000,
                receive: super::super::config::ReceivePolicy::default(),
                burn_minimum_amount: 5_000_000,
                burn_float_lamports: 500_000_000,
                daily_loss_lamports: 20_000_000,
                unbacked_daily_loss_lamports: 2_000_000,
            },
            relayer: Pubkey::default(),
            vault_program: ledger.program_id(),
            ledger,
            store: RelayStore::in_memory().unwrap(),
            iris: IrisClient::new("http://127.0.0.1:9").unwrap(),
            rent: RentTable {
                note: rent(note_account_len() as u64),
                used_nullifier: rent(used_nullifier_account_len() as u64),
                token_account: rent(165),
                used_nonce: rent(9),
            },
            limiter: RateLimiter::new(),
            lookup_table: tokio::sync::Mutex::new(()),
            receive_lock: tokio::sync::Mutex::new(()),
            submit_lock: tokio::sync::Mutex::new(()),
        }
        .with_relayer()
    }

    impl Relay {
        fn with_relayer(mut self) -> Self {
            self.relayer = self.config.keypair.pubkey();
            self
        }
    }

    fn deposit_body(depositor: &Pubkey, amount: &str, max_fee: &str) -> DepositBody {
        DepositBody {
            depositor: depositor.to_string(),
            expected_note_id: 0,
            commitment: Felt252::from_u64(5),
            amount: amount.into(),
            zero_path: vec![Felt252::ZERO; MERKLE_DEPTH],
            max_fee: max_fee.into(),
            inbound: None,
        }
    }

    /// Deposits are refused before the relayer spends anything: above the
    /// wallet's cap, without amount + fee in ATA(ek), below the SOL floor,
    /// and for the relayer's own key.
    #[tokio::test]
    async fn deposit_refusals_spend_nothing() {
        let ek = Pubkey::new_unique();
        let balance = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
        let funded = balance.clone();
        let url = mock_rpc(Arc::new(move |method, params| match method {
            "getAccountInfo" => {
                token_account(&ek, funded.load(std::sync::atomic::Ordering::SeqCst))
            }
            "getMinimumBalanceForRentExemption" => json!(3_000_000),
            "getBalance" => json!({"context": {"slot": 7}, "value": 10_000_000}),
            other => panic!("unexpected RPC {other} {params}"),
        }))
        .await;
        let relay = relay(url);
        let quote = relay.quote(RelayKind::Deposit, false);
        // (1,656,480 note rent at 6,960 lamports per (128 + bytes) + 2 × 5,000)
        // lamports at $88.89 + 20%.
        assert_eq!(quote, 177_761);

        let error = relay
            .prepare_deposit(deposit_body(&ek, "1000", &(quote - 1).to_string()))
            .await
            .unwrap_err();
        assert_eq!(error.code, "relay_fee_above_cap");

        let error = relay
            .prepare_deposit(deposit_body(&ek, "900000", &quote.to_string()))
            .await
            .unwrap_err();
        assert_eq!(error.code, "insufficient_funds", "{}", error.message);

        balance.store(10_000_000, std::sync::atomic::Ordering::SeqCst);
        let error = relay
            .prepare_deposit(deposit_body(&ek, "900000", &quote.to_string()))
            .await
            .unwrap_err();
        assert_eq!(error.code, "relayer_unavailable", "{}", error.message);
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);

        let error = relay
            .prepare_deposit(deposit_body(&relay.relayer, "1", "1000000"))
            .await
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");

        // Nothing was broadcast by any refusal.
        assert!(relay.store.in_flight().unwrap().is_empty());
    }

    fn burn_body(owner: &Pubkey) -> BurnBody {
        BurnBody {
            owner: owner.to_string(),
            destination_domain: 6,
            mint_recipient: "11".repeat(32),
            destination_caller: None,
            max_cctp_fee: "60000".into(),
            min_finality_threshold: cctp::FINALITY_STANDARD,
            hook_data: String::new(),
            max_fee: "50000".into(),
            inbound: None,
        }
    }

    /// Burns read Circle's pause flags first (`cctp_paused`), then refuse an
    /// unsupported domain, a denylisted owner and a balance that cannot cover
    /// the relay fee plus more than `max_cctp_fee`.
    #[tokio::test]
    async fn burn_refusals_follow_circle_state() {
        let ek = Pubkey::new_unique();
        let accounts = cctp::CctpAccounts::new(USDC_MINT);
        let paused = Arc::new(std::sync::atomic::AtomicU8::new(1));
        let denylisted = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flags = (paused.clone(), denylisted.clone());
        let url = mock_rpc(Arc::new(move |method, params| {
            if method == "getMinimumBalanceForRentExemption" {
                return json!((128 + params[0].as_u64().unwrap()) * 6_960);
            }
            assert_eq!(method, "getAccountInfo", "{params}");
            let address: Pubkey = params[0].as_str().unwrap().parse().unwrap();
            let pause = flags.0.load(std::sync::atomic::Ordering::SeqCst);
            if address == accounts.message_transmitter {
                let mut data = cctp::MESSAGE_TRANSMITTER_ACCOUNT.to_vec();
                data.resize(225, 0);
                data[136] = u8::from(pause == 1);
                account(&cctp::MESSAGE_TRANSMITTER_V2, &data)
            } else if address == accounts.token_minter {
                let mut data = cctp::TOKEN_MINTER_ACCOUNT.to_vec();
                data.resize(74, 0);
                data[72] = u8::from(pause == 2);
                account(&cctp::TOKEN_MESSENGER_MINTER_V2, &data)
            } else if address == cctp::remote_token_messenger(6) {
                account(&cctp::TOKEN_MESSENGER_MINTER_V2, &[0; 44])
            } else if address == cctp::denylist_account(&ek) {
                if flags.1.load(std::sync::atomic::Ordering::SeqCst) {
                    account(&cctp::TOKEN_MESSENGER_MINTER_V2, &[0; 40])
                } else {
                    ABSENT()
                }
            } else if address == ata(&ek) {
                token_account(&ek, 70_000)
            } else {
                ABSENT()
            }
        }))
        .await;
        let relay = relay(url);
        let error = relay.prepare_burn(burn_body(&ek)).await.unwrap_err();
        assert_eq!((error.code, error.status.as_u16()), ("cctp_paused", 503));
        paused.store(2, std::sync::atomic::Ordering::SeqCst);
        let error = relay.prepare_burn(burn_body(&ek)).await.unwrap_err();
        assert_eq!(error.code, "cctp_paused");
        assert!(error.message.contains("TokenMinter"));
        paused.store(0, std::sync::atomic::Ordering::SeqCst);

        let mut unsupported = burn_body(&ek);
        unsupported.destination_domain = 99;
        assert_eq!(
            relay.prepare_burn(unsupported).await.unwrap_err().code,
            "invalid_request"
        );
        let error = relay.prepare_burn(burn_body(&ek)).await.unwrap_err();
        assert!(error.message.contains("denylisted"), "{}", error.message);
        denylisted.store(false, std::sync::atomic::Ordering::SeqCst);
        // The signature fee leaves less than the 70,000 CCTP fee ceiling.
        let mut tight = burn_body(&ek);
        tight.max_cctp_fee = "70000".into();
        let error = relay.prepare_burn(tight).await.unwrap_err();
        assert_eq!(error.code, "insufficient_funds", "{}", error.message);
        let mut low_cap = burn_body(&ek);
        low_cap.max_fee = "1".into();
        assert_eq!(
            relay.prepare_burn(low_cap).await.unwrap_err().code,
            "relay_fee_above_cap"
        );
        // Public preparations cannot spend a victim's per-owner quota.
        for _ in 0..PER_KEY_LIMIT {
            let mut public = burn_body(&ek);
            public.max_fee = "1".into();
            assert_eq!(
                relay.prepare_burn(public).await.unwrap_err().code,
                "relay_fee_above_cap"
            );
        }
        let relay = Relay {
            limiter: RateLimiter::new(),
            ..relay
        };
        for (field, value) in [("solana", 5u32), ("finality", 1_500)] {
            let mut body = burn_body(&ek);
            if field == "solana" {
                body.destination_domain = value;
            } else {
                body.min_finality_threshold = value;
            }
            assert_eq!(
                relay.prepare_burn(body).await.unwrap_err().code,
                "invalid_request"
            );
        }
    }

    /// The relay's vault, a note bound to `inputs`, and the relay's lookup
    /// table holding the exit accounts, as the ledger reads them.
    struct ExitChain {
        vault_state: Pubkey,
        vault: Value,
        note_address: Pubkey,
        note: Value,
        inputs: WithdrawalPublicInputsV2,
    }

    fn exit_chain(ek: &Pubkey) -> ExitChain {
        use anchor_lang::AccountSerialize;
        use dagon_zkapi_vault as vault_program;
        let config = crate::test_support::config(crate::test_support::oa_source());
        let program = Pubkey::new_from_array(config.profile.program_id());
        let identity = &config.identity;
        let authority = Pubkey::new_from_array(identity.vault_authority);
        let (vault_state, bump) =
            Pubkey::find_program_address(&[b"vault", authority.as_ref()], &program);
        let binding = zkapi_types::solana_deployment_binding(
            &program.to_bytes(),
            &vault_state.to_bytes(),
            &identity.genesis_hash,
        );
        let chain_id = zkapi_types::solana_chain_id(&identity.genesis_hash);
        let felt = Felt252::from_u64;
        let state = vault_program::VaultState {
            version: vault_program::VAULT_VERSION,
            bump,
            paused: false,
            authority,
            treasury_token: Pubkey::new_unique(),
            mint: USDC_MINT,
            vault_token: Pubkey::new_from_array(dagon_zkapi_profile::vault_token_address(
                &program.to_bytes(),
                &vault_state.to_bytes(),
            )),
            vault_token_bump: 255,
            genesis_hash: identity.genesis_hash,
            chain_id,
            protocol_binding: *binding.as_bytes(),
            current_root: [0; 32],
            next_note_id: 1,
            note_ttl: 86_400,
            challenge_period: 60,
            request_charge_cap: 1_000_000,
            total_credits: 1_000_000,
            state_signing_key_x: *felt(3).as_bytes(),
            state_signing_key_y: *felt(4).as_bytes(),
            clearance_signing_key_x: *felt(5).as_bytes(),
            clearance_signing_key_y: *felt(6).as_bytes(),
            paused_at: 0,
            last_pause_end: 0,
            total_paused_duration: 0,
            treasury_accrued: 0,
            deferred_payouts: 0,
        };
        let (note_address, note_bump) = Pubkey::find_program_address(
            &[b"note", vault_state.as_ref(), &0u32.to_le_bytes()],
            &program,
        );
        let note = vault_program::NoteState {
            vault: vault_state,
            note_id: 0,
            commitment: *felt(2).as_bytes(),
            deposit_amount: 1_000_000,
            expiry: 1,
            status: vault_program::NOTE_STATUS_ACTIVE,
            bump: note_bump,
            claimable_after: 0,
            paused_offset: 0,
        };
        let serialize = |value: &dyn Fn(&mut Vec<u8>)| {
            let mut data = Vec::new();
            value(&mut data);
            account(&program, &data)
        };
        ExitChain {
            vault_state,
            vault: serialize(&|data| state.try_serialize(data).unwrap()),
            note_address,
            note: serialize(&|data| note.try_serialize(data).unwrap()),
            inputs: WithdrawalPublicInputsV2 {
                protocol_version: zkapi_types::PROTOCOL_VERSION,
                chain_id,
                contract_address: binding,
                registration: felt(2),
                state_signing_key_x: felt(3),
                state_signing_key_y: felt(4),
                clearance_signing_key_x: felt(5),
                clearance_signing_key_y: felt(6),
                note_id: 0,
                deposit_amount: 1_000_000,
                expiry_ts: 1,
                final_balance: 900_000,
                destination: zkapi_types::solana_destination_binding(&ata(ek).to_bytes()),
                withdrawal_nullifier: felt(7),
                has_clearance: true,
                next_nullifier: Felt252::ZERO,
                conceded: 0,
                valid_until: u64::MAX,
            },
        }
    }

    fn lookup_table_account(relay_key: &Pubkey, addresses: &[Pubkey]) -> Value {
        let mut data = vec![0u8; cctp::LOOKUP_TABLE_META_SIZE];
        data[..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        data[12..20].copy_from_slice(&5u64.to_le_bytes());
        data[21] = 1;
        data[22..54].copy_from_slice(relay_key.as_ref());
        for address in addresses {
            data.extend_from_slice(address.as_ref());
        }
        account(&cctp::ADDRESS_LOOKUP_TABLE_PROGRAM, &data)
    }

    fn exit_body(ek: &Pubkey, kind: ExitKind, inputs: WithdrawalPublicInputsV2) -> ExitBody {
        ExitBody {
            kind,
            destination_owner: ek.to_string(),
            public_inputs: inputs,
            proof: Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: base64::engine::general_purpose::STANDARD.encode([7u8; 256]),
            },
            max_fee: "450000".into(),
        }
    }

    /// Audit #2: an exit with an invalid proof (refused by the vault in
    /// simulation) makes the relayer broadcast nothing at all — no ATA, no
    /// exit — and a mutual close carries the ATA creation, the close and the
    /// ek's fee transfer in one v0 transaction for the ek to sign. A relayed
    /// escape is refused unless `ATA(ek)` already holds the prepaid fee.
    #[tokio::test]
    async fn exits_send_nothing_and_escapes_are_prepaid() {
        let ek = Pubkey::new_unique();
        let chain = exit_chain(&ek);
        let table = Pubkey::new_unique();
        let relay_cell: Arc<std::sync::OnceLock<(Pubkey, Vec<Pubkey>)>> =
            Arc::new(std::sync::OnceLock::new());
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let simulation_fails = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ata_exists = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (cell, sent, fails, present) = (
            relay_cell.clone(),
            sends.clone(),
            simulation_fails.clone(),
            ata_exists.clone(),
        );
        let (vault_state, vault, note_address, note) = (
            chain.vault_state,
            chain.vault.clone(),
            chain.note_address,
            chain.note.clone(),
        );
        let url = mock_rpc(Arc::new(move |method, params| match method {
            "getGenesisHash" => json!(SolanaHash::new_from_array([3; 32]).to_string()),
            "getAccountInfo" => {
                let address: Pubkey = params[0].as_str().unwrap().parse().unwrap();
                let (relayer, addresses) = cell.get().unwrap();
                if address == vault_state {
                    vault.clone()
                } else if address == note_address {
                    note.clone()
                } else if address == table {
                    lookup_table_account(relayer, addresses)
                } else if address == ata(&ek) && present.load(std::sync::atomic::Ordering::SeqCst) {
                    token_account(&ek, 0)
                } else {
                    ABSENT()
                }
            }
            "getBalance" => json!({"context": {"slot": 7}, "value": 10_000_000_000u64}),
            "getMinimumBalanceForRentExemption" => json!(1_000_000),
            "getSlot" => json!(100),
            "getLatestBlockhash" => json!({"context": {"slot": 100}, "value": {
                "blockhash": SolanaHash::new_unique().to_string(),
                "lastValidBlockHeight": 250,
            }}),
            "simulateTransaction" => {
                // Prepared unsigned: the relayer signs only at submit.
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(params[0].as_str().unwrap())
                    .unwrap();
                assert_eq!(bytes[0], 2);
                assert_eq!(&bytes[1..129], &[0u8; 128]);
                assert_eq!(params[1]["sigVerify"], false);
                if fails.load(std::sync::atomic::Ordering::SeqCst) {
                    json!({"context": {"slot": 100}, "value": {
                        "err": {"InstructionError": [3, {"Custom": 6003}]},
                        "logs": ["Program log: invalid withdrawal proof"],
                    }})
                } else {
                    json!({"context": {"slot": 100}, "value": {"err": null, "logs": []}})
                }
            }
            "sendTransaction" => {
                sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                json!("unexpected")
            }
            other => panic!("unexpected RPC {other} {params}"),
        }))
        .await;
        let relay = relay(url);
        relay_cell
            .set((relay.relayer, relay.exit_lookup_addresses()))
            .unwrap();
        relay
            .store
            .set_meta(LOOKUP_TABLE_META_KEY, &table.to_string())
            .unwrap();

        let error = relay
            .prepare_exit(exit_body(&ek, ExitKind::Mutual, chain.inputs.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(error.message.contains("simulation"), "{}", error.message);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(relay.store.in_flight().unwrap().is_empty());

        // A valid close: one atomic v0 transaction for the ek to sign.
        simulation_fails.store(false, std::sync::atomic::Ordering::SeqCst);
        let prepared = relay
            .prepare_exit(exit_body(&ek, ExitKind::Mutual, chain.inputs.clone()))
            .await
            .unwrap();
        assert_eq!(prepared.destination, ata(&ek).to_string());
        let fee: u64 = prepared.fee.parse().unwrap();
        assert_eq!(fee, relay.quote(RelayKind::Close, true));
        let transaction = &prepared.transaction;
        assert_eq!(transaction.format, V0_TRANSACTION_FORMAT);
        let tables = transaction.lookup_tables.as_ref().unwrap();
        assert_eq!(tables[0].address, table.to_string());
        let message: dagon_zkapi_solana_ledger::VersionedMessage =
            bincode::deserialize(&transaction.bytes[129..]).unwrap();
        let dagon_zkapi_solana_ledger::VersionedMessage::V0(message) = message else {
            panic!("expected a v0 message");
        };
        assert_eq!(message.account_keys[..2], [relay.relayer, ek]);
        assert_eq!(message.header.num_required_signatures, 2);
        // heap, CU limit, CreateIdempotent, execute_close, fee transfer.
        assert_eq!(message.instructions.len(), 5);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);

        // With ATA(ek) already present (after a CCTP deposit) the close keeps
        // the same five instructions; the no-op ATA creation is not charged.
        ata_exists.store(true, std::sync::atomic::Ordering::SeqCst);
        let prepared = relay
            .prepare_exit(exit_body(&ek, ExitKind::Mutual, chain.inputs.clone()))
            .await
            .unwrap();
        assert_eq!(
            prepared.fee.parse::<u64>().unwrap(),
            relay.quote(RelayKind::Close, false)
        );
        let message: dagon_zkapi_solana_ledger::VersionedMessage =
            bincode::deserialize(&prepared.transaction.bytes[129..]).unwrap();
        assert_eq!(message.instructions().len(), 5);
        ata_exists.store(false, std::sync::atomic::Ordering::SeqCst);

        // Escapes are prepaid: no ATA(ek) holding the fee, no transaction.
        let mut escape = chain.inputs.clone();
        escape.has_clearance = false;
        escape.next_nullifier = Felt252::from_u64(8);
        let error = relay
            .prepare_exit(exit_body(&ek, ExitKind::Escape, escape))
            .await
            .unwrap_err();
        assert_eq!(error.code, "insufficient_funds", "{}", error.message);
        assert!(error.message.contains("prepaid"), "{}", error.message);

        let mut capped = exit_body(&ek, ExitKind::Mutual, chain.inputs.clone());
        capped.max_fee = (fee - 1).to_string();
        assert_eq!(
            relay.prepare_exit(capped).await.unwrap_err().code,
            "relay_fee_above_cap"
        );
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn sweeps_only_go_to_existing_usdc_accounts() {
        let ek = Pubkey::new_unique();
        let url = mock_rpc(Arc::new(move |method, params| {
            assert_eq!(method, "getAccountInfo", "{params}");
            ABSENT()
        }))
        .await;
        let relay = relay(url);
        let error = relay
            .prepare_sweep(SweepBody {
                owner: ek.to_string(),
                destination: Pubkey::new_unique().to_string(),
                max_fee: "50000".into(),
                inbound: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert!(error.message.contains("existing"), "{}", error.message);
    }

    fn inbound_bytes(owner: &Pubkey, recipient: &Pubkey, intent_owner: &Pubkey) -> Vec<u8> {
        let mut hook = b"cctp-forward".to_vec();
        hook.resize(24, 0);
        hook.extend_from_slice(&0u32.to_be_bytes());
        hook.extend_from_slice(&33u32.to_be_bytes());
        hook.push(1);
        hook.extend_from_slice(owner.as_ref());
        let mut intent = vec![1u8];
        intent.extend_from_slice(&[7; 32]);
        intent.extend_from_slice(intent_owner.as_ref());
        intent.extend_from_slice(&[0; 60]);
        hook.extend_from_slice(cctp::INBOUND_INTENT_MARKER);
        hook.extend_from_slice(&(intent.len() as u16).to_le_bytes());
        hook.extend_from_slice(&intent);
        let mut body = vec![0u8; 228];
        body[0..4].copy_from_slice(&1u32.to_be_bytes());
        body[36..68].copy_from_slice(recipient.as_ref());
        body[92..100].copy_from_slice(&10_000_000u64.to_be_bytes());
        body[188..196].copy_from_slice(&246_092u64.to_be_bytes());
        body.extend_from_slice(&hook);
        let mut message = vec![0u8; 148];
        message[0..4].copy_from_slice(&1u32.to_be_bytes());
        message[4..8].copy_from_slice(&6u32.to_be_bytes());
        message[8..12].copy_from_slice(&5u32.to_be_bytes());
        message[12..44].fill(0x42);
        message[76..108].copy_from_slice(cctp::TOKEN_MESSENGER_MINTER_V2.as_ref());
        message.extend_from_slice(&body);
        message
    }

    /// Only zkAPI inbound messages (forward hook + intent for the same ek,
    /// minting to ATA(ek)) are relayed; anything else is refused.
    #[test]
    fn inbound_messages_must_name_one_emergency_key() {
        let ek = Pubkey::new_unique();
        let parsed = InboundMessage::parse(&inbound_bytes(&ek, &ata(&ek), &ek), 6).unwrap();
        assert_eq!(parsed.owner, ek);
        assert_eq!(parsed.nonce, [0x42; 32]);
        assert_eq!(parsed.net_amount, 10_000_000 - 246_092);
        let other = Pubkey::new_unique();
        assert!(InboundMessage::parse(&inbound_bytes(&ek, &ata(&ek), &other), 6).is_none());
        assert!(InboundMessage::parse(&inbound_bytes(&ek, &ata(&other), &ek), 6).is_none());
        assert!(InboundMessage::parse(&inbound_bytes(&ek, &ata(&ek), &ek), 3).is_none());
        let mut caller = inbound_bytes(&ek, &ata(&ek), &ek);
        caller[110] = 1;
        assert!(InboundMessage::parse(&caller, 6).is_none());
    }

    #[test]
    fn rate_limiter_counts_per_key_and_globally() {
        let limiter = RateLimiter::new();
        let start = Instant::now();
        let keys = |owner: &str| [("k:*".to_string(), 3), (format!("k:{owner}"), 2)];
        assert!(limiter.admit(&keys("a"), start));
        assert!(limiter.admit(&keys("a"), start));
        assert!(!limiter.admit(&keys("a"), start));
        assert!(limiter.admit(&keys("b"), start));
        // The global window is full, so "c" is refused and not counted.
        assert!(!limiter.admit(&keys("c"), start));
        let later = start + RATE_WINDOW;
        assert!(limiter.admit(&keys("c"), later));
        assert!(limiter.admit(&keys("a"), later));
    }

    #[test]
    fn amounts_and_hex_parse_strictly() {
        assert_eq!(parse_amount("150000", "fee").unwrap(), 150_000);
        for bad in ["", "-1", "1.5", "0x10", "18446744073709551616", " 1"] {
            assert_eq!(
                parse_amount(bad, "fee").unwrap_err().code,
                "invalid_request"
            );
        }
        assert_eq!(parse_hex32(&"ab".repeat(32), "x").unwrap(), [0xab; 32]);
        assert_eq!(
            parse_hex32(&format!("0x{}", "ab".repeat(32)), "x").unwrap(),
            [0xab; 32]
        );
        assert!(parse_hex32(&"ab".repeat(31), "x").is_err());
        assert!(parse_hex("zz", "x", 4).is_err());
        assert!(parse_hex("0102030405", "x", 4).is_err());
        assert_eq!(parse_hex("", "x", 4).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn errors_use_the_contract_envelope() {
        for (error, status, code) in [
            (RelayError::disabled(), 404, "relay_disabled"),
            (RelayError::insufficient("x"), 409, "insufficient_funds"),
            (RelayError::above_cap(2, 1), 409, "relay_fee_above_cap"),
            (RelayError::unavailable("x"), 503, "relayer_unavailable"),
            (RelayError::paused("x"), 503, "cctp_paused"),
            (RelayError::invalid("x"), 400, "invalid_request"),
            (
                RelayError::from(LedgerError::Rejected("stale".into())),
                400,
                "invalid_request",
            ),
            (
                RelayError::from(LedgerError::Unavailable("rpc".into())),
                503,
                "relayer_unavailable",
            ),
        ] {
            assert_eq!(error.status.as_u16(), status);
            assert_eq!(error.code, code);
        }
    }
}
