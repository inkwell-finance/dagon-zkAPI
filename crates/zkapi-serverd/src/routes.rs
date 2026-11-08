//! Axum HTTP routes for the zkAPI server.
//!
//! Endpoints:
//! - GET  /health                   -- process health and config summary
//! - GET  /v1/attestation           -- published signer metadata for deployments
//! - POST /v2/openrouter/leases     -- open a prompt-private runtime-key lease
//! - POST /v2/openrouter/leases/:id -- retire a rejected runtime-key lease
//! - POST /v2/withdraw/clearance    -- request mutual-close clearance
//! - POST /v2/ledger/*/prepare      -- prepare pinned Solana wallet operations
//!   (USDC deposit, close, escape, escape finalization, parked payout release,
//!   parked rent refund, canonical USDC account creation)
//! - GET  /v2/requests/:id          -- recover by client_request_id
//! - GET  /v2/nullifiers/:nullifier -- recover by nullifier
//! - GET  /v2/relay, POST /v2/relay/* -- optional CCTP relay ([`crate::relay`])

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dagon_zkapi_ledger::{
    CreateUsdcAccountRequest, DepositRequest, FinalizeEscapeRequest, LedgerAccount,
    LedgerCommitment, PreparedLedgerOperation, RefundPendingRentRequest,
    ReleaseEscapePayoutRequest, WithdrawalRequest,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use zkapi_types::wire::{
    ApiRequestV2, ClearanceRequest, ClearanceResponseV2, CurvePointWire, ErrorResponse,
    Groth16ProofWire, OpenRouterLeaseStatusResponse, RecoveryResponseV2,
};
use zkapi_types::{Felt252, WithdrawalPublicInputsV2, MERKLE_DEPTH};

use crate::dashboard::{DashboardEvent, DashboardHub, DashboardTotals};
use crate::error::ServerError;
use crate::oa_org::IssuedOpenRouterLease;
use crate::processor::RequestProcessor;
use crate::testnet_auth::{
    handle_auth_check, require_testnet_password, TestnetPassword, TESTNET_PASSWORD_HEADER,
};

/// Shared application state.
type AppState = Arc<RequestProcessor>;

// Keep handler error variants small without changing their status, headers or body.
struct ErrorHttpResponse(Box<(StatusCode, HeaderMap, Json<ErrorResponse>)>);

impl IntoResponse for ErrorHttpResponse {
    fn into_response(self) -> Response {
        (*self.0).into_response()
    }
}

// Compact proofs are small; leave headroom for ordinary API payloads.
const PROTOCOL_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Start the HTTP server with the given config.
pub async fn run_server(mut config: crate::config::ServerConfig) -> anyhow::Result<()> {
    if let Some(password) = TestnetPassword::from_env()? {
        config.testnet_password = Some(password);
    }
    config.validate()?;
    // Parsed before any network read or state: a bad relay setting fails closed.
    let relay_config = crate::relay::RelayConfig::from_env()?;
    let signer = Arc::new(crate::signer::ServerSigner::new(
        &config.state_seed,
        &config.clear_seed,
    ));
    // No durable state, worker, or HTTP listener exists during preflight.
    let backends = prepare_solana_backends(&config, &signer).await?;
    let store = Arc::new(crate::nullifier_store::NullifierStore::new(
        &config.db_path,
    )?);
    let relay = match relay_config {
        Some(relay_config) => Some(crate::relay::Relay::start(relay_config, &config).await?),
        None => None,
    };
    let dashboard = Arc::new(DashboardHub::new(500));
    let processor = RequestProcessor::try_new(
        config.clone(),
        store,
        signer,
        backends.initial_root,
        backends.ledger,
    )?;
    let processor = Arc::new(processor.with_dashboard(dashboard));
    spawn_root_poller(
        processor.clone(),
        Duration::from_millis(config.root_poll_interval_ms),
    );
    spawn_openrouter_lease_settler(
        processor.clone(),
        Duration::from_secs(config.profile.server.settlement_poll_seconds.max(1)),
    );
    if let Some(relay) = &relay {
        crate::relay::spawn_maintenance(relay.clone());
    }
    let router = create_router_with_relay(processor, relay);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(
        network = %config.network,
        "Server listening on {}",
        config.listen_addr
    );
    axum::serve(listener, router).await?;
    Ok(())
}

pub struct ValidatedSolanaBackends {
    pub ledger: Arc<dyn dagon_zkapi_ledger::CreditLedger>,
    pub initial_root: Felt252,
}

/// Fail-closed authoritative startup reads; deliberately independent of SQLite.
///
/// The finalized deployment must be the profile's (identity genesis hash,
/// immutable program with the profile's executable hash, vault parameters,
/// USDC mint, vault token account and the identity's treasury token account),
/// and the vault must be unpaused and pin this server's signing keys.
pub async fn prepare_solana_backends(
    config: &crate::config::ServerConfig,
    signer: &crate::signer::ServerSigner,
) -> anyhow::Result<ValidatedSolanaBackends> {
    config.validate()?;
    let ledger = Arc::new(dagon_zkapi_solana_ledger::SolanaCreditLedger::new(
        config.ledger_config(),
    )?);
    let view = ledger
        .assert_profile_deployment(&config.profile, &config.identity)
        .await?;
    anyhow::ensure!(!view.paused, "Solana vault is paused");
    let state_key = signer.state_public_key();
    let clearance_key = signer.clearance_public_key();
    anyhow::ensure!(
        view.state_signing_key_x == state_key.x && view.state_signing_key_y == state_key.y,
        "Solana vault state signing key mismatch"
    );
    anyhow::ensure!(
        view.clearance_signing_key_x == clearance_key.x
            && view.clearance_signing_key_y == clearance_key.y,
        "Solana vault clearance signing key mismatch"
    );
    Ok(ValidatedSolanaBackends {
        ledger,
        initial_root: view.state.root,
    })
}

/// Create the Axum router with all zkAPI server routes and no relay.
pub fn create_router(processor: Arc<RequestProcessor>) -> Router {
    create_router_with_relay(processor, None)
}

/// The zkAPI routes plus `/v2/relay*`, which answer `relay_disabled`
/// without a relay.
pub fn create_router_with_relay(
    processor: Arc<RequestProcessor>,
    relay: Option<Arc<crate::relay::Relay>>,
) -> Router {
    let password = processor.config().testnet_password.clone();
    // Preserve the local dashboard's existing CORS policy. A password-gated
    // testnet additionally permits explicit credential headers below.
    let dashboard = Router::new()
        .route("/v1/dashboard/summary", get(handle_dashboard_summary))
        .route("/v1/dashboard/recent", get(handle_dashboard_recent))
        .route("/v1/dashboard/events", get(handle_dashboard_events))
        .layer(CorsLayer::very_permissive());

    let router = Router::new()
        .route("/", get(handle_health))
        .route("/health", get(handle_health))
        .route("/v1/attestation", get(handle_attestation))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::HEAD]),
        )
        .route("/v2/auth", get(handle_auth_check))
        .route("/v2/openrouter/leases", post(handle_openrouter_lease))
        .route(
            "/v2/openrouter/leases/{client_request_id}",
            get(handle_openrouter_lease_status).post(handle_openrouter_lease_retirement),
        )
        .route("/v2/withdraw/clearance", post(handle_clearance))
        .route(
            "/v2/ledger/deposits/prepare",
            post(handle_prepare_ledger_deposit),
        )
        .route(
            "/v2/ledger/withdrawals/prepare",
            post(handle_prepare_ledger_close),
        )
        .route(
            "/v2/ledger/escapes/prepare",
            post(handle_prepare_ledger_escape),
        )
        .route(
            "/v2/ledger/escapes/finalize/prepare",
            post(handle_prepare_ledger_finalize_escape),
        )
        .route(
            "/v2/ledger/escapes/release/prepare",
            post(handle_prepare_ledger_release_escape_payout),
        )
        .route(
            "/v2/ledger/escapes/rent-refund/prepare",
            post(handle_prepare_ledger_refund_pending_rent),
        )
        .route(
            "/v2/ledger/usdc-accounts/prepare",
            post(handle_prepare_ledger_usdc_account),
        )
        .route(
            "/v2/requests/{client_request_id}",
            get(handle_recovery_by_id),
        )
        .route(
            "/v2/nullifiers/{nullifier}",
            get(handle_recovery_by_nullifier),
        )
        .merge(dashboard)
        .merge(crate::relay::router(relay))
        .layer(DefaultBodyLimit::max(PROTOCOL_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn_with_state(
            password.clone(),
            require_testnet_password,
        ))
        .with_state(processor);

    if password.is_some() {
        // The shared password is not an account cookie; no credentialed CORS.
        router.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::HEAD, Method::POST, Method::OPTIONS])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderName::from_static(TESTNET_PASSWORD_HEADER),
                ]),
        )
    } else {
        router
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    provider: &'static str,
    indexer_url: Option<String>,
    policy_enabled: bool,
    auth_scheme: &'static str,
    request_modes: Vec<&'static str>,
    testnet_password_required: bool,
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    status: &'static str,
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    state_signing_key: CurvePointWire,
    clearance_signing_key: CurvePointWire,
    auth_scheme: &'static str,
}

async fn handle_health(State(processor): State<AppState>) -> Json<HealthResponse> {
    let config = processor.config();
    Json(HealthResponse {
        status: "ok",
        protocol_version: config.protocol_version(),
        chain_id: config.chain_id(),
        contract_address: config.contract_address(),
        current_root: processor.current_root(),
        provider: "native_leases",
        indexer_url: config.indexer_url.clone(),
        policy_enabled: false,
        auth_scheme: "state-anchor",
        request_modes: vec!["direct_openrouter"],
        testnet_password_required: config.testnet_password.is_some(),
    })
}

async fn handle_attestation(State(processor): State<AppState>) -> Json<AttestationResponse> {
    let config = processor.config();
    Json(AttestationResponse {
        status: "ok",
        protocol_version: config.protocol_version(),
        chain_id: config.chain_id(),
        contract_address: config.contract_address(),
        current_root: processor.current_root(),
        state_signing_key: processor.state_signing_key(),
        clearance_signing_key: processor.clearance_signing_key(),
        auth_scheme: "state-anchor",
    })
}

async fn handle_openrouter_lease(
    State(processor): State<AppState>,
    Json(api_request): Json<ApiRequestV2>,
) -> Result<(StatusCode, Json<IssuedOpenRouterLease>), ErrorHttpResponse> {
    processor
        .issue_openrouter_lease(&api_request)
        .await
        .map(|response| (StatusCode::CREATED, Json(response)))
        .map_err(|error| error_to_response(&error, &api_request.client_request_id, &processor))
}

async fn handle_openrouter_lease_status(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Result<Json<OpenRouterLeaseStatusResponse>, StatusCode> {
    processor
        .openrouter_lease_status(&client_request_id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn handle_openrouter_lease_retirement(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
    Json(api_request): Json<ApiRequestV2>,
) -> Result<Json<OpenRouterLeaseStatusResponse>, ErrorHttpResponse> {
    processor
        .retire_openrouter_lease(&client_request_id, &api_request)
        .await
        .map(Json)
        .map_err(|error| error_to_response(&error, &client_request_id, &processor))
}

/// POST /v1/withdraw/clearance -- request a clearance signature.
async fn handle_clearance(
    State(processor): State<AppState>,
    Json(clearance_req): Json<ClearanceRequest>,
) -> Result<Json<ClearanceResponseV2>, ErrorHttpResponse> {
    processor
        .process_clearance(&clearance_req)
        .map(Json)
        .map_err(|e| {
            error_to_response(&e, &clearance_req.withdrawal_nullifier.to_hex(), &processor)
        })
}

/// GET /v1/requests/:client_request_id -- recover a response by client request ID.
async fn handle_recovery_by_id(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Result<Json<RecoveryResponseV2>, ErrorHttpResponse> {
    processor
        .recover_by_client_id(&client_request_id)
        .await
        .map(Json)
        .map_err(|e| error_to_response(&e, &client_request_id, &processor))
}

/// GET /v1/nullifiers/:nullifier -- recover a response by nullifier hex.
async fn handle_recovery_by_nullifier(
    State(processor): State<AppState>,
    Path(nullifier_hex): Path<String>,
) -> Result<Json<RecoveryResponseV2>, ErrorHttpResponse> {
    let nullifier = Felt252::from_hex(&nullifier_hex).map_err(|e| {
        let err = ServerError::InvalidRequest(format!("invalid nullifier hex: {}", e));
        error_to_response(&err, &nullifier_hex, &processor)
    })?;

    processor
        .recover_by_nullifier(&nullifier)
        .await
        .map(Json)
        .map_err(|e| error_to_response(&e, &nullifier_hex, &processor))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareDepositBody {
    payer: String,
    expected_note_id: u32,
    commitment: Felt252,
    amount: u128,
    zero_path: Vec<Felt252>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareWithdrawalBody {
    payer: String,
    destination: String,
    public_inputs: WithdrawalPublicInputsV2,
    proof: Groth16ProofWire,
}

/// `{payer, note_id}` of a pending escape (finalize, release, rent refund).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparePendingEscapeBody {
    payer: String,
    note_id: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareUsdcAccountBody {
    payer: String,
    owner: String,
}

#[derive(Debug, Serialize)]
struct PreparedLedgerOperationResponse {
    backend: String,
    network: String,
    /// Decimal string keeps the complete Solana-derived u64 identity in JS.
    chain_id: String,
    protocol_binding: Felt252,
    vault: String,
    operation: PreparedLedgerOperation,
}

fn ledger_account(value: &str, label: &str) -> Result<LedgerAccount, ServerError> {
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| ServerError::InvalidRequest(format!("{label} is not base58")))?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
        ServerError::InvalidRequest(format!("{label} must decode to exactly 32 bytes"))
    })?;
    if bytes == [0; 32] {
        return Err(ServerError::InvalidRequest(format!(
            "{label} cannot be the zero account"
        )));
    }
    Ok(LedgerAccount::new(bytes))
}

fn merkle_path(values: Vec<Felt252>, label: &str) -> Result<[Felt252; MERKLE_DEPTH], ServerError> {
    values.try_into().map_err(|values: Vec<Felt252>| {
        ServerError::InvalidRequest(format!(
            "{label} must contain {MERKLE_DEPTH} field elements, got {}",
            values.len()
        ))
    })
}

fn prepared_response(
    processor: &RequestProcessor,
    operation: PreparedLedgerOperation,
) -> PreparedLedgerOperationResponse {
    let deployment = processor.ledger_deployment();
    PreparedLedgerOperationResponse {
        backend: deployment.backend,
        network: deployment.network,
        chain_id: deployment.chain_id.to_string(),
        protocol_binding: deployment.protocol_binding,
        vault: bs58::encode(deployment.vault.0).into_string(),
        operation,
    }
}

async fn handle_prepare_ledger_deposit(
    State(processor): State<AppState>,
    Json(body): Json<PrepareDepositBody>,
) -> Result<Json<PreparedLedgerOperationResponse>, ErrorHttpResponse> {
    let request = (|| {
        Ok(DepositRequest {
            payer: ledger_account(&body.payer, "payer")?,
            expected_note_id: body.expected_note_id,
            commitment: body.commitment,
            amount: body.amount,
            zero_path: merkle_path(body.zero_path, "zero_path")?,
        })
    })()
    .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    let operation = processor
        .prepare_ledger_deposit(request)
        .await
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    Ok(Json(prepared_response(&processor, operation)))
}

fn withdrawal_request(body: PrepareWithdrawalBody) -> Result<WithdrawalRequest, ServerError> {
    Ok(WithdrawalRequest {
        payer: ledger_account(&body.payer, "payer")?,
        destination: ledger_account(&body.destination, "destination")?,
        public_inputs: body.public_inputs,
        proof: body.proof,
    })
}

async fn handle_prepare_ledger_close(
    State(processor): State<AppState>,
    Json(body): Json<PrepareWithdrawalBody>,
) -> Result<Json<PreparedLedgerOperationResponse>, ErrorHttpResponse> {
    let request = withdrawal_request(body)
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    let operation = processor
        .prepare_ledger_close(request)
        .await
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    Ok(Json(prepared_response(&processor, operation)))
}

async fn handle_prepare_ledger_escape(
    State(processor): State<AppState>,
    Json(body): Json<PrepareWithdrawalBody>,
) -> Result<Json<PreparedLedgerOperationResponse>, ErrorHttpResponse> {
    let request = withdrawal_request(body)
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    let operation = processor
        .prepare_ledger_escape(request)
        .await
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    Ok(Json(prepared_response(&processor, operation)))
}

async fn handle_prepare_ledger_finalize_escape(
    State(processor): State<AppState>,
    Json(body): Json<PreparePendingEscapeBody>,
) -> Result<Json<PreparedLedgerOperationResponse>, ErrorHttpResponse> {
    let request = FinalizeEscapeRequest {
        payer: ledger_account(&body.payer, "payer")
            .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?,
        note_id: body.note_id,
    };
    let operation = processor
        .prepare_ledger_finalize_escape(request)
        .await
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    Ok(Json(prepared_response(&processor, operation)))
}

async fn handle_prepare_ledger_release_escape_payout(
    State(processor): State<AppState>,
    Json(body): Json<PreparePendingEscapeBody>,
) -> Result<Json<PreparedLedgerOperationResponse>, ErrorHttpResponse> {
    let request = ReleaseEscapePayoutRequest {
        payer: ledger_account(&body.payer, "payer")
            .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?,
        note_id: body.note_id,
    };
    let operation = processor
        .prepare_ledger_release_escape_payout(request)
        .await
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    Ok(Json(prepared_response(&processor, operation)))
}

async fn handle_prepare_ledger_refund_pending_rent(
    State(processor): State<AppState>,
    Json(body): Json<PreparePendingEscapeBody>,
) -> Result<Json<PreparedLedgerOperationResponse>, ErrorHttpResponse> {
    let request = RefundPendingRentRequest {
        payer: ledger_account(&body.payer, "payer")
            .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?,
        note_id: body.note_id,
    };
    let operation = processor
        .prepare_ledger_refund_pending_rent(request)
        .await
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    Ok(Json(prepared_response(&processor, operation)))
}

/// Idempotently create `owner`'s canonical USDC token account, rent paid by
/// `payer`; deposits draw from it and payouts default to it.
async fn handle_prepare_ledger_usdc_account(
    State(processor): State<AppState>,
    Json(body): Json<PrepareUsdcAccountBody>,
) -> Result<Json<PreparedLedgerOperationResponse>, ErrorHttpResponse> {
    let request = (|| {
        Ok(CreateUsdcAccountRequest {
            payer: ledger_account(&body.payer, "payer")?,
            owner: ledger_account(&body.owner, "owner")?,
        })
    })()
    .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    let operation = processor
        .prepare_ledger_usdc_account(request)
        .await
        .map_err(|error| error_to_response(&error, "ledger-prepare", &processor))?;
    Ok(Json(prepared_response(&processor, operation)))
}

/// Server identity + signing capacity for the dashboard header panel.
#[derive(Debug, Serialize)]
struct ServerIdentity {
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    provider: &'static str,
    upstream_kind: Option<String>,
    upstream_api_base: Option<String>,
    auth_scheme: &'static str,
    policy_enabled: bool,
    /// USDC base units (micro-USDC).
    request_charge_cap: u128,
    request_charge_cap_usd: f64,
    /// One base unit is billed per metered micro-USD.
    credits_per_usd: f64,
    billing_asset: &'static str,
    billing_unit: &'static str,
    asset: BillingAsset,
    state_signing_key: CurvePointWire,
    clearance_signing_key: CurvePointWire,
}

/// The vault's settlement token.
#[derive(Debug, Serialize)]
struct BillingAsset {
    symbol: String,
    decimals: u8,
    mint: String,
}

#[derive(Debug, Serialize)]
struct DashboardSummary {
    server: ServerIdentity,
    totals: DashboardTotals,
    started_ms: u64,
    recent_count: usize,
}

/// GET /v1/dashboard/summary -- server identity + running totals.
async fn handle_dashboard_summary(State(processor): State<AppState>) -> Json<DashboardSummary> {
    let config = processor.config();
    let (upstream_kind, upstream_api_base) = match &config.lease_source {
        crate::config::OpenRouterLeaseSourceConfig::OpenRouter { api_base, .. } => {
            ("openrouter", api_base.clone())
        }
        crate::config::OpenRouterLeaseSourceConfig::OaOrg { org_base_url, .. } => {
            ("oa_org", org_base_url.clone())
        }
    };
    let server = ServerIdentity {
        protocol_version: config.protocol_version(),
        chain_id: config.chain_id(),
        contract_address: config.contract_address(),
        current_root: processor.current_root(),
        provider: "native_leases",
        upstream_kind: Some(upstream_kind.to_string()),
        upstream_api_base: Some(upstream_api_base),
        auth_scheme: "state-anchor",
        policy_enabled: false,
        request_charge_cap: config.request_charge_cap(),
        request_charge_cap_usd: crate::pricing::micro_usd_to_usd(config.request_charge_cap()),
        credits_per_usd: 1_000_000.0,
        billing_asset: "usdc",
        billing_unit: "micro_usdc",
        asset: BillingAsset {
            symbol: config.profile.asset.symbol.clone(),
            decimals: config.profile.asset.decimals,
            mint: config.profile.asset.mint.clone(),
        },
        state_signing_key: processor.state_signing_key(),
        clearance_signing_key: processor.clearance_signing_key(),
    };
    let (totals, started_ms, recent_count) = match processor.dashboard() {
        Some(hub) => (hub.totals(), hub.started_ms, hub.recent().len()),
        None => (DashboardTotals::default(), 0, 0),
    };
    Json(DashboardSummary {
        server,
        totals,
        started_ms,
        recent_count,
    })
}

/// GET /v1/dashboard/recent -- the recent request feed (newest last).
async fn handle_dashboard_recent(State(processor): State<AppState>) -> Json<Vec<DashboardEvent>> {
    let events = processor
        .dashboard()
        .map(|hub| hub.recent())
        .unwrap_or_default();
    Json(events)
}

/// GET /v1/dashboard/events -- Server-Sent-Events stream of live requests.
async fn handle_dashboard_events(
    State(processor): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = processor.dashboard().map(|hub| hub.subscribe());
    let stream = futures_util::stream::unfold(rx, |state| async move {
        let mut rx = state?;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    let sse = Event::default().event("request").data(data);
                    return Some((Ok(sse), Some(rx)));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Convert a ServerError into an HTTP error response.
fn error_to_response(
    err: &ServerError,
    client_request_id: &str,
    processor: &RequestProcessor,
) -> ErrorHttpResponse {
    let latest_root = if matches!(err, ServerError::StaleRoot { .. }) {
        Some(processor.current_root())
    } else {
        None
    };
    ErrorHttpResponse(Box::new(build_error_response(
        err,
        client_request_id,
        latest_root,
    )))
}

fn build_error_response(
    err: &ServerError,
    client_request_id: &str,
    latest_root: Option<Felt252>,
) -> (StatusCode, HeaderMap, Json<ErrorResponse>) {
    let status_code = match err {
        ServerError::InvalidProof(_)
        | ServerError::InvalidRequest(_)
        | ServerError::OaKeyPolicyRejected
        | ServerError::ProtocolMismatch(_) => StatusCode::BAD_REQUEST,
        ServerError::StaleRoot { .. } => StatusCode::CONFLICT,
        ServerError::Replay | ServerError::NullifierUsed => StatusCode::CONFLICT,
        ServerError::LeasePending | ServerError::LeaseSettlementPending { .. } => {
            StatusCode::CONFLICT
        }
        ServerError::NoteExpired => StatusCode::GONE,
        ServerError::CapacityExhausted => StatusCode::SERVICE_UNAVAILABLE,
        ServerError::Internal(_) | ServerError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        ServerError::OaRateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
    };

    let retry_after_seconds = match err {
        ServerError::OaRateLimited {
            retry_after_seconds,
            ..
        }
        | ServerError::LeaseSettlementPending {
            retry_after_seconds,
        } => Some(*retry_after_seconds),
        _ => None,
    };
    let mut headers = HeaderMap::new();
    if let Some(retry_after_seconds) = retry_after_seconds {
        let retry_after = HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a decimal u64 is always a valid Retry-After header");
        headers.insert(RETRY_AFTER, retry_after);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let body = ErrorResponse {
        status: "error".to_string(),
        client_request_id: client_request_id.to_string(),
        error_code: err.error_code().to_string(),
        error_message: err.to_string(),
        retriable: err.is_retriable(),
        latest_root,
        server_time_ms: Some(now_ms),
        retry_after_seconds,
    };

    (status_code, headers, Json(body))
}

fn spawn_openrouter_lease_settler(processor: Arc<RequestProcessor>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            processor.settle_due_openrouter_leases().await;
        }
    });
}

fn spawn_root_poller(processor: Arc<RequestProcessor>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if let Err(err) = processor
                .refresh_ledger_state(LedgerCommitment::Finalized)
                .await
            {
                tracing::warn!("failed to refresh root through credit ledger: {}", err);
            }
        }
    });
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    #[tokio::test]
    async fn startup_rejects_an_invalid_identity_before_opening_database() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("must-not-exist.db");
        let mut config = crate::test_support::config(crate::test_support::oa_source());
        config.db_path = db_path.to_string_lossy().into_owned();
        config.identity.vault_state = [9; 32];
        let error = run_server(config).await.unwrap_err();
        assert!(error.to_string().contains("not the vault PDA"), "{error}");
        assert!(!db_path.exists());
    }

    #[tokio::test]
    async fn compact_http_errors_preserve_status_headers_and_json() {
        for error in [
            ServerError::OaRateLimited {
                reason: "oa_hourly_issuance_budget".to_string(),
                retry_after_seconds: 37,
            },
            ServerError::LeaseSettlementPending {
                retry_after_seconds: 15,
            },
            ServerError::InvalidRequest("invalid request".to_string()),
        ] {
            let (status, headers, Json(body)) =
                build_error_response(&error, "lease-request-123", None);
            let expected_headers = headers.clone();
            let expected_body = serde_json::to_value(&body).unwrap();
            let response =
                ErrorHttpResponse(Box::new((status, headers, Json(body)))).into_response();

            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(RETRY_AFTER),
                expected_headers.get(RETRY_AFTER)
            );
            assert_eq!(response.headers()["content-type"], "application/json");
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let actual_body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(actual_body, expected_body);
        }
    }

    /// The USDC wallet routes reach the ledger boundary (the stub ledger
    /// supports none of them) and reject unknown body fields.
    #[tokio::test]
    async fn usdc_wallet_routes_reach_the_ledger() {
        use tower::ServiceExt;
        let mut config = crate::test_support::config(crate::test_support::oa_source());
        config.proof_setup_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/setup/v2")
            .to_string_lossy()
            .into_owned();
        let signer = Arc::new(crate::signer::ServerSigner::new(
            &config.state_seed,
            &config.clear_seed,
        ));
        let ledger = crate::test_support::StubLedger::unavailable(&config);
        let store = Arc::new(crate::nullifier_store::NullifierStore::in_memory().unwrap());
        let processor =
            RequestProcessor::try_new(config, store, signer, Felt252::ZERO, ledger).unwrap();
        let router = create_router(Arc::new(processor));
        let account = bs58::encode([4u8; 32]).into_string();
        let post = |uri: &str, body: serde_json::Value| {
            axum::http::Request::post(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        };
        for (uri, body) in [
            (
                "/v2/ledger/escapes/release/prepare",
                serde_json::json!({"payer": account, "note_id": 3}),
            ),
            (
                "/v2/ledger/escapes/rent-refund/prepare",
                serde_json::json!({"payer": account, "note_id": 3}),
            ),
            (
                "/v2/ledger/usdc-accounts/prepare",
                serde_json::json!({"payer": account, "owner": account}),
            ),
        ] {
            let response = router.clone().oneshot(post(uri, body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["error_code"], "invalid_request", "{uri}");
            assert!(
                body["error_message"]
                    .as_str()
                    .unwrap()
                    .contains("does not support wallet operation"),
                "{uri}: {body}"
            );
        }
        let unknown_field = router
            .oneshot(post(
                "/v2/ledger/usdc-accounts/prepare",
                serde_json::json!({"payer": account, "owner": account, "mint": account}),
            ))
            .await
            .unwrap();
        assert!(unknown_field.status().is_client_error());
    }

    #[test]
    fn oa_rate_limit_maps_to_retriable_429_with_retry_metadata() {
        let error = ServerError::OaRateLimited {
            reason: "oa_hourly_issuance_budget".to_string(),
            retry_after_seconds: 37,
        };

        let (status, headers, Json(response)) =
            build_error_response(&error, "lease-request-123", None);

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "37");
        assert_eq!(response.error_code, "oa_hourly_issuance_budget");
        assert!(response.retriable);
        assert_eq!(response.retry_after_seconds, Some(37));

        let serialized = serde_json::to_value(response).unwrap();
        assert_eq!(serialized["retry_after_seconds"], 37);
        assert_eq!(serialized["error_code"], "oa_hourly_issuance_budget");
    }

    #[test]
    fn lease_settlement_pending_maps_to_retriable_409_with_retry_metadata() {
        let error = ServerError::LeaseSettlementPending {
            retry_after_seconds: 15,
        };

        let (status, headers, Json(response)) =
            build_error_response(&error, "lease-request-123", None);

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "15");
        assert_eq!(response.error_code, "lease_settlement_pending");
        assert!(response.retriable);
        assert_eq!(response.retry_after_seconds, Some(15));
    }
}
