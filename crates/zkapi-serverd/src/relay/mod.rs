//! Optional CCTP relay (`/v2/relay/*`): pays SOL fees and rent for
//! emergency-key users and is paid back in USDC. Enabled by
//! `ZKAPI_RELAYER_KEY`; see `docs/SOLANA_SERVER.md`.

pub mod config;
pub mod fees;
mod iris;
pub mod service;
pub mod store;
mod ticket;
pub mod tx;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};

pub use config::RelayConfig;
pub use service::{Relay, RelayError};

type RelayState = Option<Arc<Relay>>;

fn enabled(state: &RelayState) -> Result<&Arc<Relay>, RelayError> {
    state.as_ref().ok_or_else(RelayError::disabled)
}

/// Background maintenance interval (settlements, cancels, reclaims).
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

pub fn spawn_maintenance(relay: Arc<Relay>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(MAINTENANCE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            relay.maintain().await;
        }
    });
}

/// `/v2/relay*` routes; each answers `404 relay_disabled` without a relay.
pub fn router<S>(relay: RelayState) -> Router<S> {
    Router::new()
        .route("/v2/relay", get(info))
        .route("/v2/relay/deposits/prepare", post(prepare_deposit))
        .route("/v2/relay/receives/prepare", post(prepare_receive))
        .route("/v2/relay/exits/prepare", post(prepare_exit))
        .route("/v2/relay/escapes/finalize", post(finalize_escape))
        .route("/v2/relay/burns/prepare", post(prepare_burn))
        .route("/v2/relay/sweeps/prepare", post(prepare_sweep))
        .route("/v2/relay/submit", post(submit))
        .with_state(relay)
}

/// Parse a JSON body after the relay check, so a disabled relay always
/// answers `relay_disabled` and a malformed body is an `invalid_request`.
fn body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, RelayError> {
    serde_json::from_slice(bytes)
        .map_err(|error| RelayError::invalid(format!("invalid request body: {error}")))
}

async fn info(State(relay): State<RelayState>) -> Result<Json<service::RelayInfo>, RelayError> {
    Ok(Json(enabled(&relay)?.info()))
}

async fn prepare_deposit(
    State(relay): State<RelayState>,
    bytes: Bytes,
) -> Result<Json<service::DepositResponse>, RelayError> {
    let relay = enabled(&relay)?;
    relay.prepare_deposit(body(&bytes)?).await.map(Json)
}

async fn prepare_receive(
    State(relay): State<RelayState>,
    bytes: Bytes,
) -> Result<Json<service::ReceiveResponse>, RelayError> {
    let relay = enabled(&relay)?;
    relay.prepare_receive(body(&bytes)?).await.map(Json)
}

async fn prepare_exit(
    State(relay): State<RelayState>,
    bytes: Bytes,
) -> Result<Json<service::ExitResponse>, RelayError> {
    let relay = enabled(&relay)?;
    relay.prepare_exit(body(&bytes)?).await.map(Json)
}

async fn finalize_escape(
    State(relay): State<RelayState>,
    bytes: Bytes,
) -> Result<Json<service::FinalizeResponse>, RelayError> {
    let relay = enabled(&relay)?;
    relay.finalize_escape(body(&bytes)?).await.map(Json)
}

async fn prepare_burn(
    State(relay): State<RelayState>,
    bytes: Bytes,
) -> Result<Json<service::BurnResponse>, RelayError> {
    let relay = enabled(&relay)?;
    relay.prepare_burn(body(&bytes)?).await.map(Json)
}

async fn prepare_sweep(
    State(relay): State<RelayState>,
    bytes: Bytes,
) -> Result<Json<service::SweepResponse>, RelayError> {
    let relay = enabled(&relay)?;
    relay.prepare_sweep(body(&bytes)?).await.map(Json)
}

async fn submit(
    State(relay): State<RelayState>,
    bytes: Bytes,
) -> Result<Json<service::SubmitResponse>, RelayError> {
    let relay = enabled(&relay)?;
    relay.submit(body(&bytes)?).await.map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    /// Without `ZKAPI_RELAYER_KEY` every relay route answers 404
    /// `relay_disabled` in the relay error envelope, whatever the body.
    #[tokio::test]
    async fn disabled_relay_answers_relay_disabled() {
        let router: Router = router(None);
        for (method, uri) in [
            ("GET", "/v2/relay"),
            ("POST", "/v2/relay/deposits/prepare"),
            ("POST", "/v2/relay/receives/prepare"),
            ("POST", "/v2/relay/exits/prepare"),
            ("POST", "/v2/relay/escapes/finalize"),
            ("POST", "/v2/relay/burns/prepare"),
            ("POST", "/v2/relay/sweeps/prepare"),
            ("POST", "/v2/relay/submit"),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{not json"))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::NOT_FOUND,
                "{uri}"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["error"]["code"], "relay_disabled", "{uri}");
            assert!(body["error"]["message"].is_string());
        }
    }
}
