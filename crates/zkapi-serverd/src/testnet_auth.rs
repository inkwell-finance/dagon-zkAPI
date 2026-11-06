//! Optional shared access gate for a testnet service, separate from note
//! proofs. Startup refuses it on mainnet-beta.

use axum::extract::{Request, State};
use axum::http::{header::CACHE_CONTROL, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

pub const TESTNET_PASSWORD_HEADER: &str = "x-zkapi-testnet-password";

/// Store only a fixed-size digest and never expose it through debug output.
#[derive(Clone)]
pub struct TestnetPassword([u8; 32]);

impl std::fmt::Debug for TestnetPassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TestnetPassword([configured])")
    }
}

impl TestnetPassword {
    pub fn new(password: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (16..=1024).contains(&password.len())
                && password.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
            "ZKAPI_TESTNET_PASSWORD must contain 16 to 1024 visible ASCII characters without whitespace"
        );
        Ok(Self(Sha3_256::digest(password.as_bytes()).into()))
    }

    /// No CLI flag: keep the shared credential out of process arguments.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        match std::env::var("ZKAPI_TESTNET_PASSWORD") {
            Ok(value) => Self::new(&value).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("ZKAPI_TESTNET_PASSWORD must contain visible ASCII characters")
            }
        }
    }

    fn matches(&self, candidate: &[u8]) -> bool {
        let digest: [u8; 32] = Sha3_256::digest(candidate).into();
        self.0.ct_eq(&digest).into()
    }
}

/// Runs before extraction, proof processing, providers, and recovery reads.
pub(crate) async fn require_testnet_password(
    State(password): State<Option<TestnetPassword>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Remove the credential before any handler can forward or record headers.
    // Duplicate values are rejected rather than depending on proxy selection.
    let duplicate = request
        .headers()
        .get_all(TESTNET_PASSWORD_HEADER)
        .iter()
        .count()
        > 1;
    let candidate = request.headers_mut().remove(TESTNET_PASSWORD_HEADER);
    let public = request.method() == Method::OPTIONS
        || ((request.method() == Method::GET || request.method() == Method::HEAD)
            && matches!(request.uri().path(), "/" | "/health" | "/v1/attestation"));
    if let Some(password) = password.as_ref() {
        if !public
            && (duplicate
                || !candidate.as_ref().is_some_and(|value| {
                    value.as_bytes().len() <= 1024 && password.matches(value.as_bytes())
                }))
        {
            return (
                StatusCode::UNAUTHORIZED,
                [(CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({
                    "error_code": "testnet_password_required",
                    "error": "testnet password required or invalid",
                    "retriable": false,
                })),
            )
                .into_response();
        }
    }
    let mut response = next.run(request).await;
    if password.is_some() || public {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

pub(crate) async fn handle_auth_check() -> impl IntoResponse {
    (
        [(CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "authenticated": true })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn credential_is_removed_before_handlers_receive_the_request() {
        let app = Router::new()
            .route(
                "/v2/auth",
                get(|request: Request| async move {
                    assert!(!request.headers().contains_key(TESTNET_PASSWORD_HEADER));
                    StatusCode::NO_CONTENT
                }),
            )
            .layer(middleware::from_fn_with_state(
                Some(TestnetPassword::new("a-test-only-password-123").unwrap()),
                require_testnet_password,
            ));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v2/auth")
                    .header(TESTNET_PASSWORD_HEADER, "a-test-only-password-123")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn secrets_are_validated_compared_exactly_and_redacted() {
        let password = TestnetPassword::new("a-test-only-password-123").unwrap();
        assert!(password.matches(b"a-test-only-password-123"));
        assert!(!password.matches(b"a-test-only-password-124"));
        assert!(!password.matches(b"a-test-only-password-123,other"));
        assert!(!format!("{password:?}").contains("a-test-only-password"));
        for invalid in [
            "",
            "short",
            "a-test-only-password\n",
            "white space password",
            "non-ascii-password-é",
        ] {
            assert!(TestnetPassword::new(invalid).is_err());
        }
        assert!(TestnetPassword::new(&"a".repeat(1025)).is_err());
    }
}
