use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use zkapi_serverd::{
    config::{OpenRouterLeaseSourceConfig, ResolvedIdentity, ServerConfig, SharedProfile},
    nullifier_store::NullifierStore,
    processor::RequestProcessor,
    routes::create_router,
    signer::ServerSigner,
    sol_billing::PythBillingOracle,
    testnet_auth::{TestnetPassword, TESTNET_PASSWORD_HEADER},
};
use zkapi_types::Felt252;

const PASSWORD: &str = "testnet-integration-password";

fn config(network: &str, password: Option<TestnetPassword>) -> ServerConfig {
    let vault_authority = [5; 32];
    let identity = ResolvedIdentity {
        genesis_hash: [3; 32],
        vault_authority,
        vault_state: dagon_zkapi_profile::vault_state_address(
            &SharedProfile::embedded().program_id(),
            &vault_authority,
        ),
        treasury: [7; 32],
        pyth_price_account: [8; 32],
    };
    ServerConfig {
        testnet_password: password,
        proof_setup_dir: format!("{}/../../protocol/setup/v2", env!("CARGO_MANIFEST_DIR")),
        ..ServerConfig::new(
            network.into(),
            identity,
            "http://127.0.0.1:9".into(),
            OpenRouterLeaseSourceConfig::OpenRouter {
                management_key: "test-management-key".into(),
                api_base: "http://127.0.0.1:9".into(),
            },
            Felt252::ONE,
            Felt252::from_u64(2),
        )
    }
}

fn router(protected: bool) -> axum::Router {
    let config = config(
        if protected { "devnet" } else { "mainnet-beta" },
        protected.then(|| TestnetPassword::new(PASSWORD).unwrap()),
    );
    // Unreachable RPC: routing and the gate need no chain reads.
    let ledger = Arc::new(
        dagon_zkapi_solana_ledger::SolanaCreditLedger::new(config.ledger_config()).unwrap(),
    );
    let billing = Arc::new(PythBillingOracle::new(&config).unwrap());
    let signer = Arc::new(ServerSigner::new(&config.state_seed, &config.clear_seed));
    create_router(Arc::new(
        RequestProcessor::try_new(
            config,
            Arc::new(NullifierStore::in_memory().unwrap()),
            signer,
            Felt252::ZERO,
            ledger,
            billing,
        )
        .unwrap(),
    ))
}

#[tokio::test]
async fn all_service_routes_reject_missing_or_wrong_password_before_body_parsing() {
    let app = router(true);
    for (method, path) in [
        ("GET", "/v2/auth"),
        ("POST", "/v2/requests"),
        ("GET", "/v2/billing/quote"),
        ("POST", "/v2/openrouter/leases"),
        ("GET", "/v2/openrouter/leases/example"),
        ("POST", "/v2/openrouter/leases/example"),
        ("POST", "/v2/openrouter/leases/example/expire"),
        ("POST", "/v2/withdraw/clearance"),
        ("GET", "/v2/requests/example"),
        ("GET", "/v2/nullifiers/invalid"),
        ("GET", "/v1/dashboard/summary"),
        ("GET", "/v1/dashboard/recent"),
        ("GET", "/v1/dashboard/events"),
        ("POST", "/health"),
        ("GET", "/unknown-future-service"),
    ] {
        for candidate in [None, Some("incorrect-test-password")] {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json");
            if let Some(candidate) = candidate {
                request = request.header(TESTNET_PASSWORD_HEADER, candidate);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from("not json")).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert_eq!(body["error_code"], "testnet_password_required");
            assert_eq!(body["retriable"], false);
            assert!(!body.to_string().contains("incorrect-test-password"));
        }
    }
}

#[tokio::test]
async fn authentication_is_exact_and_allows_authenticated_handlers() {
    let app = router(true);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/auth")
                .header(TESTNET_PASSWORD_HEADER, PASSWORD)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body, serde_json::json!({"authenticated": true}));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/auth")
                .header(TESTNET_PASSWORD_HEADER, PASSWORD)
                .header(TESTNET_PASSWORD_HEADER, "duplicate")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/openrouter/leases")
                .header(TESTNET_PASSWORD_HEADER, PASSWORD)
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_and_attestation_stay_public_with_no_store_and_browser_preflight_works() {
    let app = router(true);
    for path in ["/", "/health", "/v1/attestation"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("origin", "https://client.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        if path != "/v1/attestation" {
            assert_eq!(body["testnet_password_required"], true);
            assert_eq!(body["chain_id"], config("devnet", None).chain_id());
        }
        assert!(!body.to_string().contains(PASSWORD));
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v2/openrouter/leases")
                .header("origin", "https://client.example")
                .header("access-control-request-method", "POST")
                .header(
                    "access-control-request-headers",
                    "content-type,x-zkapi-testnet-password",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    assert!(response.headers()["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .contains(TESTNET_PASSWORD_HEADER));
    assert!(!response
        .headers()
        .contains_key("access-control-allow-credentials"));
}

#[tokio::test]
async fn mainnet_is_ungated_and_rejects_password_configuration() {
    let app = router(false);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["testnet_password_required"], false);
    assert_eq!(body["chain_id"], config("mainnet-beta", None).chain_id());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/openrouter/leases")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = config(
        "mainnet-beta",
        Some(TestnetPassword::new(PASSWORD).unwrap()),
    )
    .validate()
    .unwrap_err()
    .to_string();
    assert!(error.contains("ZKAPI_TESTNET_PASSWORD"), "{error}");
}
