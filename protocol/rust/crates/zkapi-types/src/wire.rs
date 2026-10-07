//! Wire format types for HTTP APIs.
//!
//! Field elements use 0x-prefixed lowercase hex strings; curve points have
//! x and y fields. Proofs contain base64-encoded canonical Groth16 bytes.
//! Integer fields retain the existing v2 serde representation.

use serde::{Deserialize, Serialize};

use crate::Felt252;

/// Supported proof backend on the wire.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackendWire {
    Groth16Bn254,
}

/// Compact Groth16 proof artifact. Public inputs are carried in the enclosing
/// request and are verified directly; there is no separately trusted output
/// hash or witness envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16ProofWire {
    pub backend: ProofBackendWire,
    /// Arkworks canonical compressed proof bytes, base64 encoded.
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequestV2 {
    pub client_request_id: String,
    pub payload: String,
    pub payload_hash: Felt252,
    pub public_inputs: crate::RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
}

/// Prompt-free payload authorized by a client when opening a short-lived
/// OpenRouter lease. The server rejects extra fields so this protocol message
/// cannot accidentally carry an LLM prompt or response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenRouterLeaseAuthorization {
    pub mode: String,
    pub version: u16,
}

impl Default for OpenRouterLeaseAuthorization {
    fn default() -> Self {
        Self {
            mode: "openrouter_ephemeral_lease".to_string(),
            version: 1,
        }
    }
}

/// A freshly-issued, short-lived OpenRouter key. The plaintext key is only
/// present in this live response; server recovery responses never contain it.
#[derive(Clone, Serialize, Deserialize)]
pub struct OpenRouterLeaseResponse {
    pub status: String,
    pub client_request_id: String,
    pub api_key: String,
    /// OpenRouter inference base, normally `https://openrouter.ai/api/v1`.
    pub openrouter_api_base: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub valid_for_seconds: u64,
    /// The server will not finalize usage before this UNIX timestamp.
    pub settle_after: u64,
    pub spending_limit_usd: f64,
}

/// Non-secret lease metadata, safe to return during crash recovery. It never
/// contains the plaintext OpenRouter runtime key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRouterLeaseStatusResponse {
    pub status: String,
    pub client_request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_usd: Option<f64>,
    /// Live usage of a still-active key, as the issuer reports it now. Advisory (clients use it to settle early);
    /// the settled `usage_usd` and charge always come from retirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_usage_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge_applied: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponseV2 {
    pub status: String,
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub response_code: u16,
    pub response_payload: String,
    pub response_hash: Felt252,
    pub charge_applied: u128,
    pub next_commitment: CurvePointWire,
    pub next_anchor: Felt252,
    pub blind_delta_srv: Felt252,
    pub next_state_signature: crate::SchnorrSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_evidence_hash: Option<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceResponseV2 {
    pub status: String,
    pub withdrawal_nullifier: Felt252,
    pub signature: crate::SchnorrSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResponseV2 {
    pub status: String,
    pub nullifier_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_response: Option<RequestResponseV2>,
}

/// A curve point serialized as {x, y} hex fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurvePointWire {
    pub x: Felt252,
    pub y: Felt252,
}

/// Error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub client_request_id: String,
    pub error_code: String,
    pub error_message: String,
    pub retriable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_root: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_time_ms: Option<u64>,
    /// Present for retriable throttling errors and mirrored in the HTTP
    /// `Retry-After` header when the transport supports response headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

/// Clearance request for mutual close.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceRequest {
    pub withdrawal_nullifier: Felt252,
}

#[cfg(test)]
mod tests {
    use super::ErrorResponse;

    #[test]
    fn legacy_error_response_without_retry_delay_remains_compatible() {
        let response: ErrorResponse = serde_json::from_str(
            r#"{
                "status":"error",
                "client_request_id":"request-1",
                "error_code":"internal_error",
                "error_message":"temporary failure",
                "retriable":true
            }"#,
        )
        .unwrap();

        assert_eq!(response.retry_after_seconds, None);
        let serialized = serde_json::to_value(response).unwrap();
        assert!(serialized.get("retry_after_seconds").is_none());
    }
}
