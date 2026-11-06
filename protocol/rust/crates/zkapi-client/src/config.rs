//! Client configuration.

use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

/// Proof backend used by the wallet when building request/withdrawal proofs.
#[derive(Debug, Clone)]
pub enum ClientProofMode {
    /// Generate compact Groth16 proofs using the circuit-specific setup files.
    Groth16 { setup_dir: String },
}

/// Configuration for the client SDK, matching the deployed vault parameters.
pub struct ClientConfig {
    /// Protocol version (must be 2).
    pub protocol_version: u16,
    /// Chain ID of the target network (`solana_chain_id(genesis_hash)`).
    pub chain_id: u64,
    /// Deployment binding of the vault
    /// (`solana_deployment_binding(program_id, vault_state, genesis_hash)`).
    pub contract_address: Felt252,
    /// Maximum charge the server may apply per ordinary request.
    pub request_charge_cap: u128,
    /// Maximum charge the server may apply under policy rejection.
    pub policy_charge_cap: u128,
    /// Whether policy-based charge enforcement is active on this deployment.
    pub policy_enabled: bool,
    /// Base URL of the zkAPI server (e.g. "http://localhost:8080").
    pub server_url: String,
    /// Directory for persisting wallet state and journals.
    pub state_dir: String,
    /// Proof backend used for runtime proof generation.
    pub proof_mode: ClientProofMode,
    /// Server signing keys pinned by the deployed vault.
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
    /// The deployment's settlement window W (seconds): how long a request
    /// may take to settle. Exit timing (C4, E3) depends on it.
    pub settlement_window_seconds: u64,
    /// E3's `unsettled_request_escape_after_seconds`; `None` is the default.
    pub unsettled_request_escape_after_seconds: Option<u64>,
}

impl ClientConfig {
    /// The solvency bound every request proof commits to: the policy cap when
    /// policy enforcement is on, the request cap otherwise.
    pub fn solvency_bound(&self) -> u128 {
        if self.policy_enabled {
            self.policy_charge_cap
        } else {
            self.request_charge_cap
        }
    }
}
