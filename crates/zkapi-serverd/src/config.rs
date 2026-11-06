//! Server configuration.

pub use dagon_zkapi_solana_ledger::SolanaLedgerConfig;
use zkapi_types::Felt252;

/// Source used to provision prompt-private, short-lived OpenRouter keys.
#[derive(Clone)]
pub enum OpenRouterLeaseSourceConfig {
    /// Mint child keys directly with an OpenRouter management key.
    OpenRouter {
        management_key: String,
        /// OpenRouter API base without `/v1`.
        api_base: String,
    },
    /// Ask an OA org to relay key creation to a verifier-enrolled station.
    OaOrg {
        org_base_url: String,
        /// Dedicated zkAPI service credential configured by the org.
        shared_secret: String,
    },
}

impl OpenRouterLeaseSourceConfig {
    pub fn label(&self) -> &'static str {
        match self {
            Self::OpenRouter { .. } => "openrouter",
            Self::OaOrg { .. } => "oa_org",
        }
    }
}

impl std::fmt::Debug for OpenRouterLeaseSourceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenRouter { api_base, .. } => formatter
                .debug_struct("OpenRouter")
                .field("management_key", &"[configured]")
                .field("api_base", api_base)
                .finish(),
            Self::OaOrg { org_base_url, .. } => formatter
                .debug_struct("OaOrg")
                .field("org_base_url", org_base_url)
                .field("shared_secret", &"[configured]")
                .finish(),
        }
    }
}

/// Prompt-private lease configuration for native-asset billing.
#[derive(Debug, Clone)]
pub struct OpenRouterLeaseConfig {
    pub source: OpenRouterLeaseSourceConfig,
    /// Runtime-key validity window.
    pub ttl_seconds: u64,
    /// Delay after expiry (and after disabling directly managed keys) before
    /// reading aggregate usage, allowing in-flight calls and accounting to drain.
    pub settlement_grace_seconds: u64,
    /// Background settlement scan interval.
    pub settlement_poll_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum LedgerBackend {
    #[default]
    Solana,
    Evm,
}

#[derive(Debug, Clone)]
pub struct SolanaServerConfig {
    pub ledger: dagon_zkapi_solana_ledger::SolanaLedgerConfig,
    pub billing: crate::sol_billing::PythBillingConfig,
}

/// Configuration for the zkAPI server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub backend: LedgerBackend,
    pub solana: Option<SolanaServerConfig>,
    /// Protocol version (must be 2).
    pub protocol_version: u16,
    /// Chain ID this server is bound to.
    pub chain_id: u64,
    /// Optional shared Sepolia service gate; contains only a redacted digest.
    pub testnet_password: Option<crate::testnet_auth::TestnetPassword>,
    /// On-chain contract address.
    pub contract_address: Felt252,
    /// Minimum proof-bound lease budget: lamports on Solana, gwei on EVM.
    pub request_charge_cap: u128,
    /// HTTP listen address (e.g. "0.0.0.0:3000").
    pub listen_addr: String,
    /// Path to the SQLite database file.
    pub db_path: String,
    /// Seed for the proof-friendly state-signing key.
    pub state_seed: Felt252,
    /// Seed for the proof-friendly clearance-signing key.
    pub clear_seed: Felt252,
    /// Initial Merkle root the server should accept until the indexer updates it.
    pub initial_root: Felt252,
    /// Optional base URL for an indexer that serves the latest tree root.
    pub indexer_url: Option<String>,
    /// Poll interval for indexer root refresh.
    pub root_poll_interval_ms: u64,
    /// Required prompt-private OpenRouter lease configuration.
    pub openrouter_leases: Option<OpenRouterLeaseConfig>,
    /// Required native ETH oracle configuration, checked before server startup.
    pub native_billing: Option<crate::native_billing::NativeBillingConfig>,
    /// Directory containing the v2 Groth16 proving/verifying key files.
    pub proof_setup_dir: String,
    /// The vault's escape challenge period. A settled request whose
    /// nullifier an exit consumed waits this long plus
    /// [`EXIT_DEFERRAL_SLACK_SECONDS`] for a defeat before it is terminally
    /// `exited_unsigned` (O7).
    pub challenge_period_seconds: u64,
    /// How long before an escape's deadline the challenger raises with the
    /// request's solvency bound when its charge is still unsettled.
    pub raise_lead_seconds: u64,
    /// Drill-only misbehaviour; refused in release builds.
    #[cfg(any(test, feature = "adversary"))]
    pub adversary: Option<crate::adversary::AdversaryMode>,
}

/// Grace after the challenge period before a deferred signature is given up.
pub const EXIT_DEFERRAL_SLACK_SECONDS: u64 = 3_600;
/// Upper bound on reading a provider's final usage after the settlement grace.
pub const USAGE_READ_LATENCY_SECONDS: u64 = 600;
/// Slack for clock skew, block inclusion and challenger polling.
pub const TIMING_MARGIN_SECONDS: u64 = 1_800;

/// Every request accepted before an escape must settle before the
/// challenger's raise decision: `lease TTL + settlement grace (twice for a
/// directly managed OpenRouter key, which drains again after it is disabled)
/// + two settlement polls + usage-read latency + raise lead + margin ≤
/// challenge period`.
pub fn check_challenge_timing(
    lease: &OpenRouterLeaseConfig,
    raise_lead_seconds: u64,
    challenge_period_seconds: u64,
) -> anyhow::Result<()> {
    let drains = match lease.source {
        OpenRouterLeaseSourceConfig::OpenRouter { .. } => 2,
        OpenRouterLeaseSourceConfig::OaOrg { .. } => 1,
    };
    let grace = lease.settlement_grace_seconds.saturating_mul(drains);
    let polls = lease.settlement_poll_seconds.max(1).saturating_mul(2);
    let required = lease
        .ttl_seconds
        .saturating_add(grace)
        .saturating_add(polls)
        .saturating_add(USAGE_READ_LATENCY_SECONDS)
        .saturating_add(raise_lead_seconds)
        .saturating_add(TIMING_MARGIN_SECONDS);
    anyhow::ensure!(
        raise_lead_seconds > 0 && required <= challenge_period_seconds,
        "challenge timing is unsafe: lease TTL {}s + settlement grace {grace}s + settlement \
         polls {polls}s + usage latency {USAGE_READ_LATENCY_SECONDS}s + raise lead \
         {raise_lead_seconds}s + margin {TIMING_MARGIN_SECONDS}s = {required}s exceeds the \
         challenge period {challenge_period_seconds}s",
        lease.ttl_seconds
    );
    Ok(())
}

/// The timing check and the O7 deferral window are only as good as the
/// configured challenge period: it must be the vault's own.
pub fn check_vault_challenge_period(configured: u64, vault: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        configured == vault,
        "--challenge-period-seconds {configured}s does not match the vault's challenge period \
         {vault}s"
    );
    Ok(())
}

impl ServerConfig {
    pub fn validate_testnet_auth(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.testnet_password.is_none()
                || self.chain_id == crate::testnet_auth::SEPOLIA_CHAIN_ID,
            "ZKAPI_TESTNET_PASSWORD is only supported on Sepolia (chain ID 11155111)"
        );
        Ok(())
    }

    /// Reject incomplete/mixed configurations before startup opens any state.
    pub fn validate_native_mode(&self) -> anyhow::Result<()> {
        self.validate_testnet_auth()?;
        anyhow::ensure!(self.protocol_version == 2, "protocol version must be 2");
        match self.backend {
            LedgerBackend::Evm => {
                anyhow::ensure!(
                    self.solana.is_none(),
                    "EVM mode rejects Solana configuration"
                );
                anyhow::ensure!(
                    self.native_billing.is_some(),
                    "native ETH billing configuration is required"
                );
            }
            LedgerBackend::Solana => {
                anyhow::ensure!(
                    self.native_billing.is_none(),
                    "Solana mode rejects ETH billing configuration"
                );
                anyhow::ensure!(
                    self.testnet_password.is_none(),
                    "Solana does not support the Sepolia service gate"
                );
                let solana = self.solana.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Solana ledger and Pyth configuration is required")
                })?;
                solana.billing.validate()?;
                let ledger = &solana.ledger;
                anyhow::ensure!(
                    self.chain_id == zkapi_types::solana_chain_id(&ledger.genesis_hash)
                        && self.contract_address
                            == zkapi_types::solana_deployment_binding(
                                &ledger.program_id,
                                &ledger.vault_state,
                                &ledger.genesis_hash
                            ),
                    "Solana protocol identity does not match the derived deployment"
                );
                anyhow::ensure!(
                    self.initial_root == Felt252::ZERO,
                    "Solana rejects an initial-root override"
                );
                anyhow::ensure!(
                    self.indexer_url == ledger.indexer_url,
                    "Solana indexer configuration is ambiguous"
                );
                dagon_zkapi_solana_ledger::SolanaCreditLedger::new(ledger.clone())?;
            }
        }
        let lease = self
            .openrouter_leases
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native billing requires prompt-private leases"))?;
        anyhow::ensure!(
            lease.ttl_seconds > 0,
            "OpenRouter lease TTL must be positive"
        );
        match &lease.source {
            OpenRouterLeaseSourceConfig::OpenRouter { management_key, .. } => anyhow::ensure!(
                !management_key.is_empty(),
                "OpenRouter management key cannot be empty"
            ),
            OpenRouterLeaseSourceConfig::OaOrg {
                org_base_url,
                shared_secret,
            } => {
                anyhow::ensure!(
                    !org_base_url.is_empty() && !shared_secret.is_empty(),
                    "OA org URL and shared secret are required"
                );
                anyhow::ensure!(
                    lease.ttl_seconds.is_multiple_of(60),
                    "OA org lease TTL must be a whole number of minutes"
                );
            }
        }
        anyhow::ensure!(
            self.request_charge_cap > 0
                && self.request_charge_cap <= crate::native_billing::MAX_SAFE_UNITS,
            "native request cap must fit browser-safe credit units"
        );
        anyhow::ensure!(
            self.root_poll_interval_ms > 0,
            "root poll interval must be positive"
        );
        check_challenge_timing(lease, self.raise_lead_seconds, self.challenge_period_seconds)?;
        #[cfg(any(test, feature = "adversary"))]
        crate::adversary::ensure_allowed(self.adversary)?;
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            backend: LedgerBackend::Solana,
            solana: None,
            protocol_version: 2,
            chain_id: 1,
            testnet_password: None,
            contract_address: Felt252::ZERO,
            request_charge_cap: 1_000_000,
            listen_addr: "0.0.0.0:3000".to_string(),
            db_path: "zkapi_server.db".to_string(),
            state_seed: Felt252::from_u64(1),
            clear_seed: Felt252::from_u64(2),
            initial_root: Felt252::ZERO,
            indexer_url: None,
            root_poll_interval_ms: 1_000,
            openrouter_leases: None,
            native_billing: None,
            proof_setup_dir: "protocol/setup/v2".to_string(),
            challenge_period_seconds: 86_400,
            raise_lead_seconds: 3_600,
            #[cfg(any(test, feature = "adversary"))]
            adversary: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(direct: bool, ttl: u64, grace: u64, poll: u64) -> OpenRouterLeaseConfig {
        OpenRouterLeaseConfig {
            source: if direct {
                OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "k".into(),
                    api_base: "http://127.0.0.1:9".into(),
                }
            } else {
                OpenRouterLeaseSourceConfig::OaOrg {
                    org_base_url: "http://127.0.0.1:9".into(),
                    shared_secret: "s".into(),
                }
            },
            ttl_seconds: ttl,
            settlement_grace_seconds: grace,
            settlement_poll_seconds: poll,
        }
    }

    /// Every request accepted before an escape must settle before the
    /// challenger's raise decision, or an under-concession could not be raised.
    #[test]
    fn startup_timing_check_bounds_settlement_by_the_challenge_period() {
        let fixed = USAGE_READ_LATENCY_SECONDS + TIMING_MARGIN_SECONDS;
        assert!(check_challenge_timing(&lease(true, 3_600, 300, 2), 3_600, 86_400).is_ok());
        // OA: TTL + one grace + two polls.
        let oa = lease(false, 100, 100, 1);
        assert!(check_challenge_timing(&oa, 100, 302 + fixed).is_ok());
        let error = check_challenge_timing(&oa, 101, 302 + fixed)
            .unwrap_err()
            .to_string();
        assert!(error.contains("challenge timing is unsafe"), "{error}");
        assert!(check_challenge_timing(&lease(true, 60, 0, 1), 0, 86_400).is_err());
        assert!(check_challenge_timing(&lease(true, u64::MAX, 1, 1), 1, 86_400).is_err());
    }

    /// Regression: a directly managed OpenRouter key settles only after a
    /// second grace (drain after disabling) and a settlement poll; the old
    /// inequality counted one grace and no poll, so it accepted periods in
    /// which such a lease is still unsettled at `deadline − raise_lead`.
    #[test]
    fn startup_timing_counts_the_post_disable_drain_and_settlement_polls() {
        let fixed = USAGE_READ_LATENCY_SECONDS + TIMING_MARGIN_SECONDS;
        let direct = lease(true, 3_600, 3_600, 60);
        let period = 3_600 + 3_600 + 3_600 + fixed; // TTL + one grace + lead
        assert!(check_challenge_timing(&direct, 3_600, period).is_err());
        assert!(check_challenge_timing(&direct, 3_600, period + 3_600 + 120).is_ok());
        assert!(check_challenge_timing(&direct, 3_600, period + 3_600 + 119).is_err());
    }

    /// Regression: the configured period must be the vault's own; otherwise
    /// the timing gate and the O7 deferral window are vacuous.
    #[test]
    fn configured_challenge_period_must_equal_the_vaults() {
        assert!(check_vault_challenge_period(86_400, 86_400).is_ok());
        let error = check_vault_challenge_period(86_400, 3_600)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match the vault"), "{error}");
        assert!(check_vault_challenge_period(3_600, 86_400).is_err());
    }
}
