//! Server configuration.
//!
//! Every shared parameter (protocol, USDC asset, vault, lease timing) comes
//! from the deployment profile; a network differs only through its identity.

pub use dagon_zkapi_profile::{ResolvedIdentity, SharedProfile, MAINNET_BETA};
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

/// Configuration for the zkAPI server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Shared deployment profile. Operator binaries always use
    /// [`SharedProfile::embedded`].
    pub profile: SharedProfile,
    /// Network label of the identity file.
    pub network: String,
    /// Genesis hash and deployed accounts of the network.
    pub identity: ResolvedIdentity,
    /// Solana RPC used for every authoritative read.
    pub rpc_url: String,
    /// Optional indexer that serves the latest tree snapshot to wallets.
    pub indexer_url: Option<String>,
    /// Optional shared testnet service gate; contains only a redacted digest.
    pub testnet_password: Option<crate::testnet_auth::TestnetPassword>,
    /// HTTP listen address (e.g. "0.0.0.0:3000").
    pub listen_addr: String,
    /// Path to the SQLite database file.
    pub db_path: String,
    /// Seed for the proof-friendly state-signing key.
    pub state_seed: Felt252,
    /// Seed for the proof-friendly clearance-signing key.
    pub clear_seed: Felt252,
    /// Poll interval for the finalized root refresh.
    pub root_poll_interval_ms: u64,
    /// Prompt-private OpenRouter lease source.
    pub lease_source: OpenRouterLeaseSourceConfig,
    /// Directory containing the v2 Groth16 proving/verifying key files.
    pub proof_setup_dir: String,
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
/// challenger's raise decision:
///
/// `lease TTL + settlement grace (twice for a directly managed OpenRouter
/// key, which drains again after it is disabled) + two settlement polls +
/// usage-read latency + raise lead + margin ≤ challenge period`.
pub fn check_challenge_timing(
    source: &OpenRouterLeaseSourceConfig,
    profile: &SharedProfile,
) -> anyhow::Result<()> {
    let server = &profile.server;
    let drains = match source {
        OpenRouterLeaseSourceConfig::OpenRouter { .. } => 2,
        OpenRouterLeaseSourceConfig::OaOrg { .. } => 1,
    };
    let grace = server.settlement_grace_seconds.saturating_mul(drains);
    let polls = server.settlement_poll_seconds.max(1).saturating_mul(2);
    let raise_lead = server.raise_lead_seconds;
    let period = profile.vault.challenge_period_seconds;
    let required = server
        .lease_ttl_seconds
        .saturating_add(grace)
        .saturating_add(polls)
        .saturating_add(USAGE_READ_LATENCY_SECONDS)
        .saturating_add(raise_lead)
        .saturating_add(TIMING_MARGIN_SECONDS);
    anyhow::ensure!(
        raise_lead > 0 && required <= period,
        "challenge timing is unsafe: lease TTL {}s + settlement grace {grace}s + settlement \
         polls {polls}s + usage latency {USAGE_READ_LATENCY_SECONDS}s + raise lead \
         {raise_lead}s + margin {TIMING_MARGIN_SECONDS}s = {required}s exceeds the \
         challenge period {period}s",
        server.lease_ttl_seconds
    );
    Ok(())
}

impl ServerConfig {
    /// A configuration with the embedded profile and default local settings.
    pub fn new(
        network: String,
        identity: ResolvedIdentity,
        rpc_url: String,
        lease_source: OpenRouterLeaseSourceConfig,
        state_seed: Felt252,
        clear_seed: Felt252,
    ) -> Self {
        Self {
            profile: SharedProfile::embedded().clone(),
            network,
            identity,
            rpc_url,
            indexer_url: None,
            testnet_password: None,
            listen_addr: "127.0.0.1:3000".to_string(),
            db_path: "zkapi-server.db".to_string(),
            state_seed,
            clear_seed,
            root_poll_interval_ms: 1_000,
            lease_source,
            proof_setup_dir: "protocol/setup/v2".to_string(),
            #[cfg(any(test, feature = "adversary"))]
            adversary: None,
        }
    }

    pub fn protocol_version(&self) -> u16 {
        self.profile.protocol.protocol_version
    }

    /// Protocol chain ID derived from the identity's genesis hash.
    pub fn chain_id(&self) -> u64 {
        zkapi_types::solana_chain_id(&self.identity.genesis_hash)
    }

    /// The v2 `contract_address` statement input: the deployment binding of
    /// the profile's program, the identity's vault and genesis hash.
    pub fn contract_address(&self) -> Felt252 {
        zkapi_types::solana_deployment_binding(
            &self.profile.program_id(),
            &self.identity.vault_state,
            &self.identity.genesis_hash,
        )
    }

    /// Minimum proof-bound lease budget in USDC base units ($1).
    pub fn request_charge_cap(&self) -> u128 {
        u128::from(self.profile.vault.request_charge_cap)
    }

    pub fn ledger_config(&self) -> SolanaLedgerConfig {
        SolanaLedgerConfig::from_identity(
            self.rpc_url.clone(),
            self.indexer_url.clone(),
            self.network.clone(),
            &self.profile,
            &self.identity,
        )
    }

    /// Reject incomplete or unsafe configurations before startup opens any
    /// state or makes any network request.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.profile.validate()?;
        anyhow::ensure!(
            self.testnet_password.is_none() || self.network != MAINNET_BETA,
            "ZKAPI_TESTNET_PASSWORD is not allowed on {MAINNET_BETA}"
        );
        anyhow::ensure!(
            self.identity.vault_state
                == dagon_zkapi_profile::vault_state_address(
                    &self.profile.program_id(),
                    &self.identity.vault_authority
                ),
            "identity vault state is not the vault PDA of its authority"
        );
        dagon_zkapi_solana_ledger::SolanaCreditLedger::new(self.ledger_config())?;
        match &self.lease_source {
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
                    self.profile.server.lease_ttl_seconds.is_multiple_of(60),
                    "OA org lease TTL must be a whole number of minutes"
                );
            }
        }
        anyhow::ensure!(
            self.request_charge_cap() <= crate::billing::MAX_SAFE_UNITS,
            "request charge cap must fit browser-safe credit units"
        );
        anyhow::ensure!(
            self.root_poll_interval_ms > 0,
            "root poll interval must be positive"
        );
        check_challenge_timing(&self.lease_source, &self.profile)?;
        #[cfg(any(test, feature = "adversary"))]
        crate::adversary::ensure_allowed(self.adversary)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(direct: bool) -> OpenRouterLeaseSourceConfig {
        if direct {
            OpenRouterLeaseSourceConfig::OpenRouter {
                management_key: "k".into(),
                api_base: "http://127.0.0.1:9".into(),
            }
        } else {
            OpenRouterLeaseSourceConfig::OaOrg {
                org_base_url: "http://127.0.0.1:9".into(),
                shared_secret: "s".into(),
            }
        }
    }

    fn profile(ttl: u64, grace: u64, poll: u64, lead: u64, period: u64) -> SharedProfile {
        let mut profile = SharedProfile::embedded().clone();
        profile.server.lease_ttl_seconds = ttl;
        profile.server.settlement_grace_seconds = grace;
        profile.server.settlement_poll_seconds = poll;
        profile.server.raise_lead_seconds = lead;
        profile.vault.challenge_period_seconds = period;
        profile
    }

    /// The embedded profile itself satisfies the timing bound for both lease
    /// sources, so every network runs with a safe challenge period.
    #[test]
    fn embedded_profile_timing_is_safe() {
        for direct in [true, false] {
            check_challenge_timing(&source(direct), SharedProfile::embedded()).unwrap();
        }
    }

    /// Every request accepted before an escape must settle before the
    /// challenger's raise decision, or an under-concession could not be raised.
    #[test]
    fn startup_timing_check_bounds_settlement_by_the_challenge_period() {
        let fixed = USAGE_READ_LATENCY_SECONDS + TIMING_MARGIN_SECONDS;
        assert!(
            check_challenge_timing(&source(true), &profile(3_600, 300, 2, 3_600, 86_400)).is_ok()
        );
        // OA: TTL + one grace + two polls.
        assert!(
            check_challenge_timing(&source(false), &profile(100, 100, 1, 100, 302 + fixed)).is_ok()
        );
        let error = check_challenge_timing(&source(false), &profile(100, 100, 1, 101, 302 + fixed))
            .unwrap_err()
            .to_string();
        assert!(error.contains("challenge timing is unsafe"), "{error}");
        assert!(check_challenge_timing(&source(true), &profile(60, 0, 1, 0, 86_400)).is_err());
        assert!(
            check_challenge_timing(&source(true), &profile(u64::MAX, 1, 1, 1, 86_400)).is_err()
        );
    }

    /// Regression: a directly managed OpenRouter key settles only after a
    /// second grace (drain after disabling) and a settlement poll; the old
    /// inequality counted one grace and no poll, so it accepted periods in
    /// which such a lease is still unsettled at `deadline − raise_lead`.
    #[test]
    fn startup_timing_counts_the_post_disable_drain_and_settlement_polls() {
        let fixed = USAGE_READ_LATENCY_SECONDS + TIMING_MARGIN_SECONDS;
        let period = 3_600 + 3_600 + 3_600 + fixed; // TTL + one grace + lead
        let direct = |period| profile(3_600, 3_600, 60, 3_600, period);
        assert!(check_challenge_timing(&source(true), &direct(period)).is_err());
        assert!(check_challenge_timing(&source(true), &direct(period + 3_600 + 120)).is_ok());
        assert!(check_challenge_timing(&source(true), &direct(period + 3_600 + 119)).is_err());
    }
}
