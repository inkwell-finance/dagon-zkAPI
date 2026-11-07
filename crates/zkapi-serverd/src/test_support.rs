//! Solana lease fixtures; never compiled into the server binary.
use std::sync::Arc;

use dagon_zkapi_ledger::{
    CreditLedger, LedgerAccount, LedgerAsset, LedgerCommitment, LedgerDeployment, LedgerError,
    LedgerFuture, LedgerNullifierStatus, LedgerPath, LedgerSnapshot, LedgerState,
};
use zkapi_types::wire::OpenRouterLeaseAuthorization;
use zkapi_types::Felt252;

use crate::config::{OpenRouterLeaseSourceConfig, ResolvedIdentity, ServerConfig, SharedProfile};

/// A localnet identity whose vault is the profile program's PDA.
pub(crate) fn identity() -> ResolvedIdentity {
    let vault_authority = [5; 32];
    ResolvedIdentity {
        genesis_hash: [3; 32],
        vault_authority,
        vault_state: dagon_zkapi_profile::vault_state_address(
            &SharedProfile::embedded().program_id(),
            &vault_authority,
        ),
        treasury_token_account: dagon_zkapi_profile::usdc_associated_token_address(&[7; 32]),
    }
}

pub(crate) fn oa_source() -> OpenRouterLeaseSourceConfig {
    OpenRouterLeaseSourceConfig::OaOrg {
        org_base_url: "http://127.0.0.1:9".into(),
        shared_secret: "test-secret".into(),
    }
}

/// The embedded profile under the test identity; no RPC is reachable.
pub(crate) fn config(lease_source: OpenRouterLeaseSourceConfig) -> ServerConfig {
    ServerConfig::new(
        "localnet".into(),
        identity(),
        "http://127.0.0.1:9".into(),
        lease_source,
        Felt252::from_u64(1),
        Felt252::from_u64(2),
    )
}

/// The exact prompt-free lease payload.
pub(crate) fn lease_payload() -> String {
    serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap()
}

pub(crate) type NullifierRead =
    Arc<dyn Fn() -> Result<LedgerNullifierStatus, LedgerError> + Send + Sync>;

/// A credit ledger that answers only nullifier reads, through `nullifier`.
pub(crate) struct StubLedger {
    deployment: LedgerDeployment,
    nullifier: NullifierRead,
}

impl StubLedger {
    pub(crate) fn new(config: &ServerConfig, nullifier: NullifierRead) -> Arc<Self> {
        Arc::new(Self {
            deployment: LedgerDeployment {
                backend: "dagon.solana.groth16.v1".into(),
                network: config.network.clone(),
                chain_id: config.chain_id(),
                protocol_binding: config.contract_address(),
                vault: LedgerAccount::new(config.identity.vault_state),
                asset: LedgerAsset {
                    symbol: "USDC".into(),
                    decimals: 6,
                    mint: Some(LedgerAccount::new(config.profile.usdc_mint())),
                },
            },
            nullifier,
        })
    }

    /// Every chain read fails, as against an unreachable RPC.
    pub(crate) fn unavailable(config: &ServerConfig) -> Arc<Self> {
        Self::new(
            config,
            Arc::new(|| Err(LedgerError::Unavailable("test RPC unavailable".into()))),
        )
    }
}

fn unavailable<T>() -> LedgerFuture<'static, T> {
    Box::pin(async { Err(LedgerError::Unavailable("test RPC unavailable".into())) })
}

impl CreditLedger for StubLedger {
    fn deployment(&self) -> &LedgerDeployment {
        &self.deployment
    }

    fn state(&self, _: LedgerCommitment) -> LedgerFuture<'_, LedgerState> {
        unavailable()
    }

    fn snapshot(&self, _: LedgerCommitment) -> LedgerFuture<'_, LedgerSnapshot> {
        unavailable()
    }

    fn path(&self, _: u32, _: bool, _: LedgerCommitment) -> LedgerFuture<'_, LedgerPath> {
        unavailable()
    }

    fn nullifier_status(
        &self,
        _: Felt252,
        _: LedgerCommitment,
    ) -> LedgerFuture<'_, LedgerNullifierStatus> {
        let result = (self.nullifier)();
        Box::pin(async move { result })
    }
}
