//! Solana lease fixtures; never compiled into the server binary.
use std::sync::Arc;

use dagon_zkapi_ledger::{
    CreditLedger, LedgerAccount, LedgerAsset, LedgerCommitment, LedgerDeployment, LedgerError,
    LedgerFuture, LedgerNullifierStatus, LedgerPath, LedgerSnapshot, LedgerState,
};
use zkapi_types::Felt252;

use crate::billing::{
    BillingFuture, BillingPins, BillingPriceSource, BillingQuote, LAMPORTS_PER_SOL, PYTH_SOURCE,
};
use crate::config::{OpenRouterLeaseSourceConfig, ResolvedIdentity, ServerConfig, SharedProfile};
use crate::error::ServerError;

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
        treasury: [7; 32],
        pyth_price_account: [8; 32],
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

/// A quote pinned to `config` at `price × 10⁻⁸` USD per SOL.
pub(crate) fn quote(config: &ServerConfig, publish_time: u64, price: &str) -> BillingQuote {
    let pins = config.billing_pins();
    BillingQuote {
        asset: "native_sol".into(),
        source: PYTH_SOURCE.into(),
        credit_unit: "lamports".into(),
        base_units_per_asset: LAMPORTS_PER_SOL,
        chain_id: pins.chain_id.to_string(),
        deployment_binding: pins.deployment_binding,
        backend: pins.backend,
        network: pins.network,
        vault: pins.vault,
        feed_id: pins.feed_id,
        feed_account: pins.feed_account,
        receiver_program: pins.receiver_program,
        price: price.into(),
        exponent: -8,
        confidence: "0".into(),
        publish_time,
        expires_at: publish_time + pins.max_age_seconds,
        posted_slot: 1,
    }
}

pub(crate) fn lease_payload_with(quote: &BillingQuote) -> String {
    serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
        .to_string()
}

pub(crate) fn lease_payload(config: &ServerConfig, now: u64) -> String {
    // A fixed $1000/SOL test quote makes one micro-USD equal one lamport.
    lease_payload_with(&quote(config, now, "100000000000"))
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
                    symbol: "SOL".into(),
                    decimals: 9,
                    mint: None,
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

pub(crate) type QuoteCheck = Arc<dyn Fn(BillingQuote) -> BillingFuture<'static, ()> + Send + Sync>;

/// A price source whose authenticated-source check is `check`, after the
/// same identity and freshness checks as the Pyth oracle.
pub(crate) struct StubBilling {
    pins: BillingPins,
    check: QuoteCheck,
}

impl StubBilling {
    pub(crate) fn new(config: &ServerConfig, check: QuoteCheck) -> Arc<Self> {
        Arc::new(Self {
            pins: config.billing_pins(),
            check,
        })
    }

    pub(crate) fn accepting(config: &ServerConfig) -> Arc<Self> {
        Self::new(config, Arc::new(|_| Box::pin(async { Ok(()) })))
    }
}

impl BillingPriceSource for StubBilling {
    fn quote(&self, _: u64) -> BillingFuture<'_, BillingQuote> {
        Box::pin(async { Err(ServerError::Internal("test oracle has no quotes".into())) })
    }

    fn validate<'a>(&'a self, quote: &'a BillingQuote, now: u64) -> BillingFuture<'a, ()> {
        Box::pin(async move {
            self.assert_fresh(quote, now)?;
            (self.check)(quote.clone()).await
        })
    }

    fn validate_identity(&self, quote: &BillingQuote) -> Result<(), ServerError> {
        quote.validate_identity(&self.pins)
    }
}
