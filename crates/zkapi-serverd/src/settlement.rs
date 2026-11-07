//! Finalized native lease usage and settlement data.

/// Aggregate upstream spend surfaced to the operator dashboard. Its micro-USD
/// cost, rounded up, is `charge_applied` in USDC base units.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct UsageInfo {
    /// Upstream cost in US dollars.
    pub cost_usd: f64,
    /// Origin of the aggregate cost, such as an OA signed receipt.
    pub cost_source: String,
}

/// Result of settling a prompt-private lease. The charge is in USDC base units.
#[derive(Debug, Clone)]
pub struct SettlementResult {
    pub status_code: u16,
    pub payload: String,
    pub charge_applied: u128,
    /// Aggregate upstream usage behind the USDC charge.
    pub usage: Option<UsageInfo>,
    /// Human-readable lease source for the dashboard.
    pub billing_label: String,
}
