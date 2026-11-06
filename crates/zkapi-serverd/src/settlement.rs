//! Finalized native lease usage and settlement data.

/// Aggregate upstream spend surfaced to the operator dashboard. The frozen
/// SOL quote converts this USD cost to `charge_applied` in whole lamports.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct UsageInfo {
    /// Upstream cost in US dollars.
    pub cost_usd: f64,
    /// Origin of the aggregate cost, such as an OA signed receipt.
    pub cost_source: String,
}

/// Result of settling a prompt-private lease. The charge is in whole lamports.
#[derive(Debug, Clone)]
pub struct SettlementResult {
    pub status_code: u16,
    pub payload: String,
    pub charge_applied: u128,
    /// Aggregate upstream usage behind the frozen-quote lamport charge.
    pub usage: Option<UsageInfo>,
    /// Human-readable lease source for the dashboard.
    pub billing_label: String,
}
