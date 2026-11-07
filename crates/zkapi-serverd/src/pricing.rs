//! Upstream USD accounting for USDC lease settlement.
//!
//! These units describe provider spend. [`crate::billing`] maps micro-USD to
//! the vault's USDC base units (one micro-USDC each).

const MICRO_USD_PER_USD: f64 = 1_000_000.0;

/// Round upstream USD spend up to a whole micro-dollar, the charge unit.
pub fn usd_to_micro_usd(cost_usd: f64) -> u128 {
    if !cost_usd.is_finite() || cost_usd <= 0.0 {
        return 0;
    }
    (cost_usd * MICRO_USD_PER_USD).ceil().max(1.0) as u128
}

pub fn micro_usd_to_usd(micro_usd: u128) -> f64 {
    let micro_usd_float = micro_usd as f64;
    let candidate = micro_usd_float / MICRO_USD_PER_USD;
    // Proof-covered limits are bounded to JavaScript's safe-integer range, but
    // the division can still round the provider-facing `f64` upward by one
    // micro-dollar. Never provision more upstream spend than the integer floor.
    if candidate * MICRO_USD_PER_USD > micro_usd_float {
        candidate.next_down()
    } else {
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_cost_rounds_up_with_floor() {
        assert_eq!(usd_to_micro_usd(0.0000051), 6);
        assert_eq!(usd_to_micro_usd(0.000010), 10);
        assert_eq!(usd_to_micro_usd(0.0000001), 1);
        assert_eq!(usd_to_micro_usd(0.0), 0);
        assert_eq!(usd_to_micro_usd(-1.0), 0);
    }

    #[test]
    fn upstream_cost_round_trip() {
        assert!((micro_usd_to_usd(1_000_000) - 1.0).abs() < 1e-12);
        assert!((micro_usd_to_usd(6) - 0.000006).abs() < 1e-12);
    }

    #[test]
    fn provider_limit_never_rounds_above_the_integer_budget() {
        let max_safe_units = 9_007_199_254_740_991u128;
        let rounded_up = max_safe_units as f64 / MICRO_USD_PER_USD;
        assert!(rounded_up * MICRO_USD_PER_USD > max_safe_units as f64);

        let conservative = micro_usd_to_usd(max_safe_units);
        assert!(conservative * MICRO_USD_PER_USD <= max_safe_units as f64);
    }
}
