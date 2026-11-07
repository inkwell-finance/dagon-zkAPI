//! Boundary between metered upstream spend and the vault's USDC credits.
//!
//! One vault base unit is one micro-USDC, which the server bills as one
//! micro-USD: a request's proof-bound `solvency_bound` is its upstream spend
//! budget and metered micro-USD (already rounded up by
//! [`crate::pricing::usd_to_micro_usd`]) is its charge. Both stay within the
//! integers a JavaScript number represents exactly.

use crate::error::ServerError;

/// Largest integer a JavaScript number represents exactly.
pub const MAX_SAFE_UNITS: u128 = 9_007_199_254_740_991;

/// Upstream spend budget, in micro-USD, of a request's proof-bound solvency
/// bound. Zero and browser-unsafe budgets fail closed.
pub fn lease_limit_micro_usd(solvency_bound: u128) -> Result<u128, ServerError> {
    if solvency_bound == 0 || solvency_bound > MAX_SAFE_UNITS {
        return Err(ServerError::InvalidRequest(
            "USDC lease budget is outside browser-safe bounds".into(),
        ));
    }
    Ok(solvency_bound)
}

/// Charge, in USDC base units, for metered micro-USD. Callers cap it by the
/// request's solvency bound, which is also its spend budget.
pub fn charge_units(micro_usd: u128) -> Result<u128, ServerError> {
    if micro_usd > MAX_SAFE_UNITS {
        return Err(ServerError::InvalidRequest(
            "USDC usage is outside browser-safe bounds".into(),
        ));
    }
    Ok(micro_usd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pricing::usd_to_micro_usd;

    #[test]
    fn budget_and_charge_are_identity_conversions_within_safe_bounds() {
        for units in [1, 999_999, 1_000_000, MAX_SAFE_UNITS] {
            assert_eq!(lease_limit_micro_usd(units).unwrap(), units);
            assert_eq!(charge_units(units).unwrap(), units);
        }
        assert_eq!(charge_units(0).unwrap(), 0);
        assert!(lease_limit_micro_usd(0).is_err());
        assert!(lease_limit_micro_usd(MAX_SAFE_UNITS + 1).is_err());
        assert!(charge_units(MAX_SAFE_UNITS + 1).is_err());
    }

    /// Fractional micro-USD spend is charged upward, and the charge for a
    /// lease's whole budget never exceeds its solvency bound.
    #[test]
    fn metered_spend_ceils_and_a_full_budget_charge_fits_the_bound() {
        assert_eq!(charge_units(usd_to_micro_usd(0.000_000_1)).unwrap(), 1);
        assert_eq!(
            charge_units(usd_to_micro_usd(1.234_567_1)).unwrap(),
            1_234_568
        );
        for bound in [1, 7, 1_000_000, 3_000_000, MAX_SAFE_UNITS] {
            let budget = lease_limit_micro_usd(bound).unwrap();
            assert!(charge_units(budget).unwrap() <= bound);
        }
    }

    /// Exercise the actual browser implementation, not a second Rust copy.
    /// Like the SDK gates, this integration test requires Node and npm ci.
    #[test]
    fn server_and_sdk_lease_limits_match_bit_for_bit() {
        let bounds = [
            1,
            7,
            123,
            246,
            253,
            999_999,
            1_000_000,
            1_234_567,
            MAX_SAFE_UNITS,
        ];
        let script = r#"
            import { leaseLimitUsd } from './sdk/services/zkapiUsdc.mjs';
            const view = new DataView(new ArrayBuffer(8));
            const bits = JSON.parse(process.argv[1]).map(bound => {
                view.setFloat64(0, leaseLimitUsd(bound));
                return view.getBigUint64(0).toString();
            });
            console.log(JSON.stringify(bits));
        "#;
        let output = std::process::Command::new("node")
            .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
            .args(["--input-type=module", "-e", script])
            .arg(serde_json::to_string(&bounds).unwrap())
            .output()
            .expect("Node is required for the server/SDK billing parity gate");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bits: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(bits.len(), bounds.len());
        for (bound, sdk_bits) in bounds.into_iter().zip(bits) {
            let limit = crate::pricing::micro_usd_to_usd(lease_limit_micro_usd(bound).unwrap());
            assert_eq!(limit.to_bits().to_string(), sdk_bits, "bound {bound}");
            assert_eq!(charge_units(bound).unwrap(), bound);
        }
    }
}
