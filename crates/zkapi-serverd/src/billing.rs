//! Price boundary between Pyth SOL/USD quotes and lamport credits. A price
//! source is not a credit ledger.
//!
//! Quotes carry an explicit source and deployment binding; callers must
//! authenticate them through `BillingPriceSource::validate` before first
//! acceptance. Settlement only uses the already accepted, proof-bound quote.

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

use crate::error::ServerError;

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
pub const PYTH_SOURCE: &str = "pyth_solana_receiver";
/// Largest integer a JavaScript number represents exactly.
pub const MAX_SAFE_UNITS: u128 = 9_007_199_254_740_991;

pub type BillingFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ServerError>> + Send + 'a>>;

/// Authentication and acquisition of prices, independent of chain accounting.
/// `validate` must check the pinned finalized source, not just quote syntax.
/// `validate_identity` intentionally omits freshness so accepted quotes remain
/// usable for settlement and exact retries after their issuance window expires.
pub trait BillingPriceSource: Send + Sync {
    fn quote(&self, now: u64) -> BillingFuture<'_, BillingQuote>;
    fn validate<'a>(&'a self, quote: &'a BillingQuote, now: u64) -> BillingFuture<'a, ()>;
    fn validate_identity(&self, quote: &BillingQuote) -> Result<(), ServerError>;

    fn assert_fresh(&self, quote: &BillingQuote, now: u64) -> Result<(), ServerError> {
        self.validate_identity(quote)?;
        quote.assert_fresh(now)
    }
}

/// Pins owned by the operator, never supplied by an API caller. The transport
/// adapter must decode/validate addresses and verify the actual account owner
/// using the official receiver SDK before constructing an authenticated quote.
#[derive(Debug, Clone)]
pub struct BillingPins {
    pub chain_id: u64,
    pub deployment_binding: Felt252,
    pub backend: String,
    pub network: String,
    pub vault: String,
    pub feed_id: String,
    pub feed_account: String,
    pub receiver_program: String,
    pub max_age_seconds: u64,
    pub max_confidence_bps: u16,
}

/// A finalized Pyth SOL/USD price bound to one deployment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BillingQuote {
    pub asset: String,
    pub source: String,
    pub credit_unit: String,
    pub base_units_per_asset: u64,
    /// Full u64 identity must not be rounded by JavaScript JSON consumers.
    pub chain_id: String,
    pub deployment_binding: Felt252,
    pub backend: String,
    pub network: String,
    pub vault: String,
    pub feed_id: String,
    pub feed_account: String,
    pub receiver_program: String,
    /// Positive canonical decimal integer, matching Pyth's signed i64 price.
    pub price: String,
    pub exponent: i32,
    pub confidence: String,
    pub publish_time: u64,
    pub expires_at: u64,
    pub posted_slot: u64,
}

impl BillingQuote {
    pub fn validate_identity(&self, pins: &BillingPins) -> Result<(), ServerError> {
        if self.asset != "native_sol"
            || self.source != PYTH_SOURCE
            || self.credit_unit != "lamports"
            || self.base_units_per_asset != LAMPORTS_PER_SOL
            || self.chain_id != pins.chain_id.to_string()
            || self.deployment_binding != pins.deployment_binding
            || self.backend != pins.backend
            || self.network != pins.network
            || self.vault != pins.vault
            || self.feed_id != pins.feed_id
            || self.feed_account != pins.feed_account
            || self.receiver_program != pins.receiver_program
            || pins.backend != "dagon.solana.groth16.v1"
            || pins.network.trim().is_empty()
            || pins.vault.trim().is_empty()
            || pins.feed_id.is_empty()
            || pins.feed_account.is_empty()
            || pins.receiver_program.is_empty()
            || pins.max_age_seconds == 0
            || pins.max_age_seconds > 60
            || !(1..=100).contains(&pins.max_confidence_bps)
            || self.publish_time == 0
            || self.expires_at
                != self
                    .publish_time
                    .checked_add(pins.max_age_seconds)
                    .ok_or_else(|| invalid("SOL billing quote expiry overflow"))?
        {
            return Err(invalid(
                "SOL billing quote does not match the pinned deployment/source",
            ));
        }
        let price = positive_price(&self.price)?;
        // Reject an interval that permits a zero/negative native-asset price.
        let confidence = canonical_u64(&self.confidence)?;
        if confidence >= price
            || u128::from(confidence) * 10_000
                > u128::from(price) * u128::from(pins.max_confidence_bps)
        {
            return Err(invalid(
                "SOL billing price confidence permits a nonpositive price",
            ));
        }
        self.micro_usd_per_lamport()?;
        Ok(())
    }

    pub fn assert_fresh(&self, now: u64) -> Result<(), ServerError> {
        if self.publish_time == 0 || self.publish_time > now {
            return Err(invalid(
                "billing price publication time is invalid or in the future",
            ));
        }
        if self.expires_at <= now {
            return Err(ServerError::NativeQuoteExpired);
        }
        Ok(())
    }

    /// Exact rational number of micro-USD per lamport. Reject unsupported
    /// exponents/overflow rather than saturating, using floats, or weakening
    /// rounding. The production adapter uses the same arithmetic at issuance.
    fn micro_usd_per_lamport(&self) -> Result<(u128, u128), ServerError> {
        if self.asset != "native_sol"
            || self.credit_unit != "lamports"
            || self.base_units_per_asset != LAMPORTS_PER_SOL
            || !(-18..=18).contains(&self.exponent)
        {
            return Err(invalid("unsupported SOL billing units or exponent"));
        }
        let price = positive_price(&self.price)?;
        let confidence = canonical_u64(&self.confidence)?;
        let price = u128::from(
            price
                .checked_sub(confidence)
                .filter(|price| *price > 0)
                .ok_or_else(|| invalid("SOL lower-bound price must be positive"))?,
        );
        // price * 10^(exponent + 6) / 10^9; combine powers before
        // multiplying and reduce the resulting ratio to avoid avoidable overflow.
        let power = self.exponent - 3;
        let (numerator, denominator) = if power >= 0 {
            (
                price
                    .checked_mul(10u128.pow(power as u32))
                    .ok_or_else(|| invalid("SOL billing price scale overflow"))?,
                1,
            )
        } else {
            (price, 10u128.pow((-power) as u32))
        };
        let divisor = gcd(numerator, denominator);
        Ok((numerator / divisor, denominator / divisor))
    }

    /// Floor the spend budget: never provision more micro-USD than the proof's
    /// lamport bound covers. Zero and browser-unsafe budgets fail closed.
    pub fn limit_micro_usd(&self, lamports: u128) -> Result<u128, ServerError> {
        if lamports == 0 || lamports > MAX_SAFE_UNITS {
            return Err(invalid("SOL lease amount is outside browser-safe bounds"));
        }
        let (numerator, denominator) = self.micro_usd_per_lamport()?;
        let (value, _) = mul_div(lamports, numerator, denominator)?;
        if value == 0 || value > MAX_SAFE_UNITS {
            return Err(invalid(
                "SOL lease USD budget is outside browser-safe bounds",
            ));
        }
        Ok(value)
    }

    /// Ceil the charge: any fractional lamport is charged upward. Validate the
    /// price even for zero usage; malformed quotes cannot bypass arithmetic.
    pub fn charge_units(&self, micro_usd: u128) -> Result<u128, ServerError> {
        let (numerator, denominator) = self.micro_usd_per_lamport()?;
        if micro_usd > MAX_SAFE_UNITS {
            return Err(invalid("SOL usage is outside browser-safe bounds"));
        }
        let (floor, remainder) = mul_div(micro_usd, denominator, numerator)?;
        let charge = floor
            .checked_add(u128::from(remainder))
            .ok_or_else(|| invalid("SOL billing charge overflow"))?;
        if charge > MAX_SAFE_UNITS {
            return Err(invalid("SOL billing charge is outside browser-safe bounds"));
        }
        Ok(charge)
    }
}

fn invalid(message: &str) -> ServerError {
    ServerError::InvalidRequest(message.into())
}

fn canonical_u64(value: &str) -> Result<u64, ServerError> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid("invalid SOL billing quote integer"));
    }
    value
        .parse()
        .map_err(|_| invalid("SOL billing quote integer overflow"))
}

fn positive_price(value: &str) -> Result<u64, ServerError> {
    let price = canonical_u64(value)?;
    if price == 0 || price > i64::MAX as u64 {
        return Err(invalid("SOL billing price must be a positive i64"));
    }
    Ok(price)
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Return floor(a*b/d) and whether its exact rational value is fractional.
/// Cancel denominator factors first; overflow is always an error.
fn mul_div(a: u128, b: u128, d: u128) -> Result<(u128, bool), ServerError> {
    let g = gcd(a, d);
    let (a, d) = (a / g, d / g);
    let g = gcd(b, d);
    let (b, d) = (b / g, d / g);
    let product = a
        .checked_mul(b)
        .ok_or_else(|| invalid("SOL billing conversion overflow"))?;
    Ok((product / d, product % d != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";

    fn quote(price: &str, exponent: i32) -> BillingQuote {
        BillingQuote {
            asset: "native_sol".into(),
            source: PYTH_SOURCE.into(),
            credit_unit: "lamports".into(),
            base_units_per_asset: LAMPORTS_PER_SOL,
            chain_id: "7".into(),
            deployment_binding: Felt252::from_u64(8),
            backend: "dagon.solana.groth16.v1".into(),
            network: "localnet".into(),
            vault: "pinned-vault".into(),
            feed_id: FEED.into(),
            feed_account: "pinned-price-account".into(),
            receiver_program: "pinned-receiver".into(),
            price: price.into(),
            exponent,
            confidence: "0".into(),
            publish_time: 100,
            expires_at: 130,
            posted_slot: 90,
        }
    }

    fn pins(q: &BillingQuote, max_age_seconds: u64) -> BillingPins {
        BillingPins {
            chain_id: 7,
            deployment_binding: q.deployment_binding,
            backend: q.backend.clone(),
            network: q.network.clone(),
            vault: q.vault.clone(),
            feed_id: FEED.into(),
            feed_account: q.feed_account.clone(),
            receiver_program: q.receiver_program.clone(),
            max_age_seconds,
            max_confidence_bps: 100,
        }
    }

    #[test]
    fn sol_budget_floors_and_charge_ceils() {
        let q = quote("15000000000", -8); // $150 / SOL
        assert_eq!(q.limit_micro_usd(1_000_000_000).unwrap(), 150_000_000);
        assert_eq!(q.limit_micro_usd(10).unwrap(), 1);
        assert_eq!(q.charge_units(1).unwrap(), 7);
        assert_eq!(q.charge_units(3).unwrap(), 20);
        assert_eq!(q.charge_units(0).unwrap(), 0);
        for lamports in [7, 10, 20, 999, MAX_SAFE_UNITS] {
            let budget = q.limit_micro_usd(lamports).unwrap();
            assert!(q.charge_units(budget).unwrap() <= lamports);
        }
    }

    #[test]
    fn positive_negative_and_zero_exponents_are_exact() {
        for q in [quote("15", 1), quote("150", 0), quote("15000000000", -8)] {
            assert_eq!(q.limit_micro_usd(1_000_000_000).unwrap(), 150_000_000);
            assert_eq!(q.charge_units(150_000_000).unwrap(), 1_000_000_000);
        }
    }

    #[test]
    fn bounds_and_overflow_fail_closed() {
        for price in ["0", "-1", "+1", "01", "1.0", "9223372036854775808"] {
            assert!(quote(price, -8).charge_units(0).is_err());
        }
        assert!(quote("1", i32::MIN).charge_units(0).is_err());
        assert!(quote("1", i32::MAX).charge_units(0).is_err());
        let q = quote("15000000000", -8);
        assert!(q.limit_micro_usd(0).is_err());
        assert!(q.limit_micro_usd(MAX_SAFE_UNITS + 1).is_err());
        assert!(q.charge_units(MAX_SAFE_UNITS + 1).is_err());
        assert!(quote("1", -18).charge_units(1).is_err());
        assert!(quote("9223372036854775807", 18)
            .limit_micro_usd(MAX_SAFE_UNITS)
            .is_err());
    }

    #[test]
    fn identity_is_source_asset_feed_and_deployment_bound() {
        let q = quote("15000000000", -8);
        let pins = pins(&q, 30);
        q.validate_identity(&pins).unwrap();
        for mutate in [
            (|q: &mut BillingQuote| q.asset = "native_usdc".into()) as fn(&mut BillingQuote),
            |q| q.source = "http_price".into(),
            |q| q.credit_unit = "micro_usd".into(),
            |q| q.base_units_per_asset += 1,
            |q| q.chain_id = "8".into(),
            |q| q.backend = "other.groth16.v1".into(),
            |q| q.network = "other".into(),
            |q| q.vault = "other".into(),
            |q| q.deployment_binding = Felt252::ZERO,
            |q| q.feed_id = "other-feed".into(),
            |q| q.feed_account = "other-account".into(),
            |q| q.receiver_program = "other-owner".into(),
            |q| q.expires_at += 1,
            |q| q.confidence = q.price.clone(),
        ] {
            let mut changed = q.clone();
            mutate(&mut changed);
            assert!(changed.validate_identity(&pins).is_err());
        }
    }

    #[test]
    fn production_confidence_age_and_exponent_boundaries() {
        let mut q = quote("15000000000", -8);
        let mut pins = pins(&q, 60);
        q.expires_at = 160;
        q.confidence = "150000000".into();
        q.validate_identity(&pins).unwrap();
        q.confidence = "150000001".into();
        assert!(q.validate_identity(&pins).is_err());
        q.confidence = "0".into();
        pins.max_age_seconds = 61;
        q.expires_at = 161;
        assert!(q.validate_identity(&pins).is_err());
        pins.max_age_seconds = 60;
        q.expires_at = 160;
        for exponent in [-19, -18, 18, 19] {
            q.exponent = exponent;
            assert_eq!(
                q.validate_identity(&pins).is_ok(),
                (-18..=18).contains(&exponent)
            );
        }
        q.exponent = -8;
        for field in [0, 1, 2, 3] {
            let mut empty = pins.clone();
            match field {
                0 => empty.backend.clear(),
                1 => empty.network.clear(),
                2 => empty.vault.clear(),
                _ => empty.feed_id.clear(),
            }
            assert!(q.validate_identity(&empty).is_err());
        }
    }

    #[test]
    fn confidence_uses_lower_bound_and_chain_id_is_lossless() {
        let mut q = quote("15000000000", -8);
        q.confidence = "150000000".into(); // 1%, lower price $148.50
        q.chain_id = u64::MAX.to_string();
        assert_eq!(q.limit_micro_usd(1_000_000_000).unwrap(), 148_500_000);
        assert_eq!(q.charge_units(148_500_000).unwrap(), 1_000_000_000);
        let encoded = serde_json::to_value(&q).unwrap();
        assert_eq!(encoded["chain_id"], u64::MAX.to_string());
        q.confidence = q.price.clone();
        assert!(q.charge_units(0).is_err());
    }

    #[test]
    fn freshness_is_separate_from_frozen_quote_conversion() {
        let q = quote("15000000000", -8);
        q.assert_fresh(100).unwrap();
        assert!(q.assert_fresh(99).is_err());
        assert!(matches!(
            q.assert_fresh(130),
            Err(ServerError::NativeQuoteExpired)
        ));
        // Settlement is allowed to use an already accepted quote after expiry.
        assert_eq!(q.charge_units(3).unwrap(), 20);
    }

    #[test]
    fn wire_object_round_trips_and_unknown_fields_fail() {
        let q = quote("15000000000", -8);
        let encoded = serde_json::to_value(&q).unwrap();
        assert_eq!(
            serde_json::from_value::<BillingQuote>(encoded.clone()).unwrap(),
            q
        );
        let mut extra = encoded;
        extra["untrusted"] = "123".into();
        assert!(serde_json::from_value::<BillingQuote>(extra).is_err());
    }
}
