//! Serialization helpers for wire formats.

use serde::{de, Deserialize, Deserializer, Serializer};

use crate::Felt252;

/// Deserialize a `u64` from either a JSON integer or its canonical decimal
/// string representation.
///
/// JavaScript cannot represent every Solana-derived chain identity exactly.
/// Accepting the decimal string form lets browser clients preserve all 64 bits;
/// small values may still be sent as a plain JSON number.
pub fn deserialize_u64_or_decimal_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireU64 {
        Integer(u64),
        Decimal(String),
    }

    match WireU64::deserialize(deserializer)? {
        WireU64::Integer(value) => Ok(value),
        WireU64::Decimal(value) => {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(de::Error::custom(
                    "u64 string must be a canonical unsigned decimal integer",
                ));
            }
            value.parse::<u64>().map_err(de::Error::custom)
        }
    }
}

/// Serialize a `u64` as a canonical decimal string for JavaScript-facing wire
/// formats.
pub fn serialize_u64_decimal<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

/// Encode a boolean as a felt252 (0 or 1).
pub fn bool_to_felt(b: bool) -> Felt252 {
    if b {
        Felt252::ONE
    } else {
        Felt252::ZERO
    }
}

/// Decode a felt252 as a boolean.
pub fn felt_to_bool(f: &Felt252) -> Option<bool> {
    if *f == Felt252::ZERO {
        Some(false)
    } else if *f == Felt252::ONE {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct ExactU64 {
        #[serde(
            serialize_with = "serialize_u64_decimal",
            deserialize_with = "deserialize_u64_or_decimal_string"
        )]
        value: u64,
    }

    #[test]
    fn test_bool_roundtrip() {
        assert_eq!(felt_to_bool(&bool_to_felt(true)), Some(true));
        assert_eq!(felt_to_bool(&bool_to_felt(false)), Some(false));
        assert_eq!(felt_to_bool(&Felt252::from_u64(2)), None);
    }

    #[test]
    fn exact_u64_accepts_legacy_numbers_and_canonical_strings() {
        assert_eq!(
            serde_json::from_str::<ExactU64>(r#"{"value":7}"#).unwrap(),
            ExactU64 { value: 7 }
        );
        let maximum = ExactU64 { value: u64::MAX };
        assert_eq!(
            serde_json::to_string(&maximum).unwrap(),
            r#"{"value":"18446744073709551615"}"#
        );
        assert_eq!(
            serde_json::from_str::<ExactU64>(r#"{"value":"18446744073709551615"}"#).unwrap(),
            maximum
        );
        for invalid in [
            r#"{"value":"01"}"#,
            r#"{"value":"-1"}"#,
            r#"{"value":"1.0"}"#,
        ] {
            assert!(serde_json::from_str::<ExactU64>(invalid).is_err());
        }
    }
}
