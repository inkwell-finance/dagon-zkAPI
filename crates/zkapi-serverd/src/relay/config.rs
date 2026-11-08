//! Relay configuration from the environment.
//!
//! The relay is off unless `ZKAPI_RELAYER_KEY` is set. Its key is a
//! dedicated low-balance wallet: startup refuses any key that is also an
//! operator, vault, treasury or challenger key.

use std::path::Path;

use anyhow::{bail, ensure, Context};
use dagon_zkapi_solana_ledger::SolanaPubkey as Pubkey;
use solana_keypair::Keypair;
use solana_signer::Signer;

pub const ENV_KEY: &str = "ZKAPI_RELAYER_KEY";
pub const ENV_FEE_ACCOUNT: &str = "ZKAPI_RELAYER_FEE_ACCOUNT";
pub const ENV_MARGIN_BPS: &str = "ZKAPI_RELAYER_MARGIN_BPS";
pub const ENV_SOL_USD: &str = "ZKAPI_RELAYER_SOL_USD";
pub const ENV_MIN_SOL: &str = "ZKAPI_RELAYER_MIN_SOL";
pub const ENV_IRIS_URL: &str = "ZKAPI_CCTP_IRIS_URL";
pub const ENV_RECEIVE_MIN_USDC: &str = "ZKAPI_RELAYER_RECEIVE_MIN_USDC";
pub const ENV_RECEIVE_DAILY_SOL: &str = "ZKAPI_RELAYER_RECEIVE_DAILY_SOL";
pub const ENV_RECEIVE_PER_ADDRESS_DAILY: &str = "ZKAPI_RELAYER_RECEIVE_PER_ADDRESS_DAILY";
pub const ENV_BURN_MIN_USDC: &str = "ZKAPI_RELAYER_BURN_MIN_USDC";
pub const ENV_BURN_FLOAT_SOL: &str = "ZKAPI_RELAYER_BURN_FLOAT_SOL";
pub const ENV_LOSS_DAILY_SOL: &str = "ZKAPI_RELAYER_LOSS_DAILY_SOL";
pub const ENV_UNBACKED_LOSS_DAILY_SOL: &str = "ZKAPI_RELAYER_UNBACKED_LOSS_DAILY_SOL";

pub const DEFAULT_MARGIN_BPS: u32 = 2_000;
pub const DEFAULT_IRIS_URL: &str = "https://iris-api.circle.com";
/// Below this balance the relay refuses new work (`relayer_unavailable`).
pub const DEFAULT_MIN_LAMPORTS: u64 = 50_000_000;
const MAX_MARGIN_BPS: u32 = 10_000;
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Subsidized receive admission, independent of the relay balance/top-ups.
#[derive(Debug, Clone, Copy)]
pub struct ReceivePolicy {
    pub minimum_amount: u64,
    pub daily_lamports: u64,
    pub per_address_daily: u32,
}

impl Default for ReceivePolicy {
    fn default() -> Self {
        Self {
            minimum_amount: 1_000_000,
            daily_lamports: 50_000_000,
            per_address_daily: 6,
        }
    }
}

/// Relay settings. The keypair is never printed.
pub struct RelayConfig {
    pub keypair: Keypair,
    /// USDC token account that receives relay fees.
    pub fee_account: Pubkey,
    pub margin_bps: u32,
    /// SOL price in micro-USD (one USDC base unit each).
    pub sol_usd_micros: u64,
    pub iris_url: String,
    /// SOL floor below which the relay refuses work.
    pub min_lamports: u64,
    pub receive: ReceivePolicy,
    pub burn_minimum_amount: u64,
    pub burn_float_lamports: u64,
    pub daily_loss_lamports: u64,
    /// Separate daily loss budget of ek-co-signed work without a credential.
    pub unbacked_daily_loss_lamports: u64,
}

impl std::fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConfig")
            .field("relayer", &self.keypair.pubkey())
            .field("fee_account", &self.fee_account)
            .field("margin_bps", &self.margin_bps)
            .field("sol_usd_micros", &self.sol_usd_micros)
            .field("iris_url", &self.iris_url)
            .field("min_lamports", &self.min_lamports)
            .field("receive", &self.receive)
            .finish()
    }
}

impl RelayConfig {
    /// `None` when the relay is not configured (no `ZKAPI_RELAYER_KEY`).
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid UTF-8"),
        })
    }

    pub fn from_lookup(
        lookup: impl Fn(&str) -> anyhow::Result<Option<String>>,
    ) -> anyhow::Result<Option<Self>> {
        let get = |name: &str| -> anyhow::Result<Option<String>> {
            Ok(lookup(name)?.filter(|value| !value.trim().is_empty()))
        };
        let Some(key) = get(ENV_KEY)? else {
            for name in [
                ENV_FEE_ACCOUNT,
                ENV_MARGIN_BPS,
                ENV_SOL_USD,
                ENV_MIN_SOL,
                ENV_IRIS_URL,
                ENV_RECEIVE_MIN_USDC,
                ENV_RECEIVE_DAILY_SOL,
                ENV_RECEIVE_PER_ADDRESS_DAILY,
                ENV_BURN_MIN_USDC,
                ENV_BURN_FLOAT_SOL,
                ENV_LOSS_DAILY_SOL,
                ENV_UNBACKED_LOSS_DAILY_SOL,
            ] {
                ensure!(get(name)?.is_none(), "{name} is set but {ENV_KEY} is not");
            }
            return Ok(None);
        };
        let keypair = load_keypair(key.trim())?;
        let fee_account = get(ENV_FEE_ACCOUNT)?
            .with_context(|| format!("{ENV_FEE_ACCOUNT} is required when {ENV_KEY} is set"))?;
        let fee_account = parse_pubkey(fee_account.trim(), ENV_FEE_ACCOUNT)?;
        let margin_bps = match get(ENV_MARGIN_BPS)? {
            None => DEFAULT_MARGIN_BPS,
            Some(value) => value
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|bps| *bps <= MAX_MARGIN_BPS)
                .with_context(|| {
                    format!("{ENV_MARGIN_BPS} must be an integer in 0..={MAX_MARGIN_BPS}")
                })?,
        };
        let sol_usd = get(ENV_SOL_USD)?
            .with_context(|| format!("{ENV_SOL_USD} is required when {ENV_KEY} is set"))?;
        let sol_usd_micros = parse_decimal(sol_usd.trim(), 6)
            .filter(|micros| *micros > 0)
            .with_context(|| {
                format!("{ENV_SOL_USD} must be a positive decimal with at most 6 decimals")
            })?;
        let min_lamports = match get(ENV_MIN_SOL)? {
            None => DEFAULT_MIN_LAMPORTS,
            Some(value) => parse_decimal(value.trim(), 9).with_context(|| {
                format!("{ENV_MIN_SOL} must be a decimal SOL amount with at most 9 decimals")
            })?,
        };
        let defaults = ReceivePolicy::default();
        let minimum_amount = match get(ENV_RECEIVE_MIN_USDC)? {
            None => defaults.minimum_amount,
            Some(value) => parse_decimal(value.trim(), 6)
                .filter(|value| *value > 0)
                .with_context(|| {
                    format!("{ENV_RECEIVE_MIN_USDC} must be positive USDC (at most 6 decimals)")
                })?,
        };
        let daily_lamports = match get(ENV_RECEIVE_DAILY_SOL)? {
            None => defaults.daily_lamports,
            Some(value) => parse_decimal(value.trim(), 9)
                .filter(|value| *value <= i64::MAX as u64)
                .with_context(|| {
                    format!("{ENV_RECEIVE_DAILY_SOL} must be nonnegative SOL (at most 9 decimals)")
                })?,
        };
        let per_address_daily = match get(ENV_RECEIVE_PER_ADDRESS_DAILY)? {
            None => defaults.per_address_daily,
            Some(value) => value.trim().parse::<u32>().with_context(|| {
                format!("{ENV_RECEIVE_PER_ADDRESS_DAILY} must be a nonnegative integer")
            })?,
        };
        let risk_amount = |name, decimals, default| -> anyhow::Result<u64> {
            match get(name)? {
                None => Ok(default),
                Some(value) => parse_decimal(value.trim(), decimals)
                    .filter(|value| *value <= i64::MAX as u64)
                    .with_context(|| format!("{name} is not a valid nonnegative decimal")),
            }
        };
        let burn_minimum_amount = risk_amount(ENV_BURN_MIN_USDC, 6, 5_000_000)?;
        let burn_float_lamports = risk_amount(ENV_BURN_FLOAT_SOL, 9, 500_000_000)?;
        let daily_loss_lamports = risk_amount(ENV_LOSS_DAILY_SOL, 9, 20_000_000)?;
        let unbacked_daily_loss_lamports = risk_amount(ENV_UNBACKED_LOSS_DAILY_SOL, 9, 2_000_000)?;
        let iris_url = get(ENV_IRIS_URL)?.unwrap_or_else(|| DEFAULT_IRIS_URL.into());
        let iris_url = iris_url.trim().trim_end_matches('/').to_string();
        validate_iris_url(&iris_url)?;
        Ok(Some(Self {
            keypair,
            fee_account,
            margin_bps,
            sol_usd_micros,
            iris_url,
            min_lamports,
            burn_minimum_amount,
            burn_float_lamports,
            daily_loss_lamports,
            unbacked_daily_loss_lamports,
            receive: ReceivePolicy {
                minimum_amount,
                daily_lamports,
                per_address_daily,
            },
        }))
    }

    pub fn relayer(&self) -> Pubkey {
        self.keypair.pubkey()
    }

    /// Refuse a relayer key that is also any other role's key, and a fee
    /// account that is the relayer itself or the relayer's own USDC account.
    pub fn check_distinct(&self, other_keys: &[(&str, [u8; 32])]) -> anyhow::Result<()> {
        let relayer = self.relayer().to_bytes();
        for (role, key) in other_keys {
            ensure!(
                relayer != *key,
                "{ENV_KEY} must be a dedicated relay wallet, not the {role}"
            );
        }
        let own_ata = dagon_zkapi_profile::usdc_associated_token_address(&relayer);
        ensure!(
            self.fee_account.to_bytes() != relayer && self.fee_account.to_bytes() != own_ata,
            "{ENV_FEE_ACCOUNT} must not be the relayer or its own USDC account"
        );
        Ok(())
    }
}

/// A JSON keypair file (Solana CLI format) or a base58 64-byte keypair.
fn load_keypair(value: &str) -> anyhow::Result<Keypair> {
    if Path::new(value).is_file() {
        return solana_keypair::read_keypair_file(value)
            .map_err(|_| anyhow::anyhow!("{ENV_KEY} file is not a Solana keypair file"));
    }
    let bytes = bs58::decode(value)
        .into_vec()
        .ok()
        .filter(|bytes| bytes.len() == 64);
    let keypair = bytes
        .as_deref()
        .and_then(|bytes| Keypair::try_from(bytes).ok())
        .with_context(|| {
            format!("{ENV_KEY} must be an existing keypair file or a base58 64-byte keypair")
        })?;
    Ok(keypair)
}

fn parse_pubkey(value: &str, label: &str) -> anyhow::Result<Pubkey> {
    let bytes: [u8; 32] = bs58::decode(value)
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .with_context(|| format!("{label} must be a base58 32-byte account"))?;
    ensure!(bytes != [0; 32], "{label} cannot be the zero account");
    Ok(Pubkey::new_from_array(bytes))
}

/// Parse a non-negative decimal into integer units with `decimals` places.
pub(crate) fn parse_decimal(value: &str, decimals: u32) -> Option<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty() && fraction.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > decimals as usize
    {
        return None;
    }
    let scale = 10u64.checked_pow(decimals)?;
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<u64>().ok()?
    };
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().ok()? * 10u64.pow(decimals - fraction.len() as u32)
    };
    whole.checked_mul(scale)?.checked_add(fraction)
}

/// HTTPS, or plain HTTP only to a loopback host (a local Iris simulator).
fn validate_iris_url(value: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value).with_context(|| format!("{ENV_IRIS_URL} is not a URL"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "{ENV_IRIS_URL} must use https (http only for a loopback simulator)"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none() && url.query().is_none(),
        "{ENV_IRIS_URL} must not carry credentials or a query"
    );
    Ok(())
}

/// The SOL floor in whole lamports for display.
pub fn lamports_to_sol(lamports: u64) -> String {
    format!(
        "{}.{:09}",
        lamports / LAMPORTS_PER_SOL,
        lamports % LAMPORTS_PER_SOL
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(values: &[(&str, &str)]) -> impl Fn(&str) -> anyhow::Result<Option<String>> {
        let map: HashMap<String, String> = values
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |name| Ok(map.get(name).cloned())
    }

    fn base58_keypair() -> (Keypair, String) {
        let keypair = Keypair::new();
        let encoded = bs58::encode(keypair.to_bytes()).into_string();
        (keypair, encoded)
    }

    #[test]
    fn relay_is_off_without_a_key_and_refuses_stray_settings() {
        assert!(RelayConfig::from_lookup(lookup(&[])).unwrap().is_none());
        let error = RelayConfig::from_lookup(lookup(&[(ENV_SOL_USD, "150")])).unwrap_err();
        assert!(error.to_string().contains(ENV_KEY), "{error}");
    }

    #[test]
    fn parses_base58_and_file_keys_with_defaults() {
        let (keypair, encoded) = base58_keypair();
        let fee = Keypair::new().pubkey().to_string();
        let config = RelayConfig::from_lookup(lookup(&[
            (ENV_KEY, &encoded),
            (ENV_FEE_ACCOUNT, &fee),
            (ENV_SOL_USD, "88.89"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(config.relayer(), keypair.pubkey());
        assert_eq!(config.margin_bps, DEFAULT_MARGIN_BPS);
        assert_eq!(config.sol_usd_micros, 88_890_000);
        assert_eq!(config.iris_url, DEFAULT_IRIS_URL);
        assert_eq!(config.min_lamports, DEFAULT_MIN_LAMPORTS);
        assert_eq!(config.receive.minimum_amount, 1_000_000);
        assert_eq!(config.receive.daily_lamports, 50_000_000);
        assert_eq!(config.receive.per_address_daily, 6);
        assert_eq!(config.burn_minimum_amount, 5_000_000);
        assert_eq!(config.burn_float_lamports, 500_000_000);
        assert_eq!(config.daily_loss_lamports, 20_000_000);
        assert_eq!(config.unbacked_daily_loss_lamports, 2_000_000);
        assert!(!format!("{config:?}").contains(&encoded));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relayer.json");
        solana_keypair::write_keypair_file(&keypair, &path).unwrap();
        let config = RelayConfig::from_lookup(lookup(&[
            (ENV_KEY, path.to_str().unwrap()),
            (ENV_FEE_ACCOUNT, &fee),
            (ENV_SOL_USD, "150"),
            (ENV_MARGIN_BPS, "0"),
            (ENV_MIN_SOL, "0.25"),
            (ENV_IRIS_URL, "http://127.0.0.1:18990/"),
            (ENV_RECEIVE_MIN_USDC, "2.5"),
            (ENV_RECEIVE_DAILY_SOL, "0"),
            (ENV_RECEIVE_PER_ADDRESS_DAILY, "3"),
            (ENV_BURN_MIN_USDC, "7.5"),
            (ENV_BURN_FLOAT_SOL, "0.25"),
            (ENV_LOSS_DAILY_SOL, "0.01"),
            (ENV_UNBACKED_LOSS_DAILY_SOL, "0.001"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(config.relayer(), keypair.pubkey());
        assert_eq!(config.margin_bps, 0);
        assert_eq!(config.min_lamports, 250_000_000);
        assert_eq!(config.iris_url, "http://127.0.0.1:18990");
        assert_eq!(config.receive.minimum_amount, 2_500_000);
        assert_eq!(config.receive.daily_lamports, 0);
        assert_eq!(config.receive.per_address_daily, 3);
        assert_eq!(config.burn_minimum_amount, 7_500_000);
        assert_eq!(config.burn_float_lamports, 250_000_000);
        assert_eq!(config.daily_loss_lamports, 10_000_000);
        assert_eq!(config.unbacked_daily_loss_lamports, 1_000_000);
    }

    #[test]
    fn rejects_invalid_settings_without_echoing_secrets() {
        let (_, encoded) = base58_keypair();
        let fee = Keypair::new().pubkey().to_string();
        let base = [
            (ENV_KEY, encoded.as_str()),
            (ENV_FEE_ACCOUNT, fee.as_str()),
            (ENV_SOL_USD, "150"),
        ];
        let with = |name: &'static str, value: &'static str| {
            let mut values = base.to_vec();
            values.retain(|(key, _)| *key != name);
            values.push((name, value));
            RelayConfig::from_lookup(lookup(&values))
        };
        for (name, value) in [
            (ENV_KEY, "not-a-key"),
            (ENV_FEE_ACCOUNT, "11111111111111111111111111111111"),
            (ENV_SOL_USD, "0"),
            (ENV_SOL_USD, "1.1234567"),
            (ENV_SOL_USD, "-5"),
            (ENV_MARGIN_BPS, "10001"),
            (ENV_MIN_SOL, "abc"),
            (ENV_IRIS_URL, "http://iris.example"),
            (ENV_IRIS_URL, "https://user:pw@iris.example"),
        ] {
            let error = with(name, value).unwrap_err().to_string();
            assert!(error.contains(name), "{name}={value}: {error}");
            assert!(!error.contains(&encoded));
        }
        let mut missing = base.to_vec();
        missing.retain(|(key, _)| *key != ENV_SOL_USD);
        assert!(RelayConfig::from_lookup(lookup(&missing)).is_err());
    }

    #[test]
    fn relayer_key_must_be_dedicated() {
        let (keypair, encoded) = base58_keypair();
        let fee = Keypair::new().pubkey().to_string();
        let config = RelayConfig::from_lookup(lookup(&[
            (ENV_KEY, &encoded),
            (ENV_FEE_ACCOUNT, &fee),
            (ENV_SOL_USD, "150"),
        ]))
        .unwrap()
        .unwrap();
        config
            .check_distinct(&[("vault authority", [1; 32])])
            .unwrap();
        let error = config
            .check_distinct(&[("vault authority", keypair.pubkey().to_bytes())])
            .unwrap_err();
        assert!(error.to_string().contains("vault authority"));
        let own_ata =
            dagon_zkapi_profile::usdc_associated_token_address(&keypair.pubkey().to_bytes());
        let config = RelayConfig {
            fee_account: Pubkey::new_from_array(own_ata),
            ..config
        };
        assert!(config.check_distinct(&[]).is_err());
    }

    #[test]
    fn decimals_parse_exactly() {
        assert_eq!(parse_decimal("88.89", 6), Some(88_890_000));
        assert_eq!(parse_decimal(".5", 6), Some(500_000));
        assert_eq!(parse_decimal("7", 9), Some(7_000_000_000));
        assert_eq!(parse_decimal("", 6), None);
        assert_eq!(parse_decimal(".", 6), None);
        assert_eq!(parse_decimal("1e3", 6), None);
        assert_eq!(parse_decimal("99999999999999999999", 6), None);
        assert_eq!(lamports_to_sol(50_000_000), "0.050000000");
    }
}
