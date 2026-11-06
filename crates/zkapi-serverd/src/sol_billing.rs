//! Official Pyth Receiver account adapter; no account type crosses this module.
use std::time::Duration;

use anchor_lang::{AccountDeserialize, Owner};
use base64::Engine;
use pyth_solana_receiver_sdk::price_update::{PriceUpdateV2, VerificationLevel};
use serde_json::{json, Value};

use crate::error::ServerError;
use crate::native_billing::billing::{
    BillingFuture, BillingPriceSource, BillingQuote, SolanaBillingPins, SolanaBillingQuote,
    LAMPORTS_PER_SOL, PYTH_SOURCE, SOL_USD_FEED_ID,
};

#[derive(Debug, Clone)]
pub struct PythBillingConfig {
    pub price_account: String,
    pub receiver_program: String,
    pub feed_id: String,
    pub max_age_seconds: u64,
    pub max_confidence_bps: u16,
}

pub fn parse_solana_identity(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes: [u8; 32] = bs58::decode(value)
        .into_vec()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to 32 bytes"))?;
    anyhow::ensure!(
        bytes != [0; 32] && bs58::encode(bytes).into_string() == value,
        "{name} must be a nonzero canonical base58 identity"
    );
    Ok(bytes)
}

impl PythBillingConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        parse_solana_identity("Pyth price account", &self.price_account)?;
        let owner = parse_solana_identity("Pyth receiver", &self.receiver_program)?;
        anyhow::ensure!(
            owner == PriceUpdateV2::owner().to_bytes(),
            "unsupported Pyth receiver program"
        );
        anyhow::ensure!(
            self.feed_id == SOL_USD_FEED_ID,
            "Pyth feed must be the pinned SOL/USD feed"
        );
        anyhow::ensure!(
            (1..=60).contains(&self.max_age_seconds),
            "Pyth max age must be in 1..=60 seconds"
        );
        anyhow::ensure!(
            (1..=100).contains(&self.max_confidence_bps),
            "Pyth max confidence must be in 1..=100 bps"
        );
        Ok(())
    }
}

pub struct PythBillingOracle {
    rpc_url: String,
    genesis_hash: [u8; 32],
    pins: SolanaBillingPins,
    http: reqwest::Client,
}

impl PythBillingOracle {
    pub fn new(
        rpc_url: String,
        genesis_hash: [u8; 32],
        config: PythBillingConfig,
        mut pins: SolanaBillingPins,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        let url = reqwest::Url::parse(&rpc_url)?;
        anyhow::ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))),
            "Pyth RPC requires HTTPS or loopback HTTP"
        );
        anyhow::ensure!(
            url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
            "Pyth RPC cannot contain credentials or a fragment"
        );
        anyhow::ensure!(
            genesis_hash != [0; 32],
            "Pyth requires a pinned genesis hash"
        );
        pins.feed_account = config.price_account;
        pins.receiver_program = config.receiver_program;
        pins.max_age_seconds = config.max_age_seconds;
        pins.max_confidence_bps = config.max_confidence_bps;
        Ok(Self {
            rpc_url,
            genesis_hash,
            pins,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, ServerError> {
        let mut response = self
            .http
            .post(&self.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| invalid("Pyth finalized RPC unavailable"))?;
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > 65_536)
        {
            return Err(invalid("Pyth RPC rejected the read"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| invalid("Pyth RPC body unavailable"))?
        {
            if body.len().saturating_add(chunk.len()) > 65_536 {
                return Err(invalid("Pyth RPC response too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let response: Value =
            serde_json::from_slice(&body).map_err(|_| invalid("invalid Pyth RPC response"))?;
        if response["jsonrpc"] != "2.0"
            || response["id"].as_u64() != Some(1)
            || response.get("error").is_some()
        {
            return Err(invalid("Pyth RPC response identity/error mismatch"));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| invalid("missing Pyth RPC result"))
    }

    async fn finalized_quote(&self, now: u64) -> Result<SolanaBillingQuote, ServerError> {
        let genesis = self.rpc("getGenesisHash", json!([])).await?;
        let actual = genesis
            .as_str()
            .ok_or_else(|| invalid("invalid Pyth cluster identity"))?;
        if parse_solana_identity("Pyth cluster", actual)
            .map_err(|_| invalid("invalid Pyth cluster identity"))?
            != self.genesis_hash
        {
            return Err(invalid("Pyth RPC returned the wrong cluster"));
        }
        let result = self
            .rpc(
                "getAccountInfo",
                json!([self.pins.feed_account,
            {"encoding":"base64","commitment":"finalized"}]),
            )
            .await?;
        self.decode_quote(&result, now)
    }

    fn decode_quote(&self, result: &Value, now: u64) -> Result<SolanaBillingQuote, ServerError> {
        let slot = result["context"]["slot"]
            .as_u64()
            .ok_or_else(|| invalid("Pyth context slot missing"))?;
        let account = &result["value"];
        if account["owner"].as_str() != Some(&self.pins.receiver_program)
            || account["executable"].as_bool() != Some(false)
        {
            return Err(invalid("Pyth price account owner/executable mismatch"));
        }
        let data = account["data"]
            .as_array()
            .filter(|data| data.len() == 2 && data[1] == "base64")
            .and_then(|data| data[0].as_str())
            .ok_or_else(|| invalid("Pyth account encoding mismatch"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| invalid("Pyth account base64 invalid"))?;
        if bytes.len() != PriceUpdateV2::LEN {
            return Err(invalid("Pyth account size mismatch"));
        }
        let update = PriceUpdateV2::try_deserialize(&mut bytes.as_slice())
            .map_err(|_| invalid("Pyth account discriminator/decoding failed"))?;
        // The official decoder checks its discriminator. Serialize with the
        // official type and verify the allocated account's remaining padding.
        let mut canonical = Vec::new();
        anchor_lang::AccountSerialize::try_serialize(&update, &mut canonical)
            .map_err(|_| invalid("Pyth account serialization failed"))?;
        if !bytes.starts_with(&canonical) || bytes[canonical.len()..].iter().any(|byte| *byte != 0)
        {
            return Err(invalid("noncanonical Pyth account data"));
        }
        let feed: [u8; 32] = hex::decode(SOL_USD_FEED_ID.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        if update.verification_level != VerificationLevel::Full
            || update.price_message.feed_id != feed
            || update.posted_slot > slot
        {
            return Err(invalid("Pyth feed/verification/slot mismatch"));
        }
        let quote = SolanaBillingQuote {
            asset: "native_sol".into(),
            source: PYTH_SOURCE.into(),
            credit_unit: "lamports".into(),
            base_units_per_asset: LAMPORTS_PER_SOL,
            chain_id: self.pins.chain_id.to_string(),
            deployment_binding: self.pins.deployment_binding,
            backend: self.pins.backend.clone(),
            network: self.pins.network.clone(),
            vault: self.pins.vault.clone(),
            feed_id: SOL_USD_FEED_ID.into(),
            feed_account: self.pins.feed_account.clone(),
            receiver_program: self.pins.receiver_program.clone(),
            price: update.price_message.price.to_string(),
            exponent: update.price_message.exponent,
            confidence: update.price_message.conf.to_string(),
            publish_time: u64::try_from(update.price_message.publish_time)
                .map_err(|_| invalid("negative Pyth publish time"))?,
            expires_at: u64::try_from(update.price_message.publish_time)
                .ok()
                .and_then(|time| time.checked_add(self.pins.max_age_seconds))
                .ok_or_else(|| invalid("Pyth expiry overflow"))?,
            posted_slot: update.posted_slot,
        };
        quote.validate_identity(&self.pins)?;
        BillingQuote::NativeSol(quote.clone()).assert_fresh(now)?;
        Ok(quote)
    }
}

impl BillingPriceSource for PythBillingOracle {
    fn quote(&self, now: u64) -> BillingFuture<'_, BillingQuote> {
        Box::pin(async move { self.finalized_quote(now).await.map(BillingQuote::NativeSol) })
    }
    fn validate_identity(&self, quote: &BillingQuote) -> Result<(), ServerError> {
        match quote {
            BillingQuote::NativeSol(quote) => quote.validate_identity(&self.pins),
            BillingQuote::NativeEth(_) => Err(invalid("ETH quote cannot use the SOL oracle")),
        }
    }
    fn validate<'a>(&'a self, quote: &'a BillingQuote, now: u64) -> BillingFuture<'a, ()> {
        Box::pin(async move {
            self.assert_fresh(quote, now)?;
            let current = BillingQuote::NativeSol(self.finalized_quote(now).await?);
            if &current != quote {
                return Err(ServerError::NativeQuoteSuperseded);
            }
            Ok(())
        })
    }
}

fn invalid(message: &str) -> ServerError {
    ServerError::InvalidRequest(message.into())
}
