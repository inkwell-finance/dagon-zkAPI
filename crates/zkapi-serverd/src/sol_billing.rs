//! Official Pyth Receiver account adapter; no account type crosses this module.
//!
//! The SOL/USD price account updates every few seconds while a request proof
//! takes longer than that to build, so a quote cannot be required to still be
//! the latest finalized update when the request arrives. Instead the oracle
//! remembers every quote it has itself decoded from the finalized account
//! until that quote expires, and accepts a fresh quote it observed.
use std::sync::Mutex;
use std::time::Duration;

use anchor_lang::{AccountDeserialize, Owner};
use base64::Engine;
use pyth_solana_receiver_sdk::price_update::{PriceUpdateV2, VerificationLevel};
use serde_json::{json, Value};

use crate::billing::{
    BillingFuture, BillingPins, BillingPriceSource, BillingQuote, LAMPORTS_PER_SOL, PYTH_SOURCE,
};
use crate::config::ServerConfig;
use crate::error::ServerError;

/// Bound on remembered quotes. At one update per second and a 60 s maximum
/// age, live quotes never exceed this; on overflow the oldest is forgotten.
const MAX_OBSERVED_QUOTES: usize = 256;

/// Quotes this process decoded from the finalized price account, kept until
/// they expire.
#[derive(Default)]
struct ObservedQuotes(Vec<BillingQuote>);

impl ObservedQuotes {
    fn prune(&mut self, now: u64) {
        self.0.retain(|quote| quote.expires_at > now);
    }

    fn record(&mut self, quote: &BillingQuote, now: u64) {
        self.prune(now);
        if quote.expires_at <= now || self.0.contains(quote) {
            return;
        }
        if self.0.len() == MAX_OBSERVED_QUOTES {
            self.0.remove(0);
        }
        self.0.push(quote.clone());
    }

    fn contains(&mut self, quote: &BillingQuote, now: u64) -> bool {
        self.prune(now);
        self.0.contains(quote)
    }
}

pub struct PythBillingOracle {
    rpc_url: String,
    genesis_hash: [u8; 32],
    pins: BillingPins,
    feed_id: [u8; 32],
    http: reqwest::Client,
    observed: Mutex<ObservedQuotes>,
}

impl PythBillingOracle {
    /// The oracle for the configured deployment. Makes no network request.
    pub fn new(config: &ServerConfig) -> anyhow::Result<Self> {
        let pins = config.billing_pins();
        anyhow::ensure!(
            config.profile.pyth_receiver_program() == PriceUpdateV2::owner().to_bytes(),
            "the profile's Pyth receiver is not the official receiver program"
        );
        let feed_id: [u8; 32] = hex::decode(
            pins.feed_id
                .strip_prefix("0x")
                .ok_or_else(|| anyhow::anyhow!("Pyth feed ID must be 0x-prefixed"))?,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Pyth feed ID must be 32 bytes"))?;
        let url = reqwest::Url::parse(&config.rpc_url)?;
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
        Ok(Self {
            rpc_url: config.rpc_url.clone(),
            genesis_hash: config.identity.genesis_hash,
            pins,
            feed_id,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            observed: Mutex::new(ObservedQuotes::default()),
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

    /// Read, authenticate and remember the latest finalized quote.
    async fn finalized_quote(&self, now: u64) -> Result<BillingQuote, ServerError> {
        let genesis = self.rpc("getGenesisHash", json!([])).await?;
        let actual = genesis
            .as_str()
            .and_then(|value| dagon_zkapi_profile::parse_base58_32("Pyth cluster", value).ok())
            .ok_or_else(|| invalid("invalid Pyth cluster identity"))?;
        if actual != self.genesis_hash {
            return Err(invalid("Pyth RPC returned the wrong cluster"));
        }
        let result = self
            .rpc(
                "getAccountInfo",
                json!([self.pins.feed_account,
            {"encoding":"base64","commitment":"finalized"}]),
            )
            .await?;
        let quote = self.decode_quote(&result, now)?;
        self.observed
            .lock()
            .expect("observed quote lock")
            .record(&quote, now);
        Ok(quote)
    }

    fn decode_quote(&self, result: &Value, now: u64) -> Result<BillingQuote, ServerError> {
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
        if update.verification_level != VerificationLevel::Full
            || update.price_message.feed_id != self.feed_id
            || update.posted_slot > slot
        {
            return Err(invalid("Pyth feed/verification/slot mismatch"));
        }
        let publish_time = u64::try_from(update.price_message.publish_time)
            .map_err(|_| invalid("negative Pyth publish time"))?;
        let quote = BillingQuote {
            asset: "native_sol".into(),
            source: PYTH_SOURCE.into(),
            credit_unit: "lamports".into(),
            base_units_per_asset: LAMPORTS_PER_SOL,
            chain_id: self.pins.chain_id.to_string(),
            deployment_binding: self.pins.deployment_binding,
            backend: self.pins.backend.clone(),
            network: self.pins.network.clone(),
            vault: self.pins.vault.clone(),
            feed_id: self.pins.feed_id.clone(),
            feed_account: self.pins.feed_account.clone(),
            receiver_program: self.pins.receiver_program.clone(),
            price: update.price_message.price.to_string(),
            exponent: update.price_message.exponent,
            confidence: update.price_message.conf.to_string(),
            publish_time,
            expires_at: publish_time
                .checked_add(self.pins.max_age_seconds)
                .ok_or_else(|| invalid("Pyth expiry overflow"))?,
            posted_slot: update.posted_slot,
        };
        quote.validate_identity(&self.pins)?;
        quote.assert_fresh(now)?;
        Ok(quote)
    }

    fn was_observed(&self, quote: &BillingQuote, now: u64) -> bool {
        self.observed
            .lock()
            .expect("observed quote lock")
            .contains(quote, now)
    }
}

impl BillingPriceSource for PythBillingOracle {
    fn quote(&self, now: u64) -> BillingFuture<'_, BillingQuote> {
        Box::pin(self.finalized_quote(now))
    }

    fn validate_identity(&self, quote: &BillingQuote) -> Result<(), ServerError> {
        quote.validate_identity(&self.pins)
    }

    /// Accept a fresh quote this oracle decoded from the finalized account,
    /// even if a newer update has since been published. A quote it has not
    /// observed (e.g. one fetched before a restart) is accepted only if it is
    /// the current finalized update; any other quote is superseded.
    fn validate<'a>(&'a self, quote: &'a BillingQuote, now: u64) -> BillingFuture<'a, ()> {
        Box::pin(async move {
            self.assert_fresh(quote, now)?;
            if self.was_observed(quote, now) || &self.finalized_quote(now).await? == quote {
                Ok(())
            } else {
                Err(ServerError::NativeQuoteSuperseded)
            }
        })
    }
}

fn invalid(message: &str) -> ServerError {
    ServerError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(publish_time: u64, price: &str) -> BillingQuote {
        BillingQuote {
            asset: "native_sol".into(),
            source: PYTH_SOURCE.into(),
            credit_unit: "lamports".into(),
            base_units_per_asset: LAMPORTS_PER_SOL,
            chain_id: "7".into(),
            deployment_binding: zkapi_types::Felt252::from_u64(8),
            backend: "dagon.solana.groth16.v1".into(),
            network: "localnet".into(),
            vault: "vault".into(),
            feed_id: "0x01".into(),
            feed_account: "price".into(),
            receiver_program: "receiver".into(),
            price: price.into(),
            exponent: -8,
            confidence: "0".into(),
            publish_time,
            expires_at: publish_time + 30,
            posted_slot: publish_time,
        }
    }

    #[test]
    fn an_older_observed_quote_stays_known_after_a_newer_update() {
        let mut observed = ObservedQuotes::default();
        let older = quote(100, "15000000000");
        let newer = quote(102, "15100000000");
        observed.record(&older, 101);
        observed.record(&newer, 103);
        assert!(observed.contains(&older, 104));
        assert!(observed.contains(&newer, 104));
    }

    #[test]
    fn unobserved_mutated_and_expired_quotes_are_unknown() {
        let mut observed = ObservedQuotes::default();
        let seen = quote(100, "15000000000");
        observed.record(&seen, 101);
        assert!(!observed.contains(&quote(101, "15000000000"), 102));
        let mut mutated = seen.clone();
        mutated.price = "16000000000".into();
        assert!(!observed.contains(&mutated, 102));
        mutated = seen.clone();
        mutated.posted_slot += 1;
        assert!(!observed.contains(&mutated, 102));
        // Expiry forgets the quote; an already expired quote is never kept.
        assert!(!observed.contains(&seen, 130));
        observed.record(&seen, 130);
        assert!(observed.0.is_empty());
    }

    #[test]
    fn observed_quotes_are_bounded() {
        let mut observed = ObservedQuotes::default();
        for second in 0..(MAX_OBSERVED_QUOTES as u64 + 10) {
            observed.record(&quote(1_000, &(15_000_000_000 + second).to_string()), 1_001);
        }
        assert_eq!(observed.0.len(), MAX_OBSERVED_QUOTES);
        assert!(!observed.contains(&quote(1_000, "15000000000"), 1_001));
    }
}
