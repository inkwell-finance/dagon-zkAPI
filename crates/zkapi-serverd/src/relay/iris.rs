//! Minimal Circle Iris (attestation API) client.

use serde_json::Value;

const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// One attested (or pending) CCTP message of a source transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrisMessage {
    pub message: Vec<u8>,
    /// `None` while Iris reports the attestation as pending.
    pub attestation: Option<Vec<u8>>,
    pub complete: bool,
}

#[derive(Clone)]
pub struct IrisClient {
    base_url: String,
    http: reqwest::Client,
}

impl IrisClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    /// `GET /v2/messages/{source_domain}?transactionHash=…`; a 404 (not yet
    /// indexed or unknown) is an empty list.
    pub async fn messages(
        &self,
        source_domain: u32,
        transaction_hash: &str,
    ) -> anyhow::Result<Vec<IrisMessage>> {
        let url = format!("{}/v2/messages/{source_domain}", self.base_url);
        let mut response = self
            .http
            .get(url)
            .query(&[("transactionHash", transaction_hash)])
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        anyhow::ensure!(
            response.status().is_success(),
            "Iris returned {}",
            response.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                body.len() + chunk.len() <= MAX_RESPONSE_BYTES,
                "Iris response exceeds the relay limit"
            );
            body.extend_from_slice(&chunk);
        }
        parse_messages(&serde_json::from_slice(&body)?)
    }
}

pub(crate) fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(value).ok()
}

fn parse_messages(body: &Value) -> anyhow::Result<Vec<IrisMessage>> {
    let messages = body["messages"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Iris response has no messages array"))?;
    messages
        .iter()
        .map(|entry| {
            let message = entry["message"]
                .as_str()
                .and_then(decode_hex)
                .ok_or_else(|| anyhow::anyhow!("Iris message is not hex"))?;
            let attestation = entry["attestation"]
                .as_str()
                .filter(|value| *value != "PENDING")
                .map(|value| {
                    decode_hex(value).ok_or_else(|| anyhow::anyhow!("Iris attestation is not hex"))
                })
                .transpose()?
                .filter(|bytes| !bytes.is_empty());
            Ok(IrisMessage {
                message,
                attestation,
                complete: entry["status"].as_str() == Some("complete"),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_and_pending_messages() {
        let body = serde_json::json!({"messages": [
            {"message": "0x0102", "attestation": "0xaabb", "status": "complete"},
            {"message": "0x03", "attestation": "PENDING", "status": "pending_confirmations"},
        ]});
        assert_eq!(
            parse_messages(&body).unwrap(),
            vec![
                IrisMessage {
                    message: vec![1, 2],
                    attestation: Some(vec![0xaa, 0xbb]),
                    complete: true
                },
                IrisMessage {
                    message: vec![3],
                    attestation: None,
                    complete: false
                },
            ]
        );
        assert!(parse_messages(&serde_json::json!({"error": "x"})).is_err());
        assert!(parse_messages(&serde_json::json!({"messages": [{"message": "zz"}]})).is_err());
    }
}
