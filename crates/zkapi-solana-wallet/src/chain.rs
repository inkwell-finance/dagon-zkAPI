//! Minimal Solana JSON-RPC client: reads, signature tracking and idempotent transaction submission.

use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program::{hash::Hash, instruction::Instruction, pubkey::Pubkey};
use solana_signer::Signer;
use std::{str::FromStr, time::Duration};

/// An error with a stable, enumerable code. The client (zkapi-clientd) never sees the message text, only the code, because
/// text can echo protocol values.
#[derive(Debug)]
pub struct Coded {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for Coded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Coded {}

pub fn coded(code: &'static str, message: impl Into<String>) -> anyhow::Error {
    Coded { code, message: message.into() }.into()
}

pub struct Chain {
    pub rpc: String,
    http: reqwest::Client,
}

/// How far a transaction got, as the RPC reports it.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Progress {
    Unknown,
    Processed,
    Confirmed,
    Finalized,
}

pub struct SignatureStatus {
    pub progress: Progress,
    pub failed: bool,
}

/// https, or http to a literal loopback address (a local validator). No credentials, query or fragment.
pub fn trusted_rpc_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("invalid RPC URL")?;
    ensure!(
        url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none(),
        "the RPC URL must not carry credentials, a query or a fragment"
    );
    let loopback = matches!(url.host_str(), Some("127.0.0.1") | Some("[::1]"));
    ensure!(url.scheme() == "https" || (url.scheme() == "http" && loopback), "the RPC must be HTTPS or numeric-loopback HTTP");
    Ok(())
}

impl Chain {
    pub fn new(rpc: &str) -> Result<Self> {
        trusted_rpc_url(rpc)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self { rpc: rpc.to_string(), http })
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let response: Value = self
            .http
            .post(&self.rpc)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        rpc_result(&response, method)
    }

    #[cfg_attr(not(feature = "dev"), allow(dead_code))]
    pub async fn blockhash(&self) -> Result<Hash> {
        let result = self.call("getLatestBlockhash", json!([{"commitment":"confirmed"}])).await?;
        Ok(Hash::from_str(result["value"]["blockhash"].as_str().context("blockhash")?)?)
    }

    pub async fn finalized_height(&self) -> Result<u64> {
        self.call("getBlockHeight", json!([{"commitment":"finalized"}])).await?.as_u64().context("block height")
    }

    #[cfg_attr(not(feature = "dev"), allow(dead_code))]
    pub async fn lamports(&self, address: &Pubkey, commitment: &str) -> Result<u64> {
        let result = self.call("getBalance", json!([address.to_string(), {"commitment":commitment}])).await?;
        result["value"].as_u64().context("balance")
    }

    pub async fn status(&self, signature: &str) -> Result<SignatureStatus> {
        let status = self.call("getSignatureStatuses", json!([[signature], {"searchTransactionHistory":true}])).await?;
        decode_signature_status(&status)
    }

    /// Wait until the signature reached `finalized` (or at least `confirmed`). A failed transaction is an error.
    pub async fn wait(&self, signature: &str, finalized: bool) -> Result<()> {
        for _ in 0..800 {
            let status = self.status(signature).await?;
            if status.failed && status.progress == Progress::Finalized {
                return Err(coded("transaction_failed", format!("transaction {signature} failed on chain")));
            }
            if !status.failed && (status.progress == Progress::Finalized || (!finalized && status.progress == Progress::Confirmed)) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!("transaction {signature} was not {}", if finalized { "finalized" } else { "confirmed" })
    }

    /// Submit an already signed transaction (base64) and require the RPC to echo its signature.
    pub async fn send_signed(&self, transaction_b64: &str, signature: &str) -> Result<()> {
        match self
            .call(
                "sendTransaction",
                json!([transaction_b64, {"encoding":"base64","skipPreflight":false,"preflightCommitment":"confirmed"}]),
            )
            .await
        {
            Ok(value) => {
                ensure!(value.as_str() == Some(signature), "the RPC returned a different transaction signature");
                Ok(())
            }
            // A retried send of a transaction that already landed is success, not failure.
            Err(error) if error.to_string().contains("already been processed") => Ok(()),
            Err(error) => Err(error),
        }
    }

    #[cfg_attr(not(feature = "dev"), allow(dead_code))]
    pub async fn send_message(&self, message: Vec<u8>, signer: &Keypair, finalized: bool) -> Result<String> {
        let signature = signer.sign_message(&message);
        let mut transaction = vec![1u8];
        transaction.extend_from_slice(signature.as_ref());
        transaction.extend_from_slice(&message);
        let encoded = base64::engine::general_purpose::STANDARD.encode(transaction);
        let signature = signature.to_string();
        self.send_signed(&encoded, &signature).await?;
        self.wait(&signature, finalized).await?;
        Ok(signature)
    }

    #[cfg_attr(not(feature = "dev"), allow(dead_code))]
    pub async fn send_instructions(&self, instructions: &[Instruction], signer: &Keypair, finalized: bool) -> Result<String> {
        let message = Message::new_with_blockhash(instructions, Some(&signer.pubkey()), &self.blockhash().await?);
        self.send_message(message.serialize(), signer, finalized).await
    }

    /// The account's owner and data at `commitment`, or `None` when it does not exist.
    pub async fn account(&self, address: &Pubkey, commitment: &str) -> Result<Option<(Pubkey, Vec<u8>)>> {
        let result = self
            .call("getAccountInfo", json!([address.to_string(), {"encoding":"base64","commitment":commitment}]))
            .await?;
        decode_account(&result)
    }
}

// Missing fields are malformed replies, never proof of account absence or an unseen transaction.
fn rpc_result(response: &Value, method: &str) -> Result<Value> {
    ensure!(response["jsonrpc"].as_str() == Some("2.0") && response["id"].as_u64() == Some(1), "invalid JSON-RPC envelope");
    ensure!(response.get("error").is_none_or(Value::is_null), "RPC {method}: {}", response["error"]);
    Ok(response.get("result").context("missing RPC result")?.clone())
}

fn decode_signature_status(status: &Value) -> Result<SignatureStatus> {
    let rows = status.get("value").and_then(Value::as_array).context("missing signature statuses")?;
    ensure!(rows.len() == 1, "expected exactly one signature status");
    let value = &rows[0];
    if value.is_null() { return Ok(SignatureStatus { progress: Progress::Unknown, failed: false }); }
    let progress = match value["confirmationStatus"].as_str() {
        Some("finalized") => Progress::Finalized,
        Some("confirmed") => Progress::Confirmed,
        Some("processed") => Progress::Processed,
        _ => bail!("invalid signature confirmation status"),
    };
    let err = value.get("err").context("missing signature error field")?;
    ensure!(err.is_null() || err.is_object() || err.as_str().is_some_and(|text| !text.is_empty()), "invalid signature error field");
    Ok(SignatureStatus { progress, failed: !err.is_null() })
}

fn decode_account(result: &Value) -> Result<Option<(Pubkey, Vec<u8>)>> {
    let value = result.get("value").context("missing account value")?;
    if value.is_null() { return Ok(None); }
    let data = value.get("data").and_then(Value::as_array).context("account data")?;
    ensure!(data.len() == 2 && data[1].as_str() == Some("base64"), "invalid account data encoding");
    let bytes = data[0].as_str().context("account data bytes")?;
    let owner = Pubkey::from_str(value["owner"].as_str().context("account owner")?)?;
    Ok(Some((owner, base64::engine::general_purpose::STANDARD.decode(bytes)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_numeric_loopback_rpcs_are_trusted() {
        for good in ["https://api.mainnet-beta.solana.com", "http://127.0.0.1:8899", "http://127.0.0.1:8899/"] {
            trusted_rpc_url(good).unwrap_or_else(|error| panic!("{good}: {error}"));
        }
        for bad in [
            "http://api.mainnet-beta.solana.com",
            "http://localhost:8899",
            "ftp://127.0.0.1",
            "https://user:pass@rpc.example",
            "https://rpc.example/?api-key=1",
            "https://rpc.example/#x",
            "not a url",
        ] {
            assert!(trusted_rpc_url(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn coded_errors_keep_their_code_through_anyhow() {
        let error = coded("blockhash_expired", "late");
        assert_eq!(error.downcast_ref::<Coded>().map(|c| c.code), Some("blockhash_expired"));
        assert_eq!(error.to_string(), "blockhash_expired: late");
    }
}

#[cfg(test)]
mod strict_rpc_tests {
    use super::*;
    #[test]
    fn missing_rpc_fields_never_mean_account_absence() {
        for reply in [json!({}), json!({"jsonrpc":"2.0","id":1}), json!({"jsonrpc":"2.0","id":2,"result":{}})] {
            assert!(rpc_result(&reply,"getAccountInfo").is_err());
        }
        for result in [json!({}), json!(null), json!({"value":{}}), json!({"value":{"data":["","base58"],"owner":Pubkey::new_unique().to_string()}})] {
            assert!(decode_account(&result).is_err());
        }
        assert!(decode_account(&json!({"value":null})).unwrap().is_none());
    }
    #[test]
    fn malformed_signature_replies_cannot_expire_an_operation() {
        for result in [json!({}),json!({"value":[]}),json!({"value":[null,null]}),json!({"value":[{}]}),json!({"value":[{"confirmationStatus":"future","err":null}]}),json!({"value":[{"confirmationStatus":"finalized"}]})] {
            assert!(decode_signature_status(&result).is_err());
        }
        let failed = decode_signature_status(&json!({"value":[{"confirmationStatus":"finalized","err":"BlockhashNotFound"}]})).unwrap();
        assert!(failed.failed);
        assert_eq!(decode_signature_status(&json!({"value":[null]})).unwrap().progress,Progress::Unknown);
        assert_eq!(decode_signature_status(&json!({"value":[{"confirmationStatus":"finalized","err":null}]})).unwrap().progress,Progress::Finalized);
    }
}

#[cfg(test)]
mod finality_tests {
    use super::*;
    use std::io::{Read, Write};
    // The RPC can report a provisional failure, then a finalized success after a fork switch.
    fn rpc_sequence(rows: Vec<Value>) -> (Chain, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let chain = Chain::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let thread = std::thread::spawn(move || {
            for row in rows {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "wallet stopped polling before a finalized outcome");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("mock RPC accept: {error}"),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") { stream.read_exact(&mut byte).unwrap(); request.push(byte[0]); }
                let length = String::from_utf8_lossy(&request).lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                }).unwrap();
                stream.read_exact(&mut vec![0;length]).unwrap();
                let body = json!({"jsonrpc":"2.0","id":1,"result":{"value":[row]}}).to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(),body).unwrap();
            }
        });
        (chain,thread)
    }
    #[tokio::test]
    async fn provisional_failure_waits_for_finalized_outcome() {
        for final_error in [Value::Null, json!("AccountInUse")] {
            let (chain,thread) = rpc_sequence(vec![
                json!({"confirmationStatus":"processed","err":"AccountInUse"}),
                json!({"confirmationStatus":"confirmed","err":"AccountInUse"}),
                json!({"confirmationStatus":"finalized","err":final_error}),
            ]);
            // Even a caller accepting confirmed success must wait for a failed transaction to finalize.
            let result = chain.wait("test-signature",false).await;
            if final_error.is_null() { assert!(result.is_ok()); }
            else { assert_eq!(result.unwrap_err().downcast_ref::<Coded>().unwrap().code,"transaction_failed"); }
            thread.join().unwrap();
        }
    }
}
