//! Stateless submit tickets.
//!
//! A prepare returns an unsigned transaction and a ticket: an HMAC-sealed
//! record of the exact message the relay built and the risk it implies. The
//! relay signs and reserves only when the ek-signed transaction is submitted
//! back with its ticket, so a prepare that is never submitted holds no float
//! or loss budget.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_keypair::Keypair;
use subtle::ConstantTimeEq;

const DOMAIN: &[u8] = b"dagon-zkapi/relay-ticket/v1";
const EVENT_DOMAIN: &[u8] = b"dagon-zkapi/relay-event/v1";
/// A ticket never needs to be larger than this (it carries no transaction).
pub const MAX_TOKEN_LEN: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TicketKind {
    Deposit,
    Burn,
    Sweep,
    Close,
    Escape,
}

/// The `MessageSent` account of a burn: its keypair is re-derived from
/// `nonce` at submit, so the client never learns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketEvent {
    pub nonce: String,
    pub address: String,
    pub rent: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub kind: TicketKind,
    /// Hex SHA-256 of the exact message bytes the relay prepared.
    pub message: String,
    pub owner: String,
    pub source: String,
    pub last_valid_height: u64,
    /// Address of the lookup table of a v0 transaction.
    pub table: Option<String>,
    pub event: Option<TicketEvent>,
    /// Sponsorship credential covering a failure of this transaction.
    pub backing: Option<String>,
}

/// HMAC-SHA256 keyed by the relay's secret; tickets of another relay key
/// (or a restarted relay with a new key) are refused.
pub struct TicketKey([u8; 32]);

impl TicketKey {
    pub fn new(relayer: &Keypair) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(relayer.secret_bytes());
        Self(hasher.finalize().into())
    }

    fn mac(&self, domain: &[u8], data: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&self.0);
        let pad = |byte: u8| key.map(|value| value ^ byte);
        let inner = Sha256::new()
            .chain_update(pad(0x36))
            .chain_update(domain)
            .chain_update(data)
            .finalize();
        Sha256::new()
            .chain_update(pad(0x5c))
            .chain_update(inner)
            .finalize()
            .into()
    }

    pub fn seal(&self, ticket: &Ticket) -> String {
        let body = serde_json::to_vec(ticket).expect("a ticket always serializes");
        format!(
            "{}.{}",
            hex::encode(&body),
            hex::encode(self.mac(DOMAIN, &body))
        )
    }

    pub fn open(&self, token: &str) -> Option<Ticket> {
        if token.len() > MAX_TOKEN_LEN {
            return None;
        }
        let (body, mac) = token.split_once('.')?;
        let body = hex::decode(body).ok()?;
        let mac = hex::decode(mac).ok()?;
        if !bool::from(self.mac(DOMAIN, &body).ct_eq(mac.as_slice())) {
            return None;
        }
        serde_json::from_slice(&body).ok()
    }

    /// The burn event keypair of a ticket nonce.
    pub fn event_keypair(&self, nonce: &str) -> Option<Keypair> {
        let nonce = hex::decode(nonce).ok().filter(|nonce| nonce.len() == 32)?;
        Some(Keypair::new_from_array(self.mac(EVENT_DOMAIN, &nonce)))
    }
}

/// Hex SHA-256 of a message.
pub fn message_digest(message: &[u8]) -> String {
    hex::encode(Sha256::digest(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_signer::Signer;

    fn ticket() -> Ticket {
        Ticket {
            kind: TicketKind::Burn,
            message: message_digest(b"message"),
            owner: "ek".into(),
            source: "ata".into(),
            last_valid_height: 9,
            table: None,
            event: Some(TicketEvent {
                nonce: hex::encode([5; 32]),
                address: "event".into(),
                rent: 7,
            }),
            backing: Some("note:1".into()),
        }
    }

    #[test]
    fn tickets_are_sealed_by_the_relay_key() {
        let relayer = Keypair::new();
        let key = TicketKey::new(&relayer);
        let token = key.seal(&ticket());
        assert_eq!(key.open(&token), Some(ticket()));
        assert!(TicketKey::new(&Keypair::new()).open(&token).is_none());
        let (body, mac) = token.split_once('.').unwrap();
        let mut forged = ticket();
        forged.event.as_mut().unwrap().rent = 0;
        let forged_body = hex::encode(serde_json::to_vec(&forged).unwrap());
        assert!(key.open(&format!("{forged_body}.{mac}")).is_none());
        assert!(key.open(&format!("{body}.{}", &mac[2..])).is_none());
        assert!(key.open(body).is_none());
        assert!(key.open(&"0".repeat(MAX_TOKEN_LEN + 1)).is_none());
        let first = key.event_keypair(&hex::encode([5; 32])).unwrap();
        assert_eq!(
            first.pubkey(),
            key.event_keypair(&hex::encode([5; 32])).unwrap().pubkey()
        );
        assert_ne!(
            first.pubkey(),
            key.event_keypair(&hex::encode([6; 32])).unwrap().pubkey()
        );
        assert!(key.event_keypair("05").is_none());
    }
}
