//! Live dashboard feed for the zkAPI server.
//!
//! Events expose lease authorizations, proof bindings, aggregate upstream cost,
//! USDC settlement, and signed state transitions. Inference prompts stay
//! between the client and its leased upstream key. This bounded feed is
//! observability only and does not affect protocol state.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::broadcast;
use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

use crate::settlement::UsageInfo;

/// One fully-detailed request as the server saw it.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub client_request_id: String,
    pub billing_label: String,

    // --- zk authentication / payment proof ---
    pub request_nullifier: Felt252,
    pub active_root: Felt252,
    pub anon_commitment: CurvePointWire,
    pub solvency_bound: u128,
    pub solvency_bound_usd: f64,
    pub proof_backend: String,
    pub proof_public_output_hash: Felt252,
    pub proof_size_bytes: usize,

    // --- prompt-free lease authorization ---
    pub request_raw: String,

    // --- upstream response ---
    pub response_code: u16,
    pub response_text: String,
    pub response_hash: Felt252,

    // --- aggregate upstream cost and USDC billing ---
    pub usage: Option<UsageInfo>,
    /// Charge in USDC base units (micro-USDC).
    pub charge_applied: u128,
    pub charge_usd: f64,

    // --- next state the server signed ---
    pub next_commitment: CurvePointWire,
    pub next_anchor: Felt252,
    pub blind_delta_srv: Felt252,

    // --- timing ---
    pub upstream_ms: u64,
    pub total_ms: u64,
}

/// Running totals across all requests seen this process lifetime.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DashboardTotals {
    pub request_count: u64,
    pub total_micro_usdc_charged: u128,
    pub total_cost_usd: f64,
}

/// Bounded in-memory feed + broadcast hub.
pub struct DashboardHub {
    tx: broadcast::Sender<DashboardEvent>,
    recent: Mutex<VecDeque<DashboardEvent>>,
    totals: Mutex<DashboardTotals>,
    seq: Mutex<u64>,
    capacity: usize,
    pub started_ms: u64,
}

impl DashboardHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self {
            tx,
            recent: Mutex::new(VecDeque::with_capacity(capacity)),
            totals: Mutex::new(DashboardTotals::default()),
            seq: Mutex::new(0),
            capacity,
            started_ms: now_ms(),
        }
    }

    /// Allocate the next monotonic sequence number for an event.
    pub fn next_seq(&self) -> u64 {
        let mut seq = self.seq.lock().unwrap();
        *seq += 1;
        *seq
    }

    /// Record an event: update totals, append to the ring buffer, broadcast.
    pub fn record(&self, event: DashboardEvent) {
        {
            let mut totals = self.totals.lock().unwrap();
            totals.request_count += 1;
            totals.total_micro_usdc_charged = totals
                .total_micro_usdc_charged
                .saturating_add(event.charge_applied);
            totals.total_cost_usd += event.charge_usd;
        }
        {
            let mut recent = self.recent.lock().unwrap();
            if recent.len() >= self.capacity {
                recent.pop_front();
            }
            recent.push_back(event.clone());
        }
        // A send error just means no subscribers; that's fine.
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DashboardEvent> {
        self.tx.subscribe()
    }

    pub fn recent(&self) -> Vec<DashboardEvent> {
        self.recent.lock().unwrap().iter().cloned().collect()
    }

    pub fn totals(&self) -> DashboardTotals {
        self.totals.lock().unwrap().clone()
    }
}

/// Mask bearer-style API keys (`sk-...`) before they reach the dashboard feed
/// so a secret bearer token never lands in a dashboard, screen-share, or log.
pub fn redact_secrets(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("sk-") {
        result.push_str(&rest[..pos]);
        let after = &rest[pos..];
        let end = after
            .char_indices()
            .find(|&(idx, c)| idx >= 3 && !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .map(|(idx, _)| idx)
            .unwrap_or(after.len());
        if end > 12 {
            result.push_str("sk-***REDACTED***");
        } else {
            result.push_str(&after[..end]);
        }
        rest = &after[end..];
    }
    result.push_str(rest);
    result
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_bearer_keys() {
        let s = r#"{"api_key":"sk-or-v1-3527c84aabcdef0123456789","request_id":"49802767d5a1"}"#;
        let red = redact_secrets(s);
        assert!(!red.contains("sk-or-v1-3527"), "key not redacted: {red}");
        assert!(red.contains("sk-***REDACTED***"));
        assert!(red.contains("49802767d5a1"), "request id should survive");
        // Short non-key strings are untouched.
        assert_eq!(redact_secrets("sk-1"), "sk-1");
        // Unicode content is preserved around a redaction.
        let u = redact_secrets("héllo sk-proj-ABCDEFGHIJKLMNOP wörld");
        assert!(u.contains("héllo") && u.contains("wörld") && u.contains("REDACTED"));
    }

    #[test]
    fn hub_tracks_totals_and_ring_buffer() {
        let hub = DashboardHub::new(2);
        for i in 0..3 {
            hub.record(sample_event(hub.next_seq(), i + 1));
        }
        let totals = hub.totals();
        assert_eq!(totals.request_count, 3);
        assert_eq!(totals.total_micro_usdc_charged, 6); // 1 + 2 + 3
                                                        // Ring buffer capped at 2.
        assert_eq!(hub.recent().len(), 2);
    }

    fn sample_event(seq: u64, charge: u128) -> DashboardEvent {
        DashboardEvent {
            seq,
            ts_ms: 0,
            client_request_id: format!("req-{seq}"),
            billing_label: "direct:openrouter-ephemeral".to_string(),
            request_nullifier: Felt252::from_u64(seq),
            active_root: Felt252::ZERO,
            anon_commitment: CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ZERO,
            },
            solvency_bound: 1_000_000,
            solvency_bound_usd: 1.0,
            proof_backend: "groth16_bn254".to_string(),
            proof_public_output_hash: Felt252::ZERO,
            proof_size_bytes: 100,
            request_raw: "{}".to_string(),
            response_code: 200,
            response_text: "{}".to_string(),
            response_hash: Felt252::ZERO,
            usage: None,
            charge_applied: charge,
            charge_usd: 0.000001 * charge as f64,
            next_commitment: CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ZERO,
            },
            next_anchor: Felt252::ZERO,
            blind_delta_srv: Felt252::ZERO,
            upstream_ms: 0,
            total_ms: 0,
        }
    }
}
