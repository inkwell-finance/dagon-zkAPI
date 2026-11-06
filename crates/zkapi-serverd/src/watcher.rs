//! Concession-exit challenger policy over the server's append-only evidence.
//!
//! For each pending escape `(n, N, N⁺, B, c, deadline)`:
//!
//! 1. **Defeat** if verified request evidence exists at `N⁺`: the owner
//!    held and spent the successor of the escaped state, so the escape is
//!    stale. Defeat is root-independent.
//! 2. Otherwise **raise** to `Ω(N)` once it is final and `Ω > c`. `Ω` is the
//!    settled charge of the request at `N`, or, when that request may have
//!    delivered access and is still unsettled at `deadline − raise_lead`, its
//!    solvency bound. The raise amount is `min(Ω, sb, B)`.
//! 3. Otherwise do nothing: an honest fresh escape has no evidence at `N` or
//!    `N⁺` and is never touched.
//!
//! A defeat supersedes an unmined raise; a raise never replaces a defeat.
//! Evidence comes only from `request_evidence`, which is written with the
//! reservation and is immutable.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::wire::Groth16ProofWire;
use zkapi_types::{Felt252, RequestPublicInputsV2};

use crate::nullifier_store::{NullifierStore, OaProvisioningOutcome, RequestEvidence};

/// One pending escape as the vault reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingEscape {
    pub note_id: u32,
    pub nullifier: Felt252,
    pub next_nullifier: Felt252,
    pub state_balance: u128,
    pub conceded: u128,
    pub deadline: u64,
}

/// The vault call a decision makes due.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionKind {
    Defeat,
    Raise {
        #[serde(with = "decimal_u128")]
        amount: u128,
    },
}

/// Internally tagged enums buffer their fields, and that buffer cannot carry a
/// `u128`, so checkpoints persist the raise amount as a decimal string. An
/// integer amount (older checkpoints) still loads.
mod decimal_u128 {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(amount: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(amount)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        struct Amount;
        impl de::Visitor<'_> for Amount {
            type Value = u128;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a decimal u128 string or an unsigned integer")
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<u128, E> {
                Ok(value.into())
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<u128, E> {
                value.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Amount)
    }
}

impl ActionKind {
    pub fn is_defeat(self) -> bool {
        matches!(self, Self::Defeat)
    }
}

/// A fully reconstructed challenger call.
#[derive(Debug, Clone)]
pub struct ChallengeAction {
    pub note_id: u32,
    pub kind: ActionKind,
    pub request_inputs: RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
}

/// What the policy wants done for one pending escape now.
#[derive(Debug, Clone)]
pub enum Decision {
    Act(Box<ChallengeAction>),
    /// `Ω(N)` is not final yet; decide again before `deadline − raise_lead`.
    Wait,
    Nothing,
}

/// Verifies archived request evidence before it is submitted.
pub trait EvidenceVerifier: Send + Sync {
    fn verify(
        &self,
        inputs: &RequestPublicInputsV2,
        proof: &Groth16ProofWire,
    ) -> anyhow::Result<bool>;
}

impl EvidenceVerifier for RequestVerifier {
    fn verify(
        &self,
        inputs: &RequestPublicInputsV2,
        proof: &Groth16ProofWire,
    ) -> anyhow::Result<bool> {
        RequestVerifier::verify(self, inputs, proof)
    }
}

pub struct ChallengeWatcher {
    store: Arc<NullifierStore>,
    verifier: Box<dyn EvidenceVerifier>,
    raise_lead_seconds: u64,
    chain_id: u64,
    protocol_binding: Felt252,
}

impl ChallengeWatcher {
    pub fn new(
        store: Arc<NullifierStore>,
        verifier: Box<dyn EvidenceVerifier>,
        raise_lead_seconds: u64,
        chain_id: u64,
        protocol_binding: Felt252,
    ) -> Self {
        Self {
            store,
            verifier,
            raise_lead_seconds,
            chain_id,
            protocol_binding,
        }
    }

    /// Evidence at `nullifier` that verifies for this deployment.
    fn verified_evidence(&self, nullifier: &Felt252) -> anyhow::Result<Option<RequestEvidence>> {
        let Some(evidence) = self.store.request_evidence(nullifier) else {
            return Ok(None);
        };
        let inputs = &evidence.request_inputs;
        if inputs.request_nullifier != *nullifier
            || inputs.chain_id != self.chain_id
            || inputs.contract_address != self.protocol_binding
        {
            tracing::error!(%nullifier, "request evidence belongs to another deployment");
            return Ok(None);
        }
        if !self.verifier.verify(inputs, &evidence.proof)? {
            tracing::error!(%nullifier, "request evidence failed verification");
            return Ok(None);
        }
        Ok(Some(evidence))
    }

    /// `Ω(N)` when final: the settled charge, or the bound when access may
    /// have been delivered and the request is unsettled at the raise lead.
    /// `None` means not final yet.
    fn final_charge(&self, evidence: &RequestEvidence, deadline: u64, now: u64) -> Option<u128> {
        let record = self.store.lookup_by_nullifier(&evidence.nullifier);
        if let Some(charge) = record.as_ref().and_then(|record| {
            record
                .settled_charge
                .or((record.status == zkapi_types::NullifierStatus::Finalized)
                    .then_some(record.charge_applied)
                    .flatten())
        }) {
            return Some(charge);
        }
        let possibly_delivered = self
            .store
            .lookup_openrouter_lease(&evidence.client_request_id)
            .filter(|lease| lease.request_nullifier == evidence.nullifier)
            .is_none_or(|lease| {
                lease.key_hash.is_some()
                    || lease.oa_provisioning_outcome == OaProvisioningOutcome::MayHaveIssued
            });
        if !possibly_delivered {
            // Access was provably never issued: nothing is owed.
            return Some(0);
        }
        (now >= deadline.saturating_sub(self.raise_lead_seconds))
            .then_some(evidence.request_inputs.solvency_bound)
    }

    /// Apply the concession policy to one pending escape at chain time `now`.
    pub fn decide(&self, escape: &PendingEscape, now: u64) -> anyhow::Result<Decision> {
        if escape.next_nullifier != Felt252::ZERO {
            if let Some(evidence) = self.verified_evidence(&escape.next_nullifier)? {
                return Ok(Decision::Act(Box::new(ChallengeAction {
                    note_id: escape.note_id,
                    kind: ActionKind::Defeat,
                    request_inputs: evidence.request_inputs,
                    proof: evidence.proof,
                })));
            }
        }
        let Some(evidence) = self.verified_evidence(&escape.nullifier)? else {
            return Ok(Decision::Nothing);
        };
        let Some(omega) = self.final_charge(&evidence, escape.deadline, now) else {
            return Ok(Decision::Wait);
        };
        let amount = omega
            .min(evidence.request_inputs.solvency_bound)
            .min(escape.state_balance);
        if amount <= escape.conceded {
            return Ok(Decision::Nothing);
        }
        Ok(Decision::Act(Box::new(ChallengeAction {
            note_id: escape.note_id,
            kind: ActionKind::Raise { amount },
            request_inputs: evidence.request_inputs,
            proof: evidence.proof,
        })))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine;
    use zkapi_types::wire::{ApiRequestV2, ProofBackendWire};

    pub(crate) const BINDING: u64 = 0xdead;

    /// Accepts evidence whose proof is not the literal `invalid` marker.
    pub(crate) struct StubVerifier;

    impl EvidenceVerifier for StubVerifier {
        fn verify(
            &self,
            _inputs: &RequestPublicInputsV2,
            proof: &Groth16ProofWire,
        ) -> anyhow::Result<bool> {
            Ok(proof.proof != base64::engine::general_purpose::STANDARD.encode([0xffu8; 256]))
        }
    }

    pub(crate) fn synthetic_request(id: &str, nullifier: Felt252, bound: u128) -> ApiRequestV2 {
        ApiRequestV2 {
            client_request_id: id.into(),
            payload: "{}".into(),
            payload_hash: Felt252::from_u64(88),
            public_inputs: RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::from_u64(BINDING),
                active_root: Felt252::from_u64(3),
                state_signing_key_x: Felt252::from_u64(4),
                state_signing_key_y: Felt252::from_u64(5),
                request_time: 6,
                solvency_bound: bound,
                request_nullifier: nullifier,
                authorization_tag: Felt252::from_u64(7),
                anonymous_commitment_x: Felt252::from_u64(8),
                anonymous_commitment_y: Felt252::from_u64(9),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: base64::engine::general_purpose::STANDARD
                    .encode([nullifier.as_bytes()[31]; 256]),
            },
        }
    }

    /// Reserve a request (evidence) and give it an issued key.
    pub(crate) fn served(store: &NullifierStore, id: &str, nullifier: Felt252, bound: u128) {
        let request = synthetic_request(id, nullifier, bound);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "openrouter", 1, 2, 3, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease(id, &format!("key-{id}"))
            .unwrap();
    }

    pub(crate) fn watcher(store: Arc<NullifierStore>) -> ChallengeWatcher {
        ChallengeWatcher::new(
            store,
            Box::new(StubVerifier),
            600,
            1,
            Felt252::from_u64(BINDING),
        )
    }

    fn escape(nullifier: u64, next: u64, conceded: u128) -> PendingEscape {
        PendingEscape {
            note_id: 4,
            nullifier: Felt252::from_u64(nullifier),
            next_nullifier: Felt252::from_u64(next),
            state_balance: 1_000,
            conceded,
            deadline: 10_000,
        }
    }

    /// Threat: stale-state escape after spending the successor. Evidence at
    /// `N⁺` exists, so the policy defeats; this supersedes any raise.
    #[test]
    fn stale_escape_with_evidence_at_the_successor_is_defeated() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        served(&store, "k", Felt252::from_u64(10), 300);
        served(&store, "k+1", Felt252::from_u64(11), 300);
        store
            .record_settlement(&Felt252::from_u64(10), 120, 200, "{}")
            .unwrap();
        let Decision::Act(action) = watcher(store).decide(&escape(10, 11, 0), 0).unwrap() else {
            panic!("expected a defeat");
        };
        assert_eq!(action.kind, ActionKind::Defeat);
        assert_eq!(
            action.request_inputs.request_nullifier,
            Felt252::from_u64(11)
        );
    }

    /// Threat: under-concession. Only evidence at `N`, settled at 120: raise
    /// to the settled charge, never above the bound or the state balance.
    #[test]
    fn under_concession_is_raised_to_the_settled_charge() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        served(&store, "k", Felt252::from_u64(10), 300);
        let watcher = watcher(store.clone());
        assert!(
            matches!(
                watcher.decide(&escape(10, 11, 0), 0).unwrap(),
                Decision::Wait
            ),
            "an unsettled possibly-delivered request waits for the raise lead"
        );
        let Decision::Act(action) = watcher.decide(&escape(10, 11, 0), 9_400).unwrap() else {
            panic!("expected a bound raise at the lead");
        };
        assert_eq!(action.kind, ActionKind::Raise { amount: 300 });
        store
            .record_settlement(&Felt252::from_u64(10), 120, 200, "{}")
            .unwrap();
        let Decision::Act(action) = watcher.decide(&escape(10, 11, 0), 0).unwrap() else {
            panic!("expected a raise");
        };
        assert_eq!(action.kind, ActionKind::Raise { amount: 120 });
        assert!(matches!(
            watcher.decide(&escape(10, 11, 120), 0).unwrap(),
            Decision::Nothing
        ));
        let mut small = escape(10, 11, 0);
        small.state_balance = 50;
        let Decision::Act(action) = watcher.decide(&small, 0).unwrap() else {
            panic!("expected a capped raise");
        };
        assert_eq!(action.kind, ActionKind::Raise { amount: 50 });
    }

    /// An honest fresh escape (no request at `N` or `N⁺`) is never touched,
    /// nor is an escape whose request provably never issued access.
    #[test]
    fn honest_fresh_escape_and_unissued_requests_are_left_alone() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let watcher = watcher(store.clone());
        assert!(matches!(
            watcher.decide(&escape(10, 11, 0), 9_999).unwrap(),
            Decision::Nothing
        ));
        let request = synthetic_request("never-issued", Felt252::from_u64(20), 300);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_with_oa_id(&request, "oa_org", 1, 2, 3, 1.0, Some("b"))
            .unwrap();
        assert!(matches!(
            watcher.decide(&escape(20, 21, 0), 9_999).unwrap(),
            Decision::Nothing
        ));
    }

    /// Griefing: evidence that fails verification or belongs to another
    /// deployment is never submitted.
    #[test]
    fn invalid_or_foreign_evidence_is_ignored() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut forged = synthetic_request("forged", Felt252::from_u64(11), 300);
        forged.proof.proof = base64::engine::general_purpose::STANDARD.encode([0xffu8; 256]);
        store.reserve_openrouter_lease(&forged).unwrap();
        let mut foreign = synthetic_request("foreign", Felt252::from_u64(31), 300);
        foreign.public_inputs.chain_id = 2;
        store.reserve_openrouter_lease(&foreign).unwrap();
        let watcher = watcher(store);
        assert!(matches!(
            watcher.decide(&escape(10, 11, 0), 0).unwrap(),
            Decision::Nothing
        ));
        assert!(matches!(
            watcher.decide(&escape(30, 31, 0), 0).unwrap(),
            Decision::Nothing
        ));
    }

    /// Threat: a challenger that cannot restart. Checkpoints persist the
    /// in-flight action; a raise must reload (including checkpoints written
    /// with a numeric amount), or the daemon refuses to start.
    #[test]
    fn action_kind_survives_a_checkpoint_round_trip() {
        for kind in [ActionKind::Defeat, ActionKind::Raise { amount: 120 }] {
            let json = serde_json::to_string(&Some(kind)).unwrap();
            let restored: Option<ActionKind> = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, Some(kind));
        }
        let legacy: ActionKind = serde_json::from_str(r#"{"kind":"raise","amount":120}"#).unwrap();
        assert_eq!(legacy, ActionKind::Raise { amount: 120 });
    }
}
