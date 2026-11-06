//! Signing the successor of a settled request (O1, O7).
//!
//! The successor of the state whose request spent nullifier `N` is signed at
//! exactly one anchor, the derived `τ' = H(d_anchor, N)`
//! (`zkapi_core::v2::next_anchor`). Anyone can compute it from `N`; the request
//! circuit refuses to spend a signed state at any other anchor (Q-chain) and
//! clients refuse to install one (S4). [`sign_successor_state`] refuses an
//! anchor of 0 or 1 and one that differs from an independent recomputation
//! (the circuit's native mirror), so a bug in either derivation never reaches
//! the signer. The server's blinding delta stays random.

use zkapi_core::v2 as core;
use zkapi_proof::compact::{random_scalar, server_update};
use zkapi_types::wire::{ApiRequestV2, CurvePointWire};
use zkapi_types::{Felt252, SchnorrSignature};

use crate::error::ServerError;

/// Signs state messages.
pub trait StateSigner {
    fn sign_state(&self, message: &Felt252) -> SchnorrSignature;
}

impl StateSigner for crate::signer::ServerSigner {
    fn sign_state(&self, message: &Felt252) -> SchnorrSignature {
        crate::signer::ServerSigner::sign_state(self, message)
    }
}

/// `(protocol_version, chain_id, contract_address)` of the state message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
}

/// The only anchor at which the successor of the request at `nullifier` is
/// signed.
pub fn derived_anchor(nullifier: &Felt252) -> Felt252 {
    core::next_anchor(nullifier)
}

/// `succ(N)` through the circuit's native mirror, independently of
/// `zkapi_core::v2::next_anchor`.
fn independent_anchor(nullifier: &Felt252) -> Felt252 {
    core::field_to_felt(&zkapi_proof::groth16::next_anchor(core::felt_to_field(
        nullifier,
    )))
}

/// Sign `M_state(next_commitment, next_anchor)` only when `next_anchor` is the
/// derived anchor of `request_nullifier`: never 0 or 1 (genesis), and equal to
/// an independent recomputation.
pub fn sign_successor_state<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    request_nullifier: &Felt252,
    next_commitment: &CurvePointWire,
    next_anchor: &Felt252,
) -> Result<SchnorrSignature, ServerError> {
    if *next_anchor == Felt252::ZERO || *next_anchor == core::GENESIS_ANCHOR {
        return Err(ServerError::Internal(
            "refusing to sign a successor at anchor 0 or 1".into(),
        ));
    }
    if *next_anchor != independent_anchor(request_nullifier) {
        return Err(ServerError::Internal(
            "refusing to sign a successor at an anchor that is not succ(N)".into(),
        ));
    }
    Ok(sign_unchecked(
        signer,
        deployment,
        next_commitment,
        next_anchor,
    ))
}

fn sign_unchecked<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    next_commitment: &CurvePointWire,
    next_anchor: &Felt252,
) -> SchnorrSignature {
    signer.sign_state(&core::state_message(
        deployment.protocol_version,
        deployment.chain_id,
        &deployment.contract_address,
        &next_commitment.x,
        &next_commitment.y,
        next_anchor,
    ))
}

/// A signed successor: `C' = C_anon − charge·G + δ·H` with a fresh `δ`.
#[derive(Debug, Clone)]
pub struct SignedSuccessor {
    pub charge: u128,
    pub next_commitment: CurvePointWire,
    pub next_anchor: Felt252,
    pub blind_delta: Felt252,
    pub signature: SchnorrSignature,
}

/// The honest successor of `request` at its settled `charge`, at the derived
/// anchor. Refuses a charge above the request's solvency bound and a request
/// for another deployment.
pub fn build_signed_successor<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    request: &ApiRequestV2,
    charge: u128,
) -> Result<SignedSuccessor, ServerError> {
    let public = &request.public_inputs;
    if public.protocol_version != deployment.protocol_version
        || public.chain_id != deployment.chain_id
        || public.contract_address != deployment.contract_address
    {
        return Err(ServerError::Internal(
            "refusing to sign a successor for a different deployment".into(),
        ));
    }
    if charge > public.solvency_bound {
        return Err(ServerError::Internal(
            "refusing to sign a charge above the request's solvency bound".into(),
        ));
    }
    let next_anchor = derived_anchor(&public.request_nullifier);
    let (next_commitment, blind_delta) = update(request, charge)?;
    let signature = sign_successor_state(
        signer,
        deployment,
        &public.request_nullifier,
        &next_commitment,
        &next_anchor,
    )?;
    Ok(SignedSuccessor {
        charge,
        next_commitment,
        next_anchor,
        blind_delta,
        signature,
    })
}

/// A successor at any `(charge, anchor)`, signed without the anchor and bound
/// assertions: only the adversary test modes build one.
#[cfg(any(test, feature = "adversary"))]
pub(crate) fn build_adversarial_successor<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    request: &ApiRequestV2,
    charge: u128,
    next_anchor: Felt252,
) -> Result<SignedSuccessor, ServerError> {
    let (next_commitment, blind_delta) = update(request, charge)?;
    let signature = sign_unchecked(signer, deployment, &next_commitment, &next_anchor);
    Ok(SignedSuccessor {
        charge,
        next_commitment,
        next_anchor,
        blind_delta,
        signature,
    })
}

fn update(request: &ApiRequestV2, charge: u128) -> Result<(CurvePointWire, Felt252), ServerError> {
    let public = &request.public_inputs;
    let anonymous = CurvePointWire {
        x: public.anonymous_commitment_x,
        y: public.anonymous_commitment_y,
    };
    let blind_delta = random_scalar();
    let next_commitment = server_update(&anonymous, charge, &blind_delta)
        .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
    Ok((next_commitment, blind_delta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_refuses_genesis_zero_and_non_derived_anchors() {
        let signer =
            crate::signer::ServerSigner::new(&Felt252::from_u64(11), &Felt252::from_u64(12));
        let deployment = Deployment {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(0xdead),
        };
        let nullifier = Felt252::from_u64(0xabc);
        let commitment = CurvePointWire {
            x: Felt252::from_u64(1),
            y: Felt252::from_u64(2),
        };
        for anchor in [Felt252::ZERO, core::GENESIS_ANCHOR, Felt252::from_u64(7)] {
            assert!(
                sign_successor_state(&signer, &deployment, &nullifier, &commitment, &anchor)
                    .is_err(),
                "{anchor:?}"
            );
        }
        let derived = derived_anchor(&nullifier);
        assert_eq!(derived, independent_anchor(&nullifier));
        assert!(
            sign_successor_state(&signer, &deployment, &nullifier, &commitment, &derived).is_ok()
        );
    }
}
