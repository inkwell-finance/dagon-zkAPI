//! Deliberately misbehaving server modes for drills and acceptance tests:
//! `zkapi serverd --adversary <mode>`. The module and flag exist only in
//! builds with the `adversary` cargo feature (and in this crate's unit
//! tests); a server built without `debug_assertions` refuses every mode at
//! startup, so no release build can run one.
//!
//! Every mode is a form of withholding from the wallet's point of view: an
//! honest wallet installs none of these successors and exits from its newest
//! installed state with the concession it released there.
//!
//! * `withhold`: settle every request but never sign its successor; recovery
//!   keeps answering `reserved` without a response.
//! * `random-anchor`: sign the successor at a random anchor (fails S4 and
//!   Q-chain).
//! * `born-spent`: sign the successor at anchor 1, the genesis anchor (fails
//!   S4 and Q-gen).
//! * `overcharge`: charge one unit above the request's solvency bound at the
//!   derived anchor (fails S3).

use zkapi_proof::compact::random_field;
use zkapi_types::wire::ApiRequestV2;
use zkapi_types::Felt252;

use crate::error::ServerError;
use crate::successor::{
    build_adversarial_successor, derived_anchor, Deployment, SignedSuccessor, StateSigner,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AdversaryMode {
    Withhold,
    RandomAnchor,
    BornSpent,
    Overcharge,
}

/// Refuse every adversary mode unless this is a debug (drill) build.
pub fn ensure_allowed(mode: Option<AdversaryMode>) -> anyhow::Result<()> {
    if let Some(mode) = mode {
        anyhow::ensure!(
            cfg!(debug_assertions) || cfg!(test),
            "adversary mode {mode:?} is refused in release builds"
        );
        tracing::warn!(
            ?mode,
            "ADVERSARY MODE: this server deliberately misbehaves (drill build)"
        );
    }
    Ok(())
}

/// The charge an adversary settles at instead of the measured one.
pub(crate) fn settled_charge(
    mode: Option<AdversaryMode>,
    request: &ApiRequestV2,
    measured: u128,
) -> u128 {
    match mode {
        Some(AdversaryMode::Overcharge) => request.public_inputs.solvency_bound.saturating_add(1),
        _ => measured,
    }
}

/// What the adversary signs instead of the honest successor: `None` for an
/// honest server, `Some(Err)` when it withholds.
pub(crate) fn successor<S: StateSigner + ?Sized>(
    mode: Option<AdversaryMode>,
    signer: &S,
    deployment: &Deployment,
    request: &ApiRequestV2,
    charge: u128,
) -> Option<Result<SignedSuccessor, ServerError>> {
    let honest = derived_anchor(&request.public_inputs.request_nullifier);
    let anchor = match mode? {
        AdversaryMode::Withhold => {
            return Some(Err(ServerError::Internal(
                "adversary withhold: the successor is never signed".into(),
            )))
        }
        AdversaryMode::BornSpent => Felt252::ONE,
        AdversaryMode::RandomAnchor => random_field(),
        AdversaryMode::Overcharge => honest,
    };
    Some(build_adversarial_successor(
        signer, deployment, request, charge, anchor,
    ))
}
