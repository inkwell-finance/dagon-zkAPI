//! Browser-safe zkAPI v2 wallet operations (concession exit).
//!
//! This crate deliberately owns neither storage nor transport. Every operation
//! accepts an immutable state snapshot and returns the complete next snapshot,
//! allowing the JavaScript host to commit state and its write-ahead journal in
//! one IndexedDB transaction before any network request is made.
//!
//! Refusals are errors whose message starts with a stable code followed by
//! `": "` (for example `invalid_successor: S4 ...`), so the host can tell a
//! signed but unusable successor from a transport problem. The codes are the
//! `pub const` strings of [`codes`].
//!
//! Rules enforced here:
//! * **S1–S6** before a successor is installed ([`complete_response`]). A
//!   correctly signed successor that fails S3, S4 or S5 is refused with
//!   [`codes::INVALID_SUCCESSOR`] and must be treated as withheld.
//! * **C2**: every request proof at a state carries the same solvency bound,
//!   recorded in the returned state as `bound_at_state` ([`prepare_request`]).
//! * **Q-chain**: a signed state proves requests and exits only with its
//!   `prev_anchor`, which an install records.
//! * Withdrawal modes: an escape concedes at most `bound_at_state`; a mutual
//!   close concedes nothing. No exit takes a Merkle path or root: the
//!   statement binds the note's registration and packed fields, which the
//!   vault compares with the note it stores.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use zkapi_core::merkle::MerkleTree;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, random_field, random_scalar, rerandomize, server_update,
    verify_signature, RequestProver, RequestWitnessData, WithdrawalProver, WithdrawalWitnessData,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceResponseV2, CurvePointWire, Groth16ProofWire, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2, SchnorrSignature, WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

/// Stable refusal codes; every refusal message starts with `"<code>: "`.
pub mod codes {
    /// The state snapshot is inconsistent or belongs to another deployment.
    pub const STATE_INVALID: &str = "state_invalid";
    /// A signed state without its predecessor's anchor cannot prove.
    pub const PREV_ANCHOR_MISSING: &str = "prev_anchor_missing";
    /// C2: a request proof at this state already used another bound.
    pub const BOUND_FIXED_AT_STATE: &str = "bound_fixed_at_state";
    /// The response names another request or nullifier than the journal.
    pub const RESPONSE_IDENTITY_MISMATCH: &str = "response_identity_mismatch";
    /// The journal was not made at this note state.
    pub const JOURNAL_STATE_MISMATCH: &str = "journal_state_mismatch";
    /// S2: the response payload does not hash to `response_hash`.
    pub const RESPONSE_HASH_MISMATCH: &str = "response_hash_mismatch";
    /// S6: the successor is not signed by the pinned state key.
    pub const SUCCESSOR_SIGNATURE_INVALID: &str = "successor_signature_invalid";
    /// S3, S4 or S5 failed on a correctly signed successor: treat it exactly
    /// like a withheld successor.
    pub const INVALID_SUCCESSOR: &str = "invalid_successor";
    /// A withdrawal argument is not allowed for its mode.
    pub const WITHDRAWAL_ARGS: &str = "invalid_withdrawal_args";
    /// An escape may concede at most the state's bound.
    pub const CONCEDED_EXCEEDS_BOUND: &str = "conceded_exceeds_bound";
}

fn refusal(code: &str, detail: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("{code}: {detail}")
}

fn invalid_successor(check: &str, detail: impl std::fmt::Display) -> anyhow::Error {
    refusal(codes::INVALID_SUCCESSOR, format!("{check}: {detail}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserWalletConfig {
    pub protocol_version: u16,
    #[serde(
        serialize_with = "zkapi_types::serialization::serialize_u64_decimal",
        deserialize_with = "zkapi_types::serialization::deserialize_u64_or_decimal_string"
    )]
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub request_charge_cap: u128,
    pub policy_charge_cap: u128,
    pub policy_enabled: bool,
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserNoteState {
    pub protocol_version: u16,
    #[serde(
        serialize_with = "zkapi_types::serialization::serialize_u64_decimal",
        deserialize_with = "zkapi_types::serialization::deserialize_u64_or_decimal_string"
    )]
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub note_id: u32,
    pub secret_s: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub current_balance: u128,
    pub balance_blinding: String,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_signature: Option<SchnorrSignature>,
    /// The anchor of the state this one succeeded (`None` at genesis). A
    /// signed state without it cannot prove (`prev_anchor_missing`).
    #[serde(default)]
    pub prev_anchor: Option<Felt252>,
    /// The solvency bound of every request proof made at this state (C2);
    /// 0 while no request proof was made. Reset to 0 by an install.
    #[serde(default)]
    pub bound_at_state: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequestJournal {
    pub exists: bool,
    pub client_request_id: String,
    pub nullifier: Felt252,
    pub payload_hash: Felt252,
    pub user_rerandomization: Felt252,
    pub created_at_ms: u64,
    pub prepared_request: ApiRequestV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositParams {
    pub secret: Felt252,
    pub registration_commitment: Felt252,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmDepositArgs {
    pub secret: Felt252,
    pub note_id: u32,
    pub amount: u128,
    pub expiry_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareRequestArgs {
    pub payload: String,
    pub active_root: Felt252,
    pub merkle_siblings: Vec<Felt252>,
    pub client_request_id: String,
    pub request_time: u64,
    pub created_at_ms: u64,
}

/// A proved request, its journal, and the state with `bound_at_state` set to
/// the request's bound. The host commits `state` and `journal` in one
/// transaction before transmitting `request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedRequest {
    pub request: ApiRequestV2,
    pub journal: PendingRequestJournal,
    pub state: BrowserNoteState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteResponseArgs {
    pub state: BrowserNoteState,
    pub journal: PendingRequestJournal,
    pub response: RequestResponseV2,
}

/// Arguments of [`prepare_withdrawal`].
///
/// * `escape`: `destination` is required and `conceded <= bound_at_state`.
///   No clearance.
/// * `mutual`: `destination` and the server `clearance` are required;
///   `conceded` must be 0.
///
/// `valid_until` (seconds) is the last second the vault accepts the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareWithdrawalArgs {
    pub mode: String,
    pub destination: String,
    #[serde(default, deserialize_with = "deserialize_u128_or_decimal_string")]
    pub conceded: u128,
    #[serde(deserialize_with = "zkapi_types::serialization::deserialize_u64_or_decimal_string")]
    pub valid_until: u64,
    #[serde(default)]
    pub clearance: Option<ClearanceResponseV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalPlan {
    pub mode: String,
    pub public_inputs: WithdrawalPublicInputsV2,
    pub proof: Groth16ProofWire,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserNoteStatus {
    pub note_id: u32,
    pub deposit_amount: u128,
    pub current_balance: u128,
    pub expiry_ts: u64,
    pub is_genesis: bool,
    pub current_anchor: Felt252,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub bound_at_state: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserWalletStatus {
    pub has_note: bool,
    pub pending_request: bool,
    pub note: Option<BrowserNoteStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSnapshot {
    pub root: Felt252,
    pub next_note_id: u32,
    pub leaves: Vec<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserTreePath {
    pub active_root: Felt252,
    pub note_id: u32,
    pub siblings: Vec<Felt252>,
}

/// Derive a request path from the indexer's privacy-safe whole-tree snapshot
/// and verify the advertised root before any proof uses it. Exits need no
/// path.
pub fn tree_path(
    snapshot: TreeSnapshot,
    note_id: u32,
    require_existing: bool,
) -> Result<BrowserTreePath> {
    if snapshot.leaves.len() != snapshot.next_note_id as usize {
        bail!("tree snapshot leaf count does not match next_note_id");
    }
    if (require_existing && note_id >= snapshot.next_note_id)
        || (!require_existing && note_id != snapshot.next_note_id)
    {
        bail!("requested note index is inconsistent with the tree snapshot");
    }
    let mut tree = MerkleTree::new();
    for (index, leaf) in snapshot.leaves.into_iter().enumerate() {
        tree.set_leaf(index as u32, leaf);
    }
    if tree.root() != snapshot.root {
        bail!("tree snapshot root verification failed");
    }
    Ok(BrowserTreePath {
        active_root: snapshot.root,
        note_id,
        siblings: tree.get_siblings(note_id).to_vec(),
    })
}

pub fn generate_deposit_params() -> DepositParams {
    loop {
        let secret = random_field();
        if !secret.is_zero() {
            return DepositParams {
                registration_commitment: core::registration_commitment(&secret),
                secret,
            };
        }
    }
}

pub fn confirm_deposit(
    config: &BrowserWalletConfig,
    args: ConfirmDepositArgs,
) -> Result<BrowserNoteState> {
    validate_state_identity(config, args.secret, args.amount)?;
    let blinding = random_scalar();
    let commitment = balance_commitment(
        args.amount,
        &blinding,
        &core::note_leaf(
            args.note_id,
            &core::registration_commitment(&args.secret),
            args.amount,
            args.expiry_ts,
        ),
    );
    Ok(BrowserNoteState {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        note_id: args.note_id,
        secret_s: args.secret,
        deposit_amount: args.amount,
        expiry_ts: args.expiry_ts,
        current_balance: args.amount,
        balance_blinding: blinding.to_hex(),
        current_commitment_x: commitment.x,
        current_commitment_y: commitment.y,
        current_anchor: core::GENESIS_ANCHOR,
        is_genesis: true,
        state_signature: None,
        prev_anchor: None,
        bound_at_state: 0,
    })
}

pub fn wallet_status(
    state: Option<&BrowserNoteState>,
    journal: Option<&PendingRequestJournal>,
) -> BrowserWalletStatus {
    BrowserWalletStatus {
        has_note: state.is_some(),
        pending_request: journal.is_some_and(|entry| entry.exists),
        note: state.map(|state| BrowserNoteStatus {
            note_id: state.note_id,
            deposit_amount: state.deposit_amount,
            current_balance: state.current_balance,
            expiry_ts: state.expiry_ts,
            is_genesis: state.is_genesis,
            current_anchor: state.current_anchor,
            current_commitment_x: state.current_commitment_x,
            current_commitment_y: state.current_commitment_y,
            bound_at_state: state.bound_at_state,
        }),
    }
}

/// The nullifier `N(s, note_id, τ)` the state's requests spend and its exits
/// publish.
pub fn withdrawal_nullifier(state: &BrowserNoteState) -> Felt252 {
    core::nullifier(&state.secret_s, state.note_id, &state.current_anchor)
}

/// The successor nullifier `N⁺` an escape from this state publishes; a
/// request at `N⁺` (spending the successor) is what defeats such an escape.
pub fn successor_nullifier(state: &BrowserNoteState) -> Felt252 {
    core::successor_nullifier(
        &state.secret_s,
        state.note_id,
        &withdrawal_nullifier(state),
    )
}

pub fn prepare_request(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareRequestArgs,
    proving_key: &[u8],
) -> Result<PreparedRequest> {
    request_bound(config, state)?;
    let prover = RequestProver::from_bytes(proving_key)?;
    prepare_request_with_prover(config, state, args, &prover)
}

/// Check that `state` may prove a request now and return its bound: the
/// deployment's cap, which must equal `bound_at_state` when one is already
/// recorded (C2), and the predecessor anchor a signed state needs.
fn request_bound(config: &BrowserWalletConfig, state: &BrowserNoteState) -> Result<u128> {
    validate_state(config, state)?;
    let solvency_bound = if config.policy_enabled {
        config.policy_charge_cap
    } else {
        config.request_charge_cap
    };
    // 0 means "no request proof yet" in bound_at_state, so it is never a bound.
    if solvency_bound == 0 {
        bail!("the solvency bound must be positive");
    }
    if state.bound_at_state != 0 && state.bound_at_state != solvency_bound {
        return Err(refusal(
            codes::BOUND_FIXED_AT_STATE,
            format!(
                "request proofs at this state use the bound {}; refusing a proof with bound {solvency_bound}",
                state.bound_at_state
            ),
        ));
    }
    if state.current_balance < solvency_bound {
        bail!(
            "insufficient balance: need {solvency_bound}, have {}",
            state.current_balance
        );
    }
    predecessor_anchor(state)?;
    Ok(solvency_bound)
}

/// The `prev_anchor` witness: zero at genesis, the recorded predecessor
/// anchor otherwise.
fn predecessor_anchor(state: &BrowserNoteState) -> Result<Felt252> {
    if state.is_genesis {
        return Ok(Felt252::ZERO);
    }
    state.prev_anchor.ok_or_else(|| {
        refusal(
            codes::PREV_ANCHOR_MISSING,
            "this signed state was saved without its predecessor's anchor",
        )
    })
}

/// Prove one request at `state`. The returned state records the request's
/// solvency bound as `bound_at_state` (C2): the first request proof at a state
/// fixes it, and a later one with another bound is refused with
/// [`codes::BOUND_FIXED_AT_STATE`] before any proof is made.
pub fn prepare_request_with_prover(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareRequestArgs,
    prover: &RequestProver,
) -> Result<PreparedRequest> {
    let solvency_bound = request_bound(config, state)?;
    if args.client_request_id.trim().is_empty() {
        bail!("client_request_id is required");
    }
    let siblings = siblings_array(args.merkle_siblings)?;
    let payload_hash = canonical_payload_hash(args.payload.as_bytes());
    let current_blinding = parse_scalar(&state.balance_blinding)?;
    let current = stored_commitment(state, &current_blinding)?;
    let rerandomization = random_scalar();
    let anonymous = rerandomize(&current, &rerandomization)?;
    let nullifier = withdrawal_nullifier(state);
    let request_context = canonical_request_context(&args.client_request_id, &payload_hash);
    let public_inputs = RequestPublicInputsV2 {
        protocol_version: state.protocol_version,
        chain_id: state.chain_id,
        contract_address: state.contract_address,
        active_root: args.active_root,
        state_signing_key_x: config.state_signing_key.x,
        state_signing_key_y: config.state_signing_key.y,
        request_time: args.request_time,
        solvency_bound,
        request_nullifier: nullifier,
        authorization_tag: core::authorization_tag(&nullifier, &request_context),
        anonymous_commitment_x: anonymous.x,
        anonymous_commitment_y: anonymous.y,
    };
    let proof = prover
        .prove(
            &public_inputs,
            RequestWitnessData {
                secret: state.secret_s,
                request_context,
                note_id: state.note_id,
                deposit_amount: state.deposit_amount,
                expiry: state.expiry_ts,
                merkle_siblings: siblings,
                current_balance: state.current_balance,
                current_blinding,
                rerandomization,
                current_anchor: state.current_anchor,
                prev_anchor: predecessor_anchor(state)?,
                state_signature: state.state_signature,
            },
        )
        .context("generate request proof")?;
    let request = ApiRequestV2 {
        client_request_id: args.client_request_id.clone(),
        payload: args.payload,
        payload_hash,
        public_inputs,
        proof,
    };
    let journal = PendingRequestJournal {
        exists: true,
        client_request_id: args.client_request_id,
        nullifier,
        payload_hash,
        user_rerandomization: rerandomization,
        created_at_ms: args.created_at_ms,
        prepared_request: request.clone(),
    };
    let mut next = state.clone();
    next.bound_at_state = solvency_bound;
    Ok(PreparedRequest {
        request,
        journal,
        state: next,
    })
}

/// Check a server response against S1–S6 and return the installed successor.
///
/// * S1: the response names the journal's request and nullifier, and the
///   journal was made at this state (`N(s, note_id, τ)`).
/// * S2: the payload hashes to `response_hash`.
/// * S6: the pinned state key signs `(next_commitment, next_anchor)`.
/// * S3: `charge <= bound_at_state`, and the journal's bound is that bound.
/// * S4: `next_anchor == next_anchor(N)`.
/// * S5: `server_update(C + ε·H, charge, δ) == next_commitment`.
///
/// A signed response that fails S3, S4 or S5 is refused with
/// [`codes::INVALID_SUCCESSOR`]: the host treats it as withheld. The
/// successor has `prev_anchor = τ` and `bound_at_state = 0`.
pub fn complete_response(
    config: &BrowserWalletConfig,
    args: CompleteResponseArgs,
) -> Result<BrowserNoteState> {
    let CompleteResponseArgs {
        state,
        journal,
        response,
    } = args;
    validate_state(config, &state)?;
    let current_blinding = parse_scalar(&state.balance_blinding)?;
    let current = stored_commitment(&state, &current_blinding)?;

    // S1
    if !journal.exists
        || response.client_request_id != journal.client_request_id
        || response.request_nullifier != journal.nullifier
    {
        return Err(refusal(
            codes::RESPONSE_IDENTITY_MISMATCH,
            "the response names another request or nullifier than the journal",
        ));
    }
    let nullifier = withdrawal_nullifier(&state);
    let proven = &journal.prepared_request.public_inputs;
    if journal.nullifier != nullifier
        || proven.request_nullifier != nullifier
        || proven.protocol_version != state.protocol_version
        || proven.chain_id != state.chain_id
        || proven.contract_address != state.contract_address
        || journal.prepared_request.client_request_id != journal.client_request_id
    {
        return Err(refusal(
            codes::JOURNAL_STATE_MISMATCH,
            "the journal was not made at this note state",
        ));
    }
    // S2
    if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
        return Err(refusal(
            codes::RESPONSE_HASH_MISMATCH,
            "the response payload does not hash to response_hash",
        ));
    }
    // S6
    verify_successor_signature(config, &state, &response)?;
    // S3
    if state.bound_at_state == 0 || proven.solvency_bound != state.bound_at_state {
        return Err(invalid_successor(
            "S3",
            format!(
                "the journal's solvency bound {} is not this state's bound {}",
                proven.solvency_bound, state.bound_at_state
            ),
        ));
    }
    if response.charge_applied > state.bound_at_state {
        return Err(invalid_successor(
            "S3",
            format!(
                "charge {} exceeds the state's bound {}",
                response.charge_applied, state.bound_at_state
            ),
        ));
    }
    // S4
    check_derived_anchor(&nullifier, &response.next_anchor)?;
    // S5
    let anonymous = rerandomize(&current, &journal.user_rerandomization)?;
    let expected = server_update(
        &anonymous,
        response.charge_applied,
        &response.blind_delta_srv,
    )?;
    if expected != response.next_commitment {
        return Err(invalid_successor(
            "S5",
            "the successor commitment is not C + ε·H − charge·G + δ·H",
        ));
    }
    let next_blinding = add_blindings(
        &add_blindings(&current_blinding, &journal.user_rerandomization),
        &response.blind_delta_srv,
    );
    let mut next = state;
    next.prev_anchor = Some(next.current_anchor);
    next.current_balance = next
        .current_balance
        .checked_sub(response.charge_applied)
        .ok_or_else(|| invalid_successor("S3", "charge exceeds balance"))?;
    next.balance_blinding = next_blinding.to_hex();
    next.current_commitment_x = response.next_commitment.x;
    next.current_commitment_y = response.next_commitment.y;
    next.current_anchor = response.next_anchor;
    next.is_genesis = false;
    next.state_signature = Some(response.next_state_signature);
    next.bound_at_state = 0;
    Ok(next)
}

fn verify_successor_signature(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    response: &RequestResponseV2,
) -> Result<()> {
    let message = core::state_message(
        state.protocol_version,
        state.chain_id,
        &state.contract_address,
        &response.next_commitment.x,
        &response.next_commitment.y,
        &response.next_anchor,
    );
    if !verify_signature(
        &config.state_signing_key,
        &message,
        &response.next_state_signature,
    )? {
        return Err(refusal(
            codes::SUCCESSOR_SIGNATURE_INVALID,
            "the successor is not signed by the pinned state key",
        ));
    }
    Ok(())
}

/// S4: a successor must sit at `next_anchor(N)`. A random anchor or the
/// genesis anchor (a born-spent successor) is refused.
fn check_derived_anchor(nullifier: &Felt252, next_anchor: &Felt252) -> Result<()> {
    if *next_anchor != core::next_anchor(nullifier)
        || next_anchor.is_zero()
        || *next_anchor == core::GENESIS_ANCHOR
    {
        return Err(invalid_successor(
            "S4",
            "the successor is not at the derived anchor next_anchor(N)",
        ));
    }
    Ok(())
}

/// What a finalized response proves about a state whose request journal (or
/// its rerandomization ε) is lost: it passes S1, S2, S4 and S6, so its charge
/// may lower an escape's concession to `min(charge, bound_at_state)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnrecoverableResponse {
    pub charge_applied: u128,
    pub next_anchor: Felt252,
}

/// Check a finalized response at `state` that cannot be installed because
/// its journal is lost: S1 (it names this state's nullifier), S2, S6 and S4.
/// S3 and S5 need the journal.
pub fn check_unrecoverable_response(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    response: &RequestResponseV2,
) -> Result<UnrecoverableResponse> {
    validate_state(config, state)?;
    let nullifier = withdrawal_nullifier(state);
    if response.request_nullifier != nullifier {
        return Err(refusal(
            codes::RESPONSE_IDENTITY_MISMATCH,
            "the response names another nullifier than this state's",
        ));
    }
    if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
        return Err(refusal(
            codes::RESPONSE_HASH_MISMATCH,
            "the response payload does not hash to response_hash",
        ));
    }
    verify_successor_signature(config, state, response)?;
    check_derived_anchor(&nullifier, &response.next_anchor)?;
    Ok(UnrecoverableResponse {
        charge_applied: response.charge_applied,
        next_anchor: response.next_anchor,
    })
}

/// The withdrawal statement for `args` at `state` and the clearance
/// signature a mutual close carries. Checks every argument before any key
/// is loaded.
fn withdrawal_statement(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: &PrepareWithdrawalArgs,
) -> Result<(WithdrawalPublicInputsV2, Option<SchnorrSignature>)> {
    validate_state(config, state)?;
    predecessor_anchor(state)?;
    if args.valid_until == 0 {
        return Err(refusal(codes::WITHDRAWAL_ARGS, "valid_until must be set"));
    }
    let destination = withdrawal_destination(&args.destination)?;
    if destination == [0u8; 20] {
        return Err(refusal(
            codes::WITHDRAWAL_ARGS,
            "a withdrawal needs a nonzero destination",
        ));
    }
    let nullifier = withdrawal_nullifier(state);
    let (has_clearance, clearance_signature, next_nullifier) = match args.mode.as_str() {
        "mutual" => {
            if args.conceded != 0 {
                return Err(refusal(
                    codes::WITHDRAWAL_ARGS,
                    "only an escape may concede; a mutual close concedes 0",
                ));
            }
            let clearance = args.clearance.as_ref().ok_or_else(|| {
                refusal(
                    codes::WITHDRAWAL_ARGS,
                    "a mutual close requires server clearance",
                )
            })?;
            if clearance.withdrawal_nullifier != nullifier {
                bail!("clearance nullifier mismatch");
            }
            let message = core::clearance_message(
                state.protocol_version,
                state.chain_id,
                &state.contract_address,
                &nullifier,
            );
            if !verify_signature(
                &config.clearance_signing_key,
                &message,
                &clearance.signature,
            )? {
                bail!("invalid clearance signature");
            }
            (true, Some(clearance.signature), Felt252::ZERO)
        }
        "escape" => {
            if args.clearance.is_some() {
                return Err(refusal(
                    codes::WITHDRAWAL_ARGS,
                    "an escape takes no clearance",
                ));
            }
            if args.conceded > state.bound_at_state {
                return Err(refusal(
                    codes::CONCEDED_EXCEEDS_BOUND,
                    format!(
                        "conceded {} exceeds the state's bound {}",
                        args.conceded, state.bound_at_state
                    ),
                ));
            }
            (false, None, successor_nullifier(state))
        }
        other => {
            return Err(refusal(
                codes::WITHDRAWAL_ARGS,
                format!("withdrawal mode must be escape or mutual, not {other:?}"),
            ))
        }
    };
    // bound_at_state <= current_balance (validate_state), so this never wraps.
    let final_balance = state.current_balance - args.conceded;
    Ok((
        WithdrawalPublicInputsV2 {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            registration: core::registration_commitment(&state.secret_s),
            state_signing_key_x: config.state_signing_key.x,
            state_signing_key_y: config.state_signing_key.y,
            clearance_signing_key_x: config.clearance_signing_key.x,
            clearance_signing_key_y: config.clearance_signing_key.y,
            note_id: state.note_id,
            deposit_amount: state.deposit_amount,
            expiry_ts: state.expiry_ts,
            final_balance,
            destination,
            withdrawal_nullifier: nullifier,
            has_clearance,
            next_nullifier,
            conceded: args.conceded,
            valid_until: args.valid_until,
        },
        clearance_signature,
    ))
}

pub fn prepare_withdrawal(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareWithdrawalArgs,
    proving_key: &[u8],
) -> Result<WithdrawalPlan> {
    let (public_inputs, clearance_signature) = withdrawal_statement(config, state, &args)?;
    let proof = WithdrawalProver::from_bytes(proving_key)?
        .prove(
            &public_inputs,
            WithdrawalWitnessData {
                secret: state.secret_s,
                current_balance: state.current_balance,
                final_blinding: parse_scalar(&state.balance_blinding)?,
                current_anchor: state.current_anchor,
                prev_anchor: predecessor_anchor(state)?,
                state_signature: state.state_signature,
                clearance_signature,
            },
        )
        .context("generate withdrawal proof")?;
    Ok(WithdrawalPlan {
        mode: args.mode,
        public_inputs,
        proof,
    })
}

fn validate_state_identity(
    config: &BrowserWalletConfig,
    secret: Felt252,
    amount: u128,
) -> Result<()> {
    if config.protocol_version != 2 {
        bail!("unsupported protocol version {}", config.protocol_version);
    }
    if config.contract_address.is_zero() || secret.is_zero() || amount == 0 {
        bail!("deposit identity contains a zero value");
    }
    Ok(())
}

fn validate_state(config: &BrowserWalletConfig, state: &BrowserNoteState) -> Result<()> {
    if state.protocol_version != config.protocol_version
        || state.chain_id != config.chain_id
        || state.contract_address != config.contract_address
    {
        return Err(refusal(
            codes::STATE_INVALID,
            "wallet state belongs to a different zkAPI deployment",
        ));
    }
    validate_state_identity(config, state.secret_s, state.deposit_amount)?;
    let genesis = state.current_anchor == core::GENESIS_ANCHOR;
    if state.is_genesis != genesis
        || (genesis
            && (state.state_signature.is_some()
                || state.prev_anchor.is_some()
                || state.current_balance != state.deposit_amount))
        || (!genesis && state.state_signature.is_none())
        || state.current_balance > state.deposit_amount
        || state.bound_at_state > state.current_balance
    {
        return Err(refusal(
            codes::STATE_INVALID,
            "the note state is inconsistent (genesis flag, signature, balance or bound)",
        ));
    }
    Ok(())
}

fn stored_commitment(state: &BrowserNoteState, blinding: &Felt252) -> Result<CurvePointWire> {
    let commitment = balance_commitment(state.current_balance, blinding, &state_note_leaf(state));
    if commitment.x != state.current_commitment_x || commitment.y != state.current_commitment_y {
        return Err(refusal(
            codes::STATE_INVALID,
            "persisted balance commitment is inconsistent",
        ));
    }
    Ok(commitment)
}

fn parse_scalar(value: &str) -> Result<Felt252> {
    Felt252::from_hex(value).map_err(|error| anyhow!("invalid balance blinding: {error}"))
}

fn siblings_array(values: Vec<Felt252>) -> Result<[Felt252; MERKLE_DEPTH]> {
    let count = values.len();
    values
        .try_into()
        .map_err(|_| anyhow!("expected {MERKLE_DEPTH} Merkle siblings, got {count}"))
}

/// Accept a u128 as a JSON number or a decimal string (JavaScript numbers
/// lose precision above 2^53).
fn deserialize_u128_or_decimal_string<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;
    impl serde::de::Visitor<'_> for Visitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an unsigned integer or a decimal string")
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u128, E> {
            Ok(value.into())
        }

        fn visit_u128<E: serde::de::Error>(self, value: u128) -> Result<u128, E> {
            Ok(value)
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<u128, E> {
            u128::try_from(value).map_err(|_| E::custom("negative amount"))
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<u128, E> {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(E::custom("amount must be a decimal string"));
            }
            value.parse().map_err(E::custom)
        }
    }
    deserializer.deserialize_any(Visitor)
}

/// The 20-byte statement binding of a canonical, nonzero base58 Solana
/// destination account.
fn withdrawal_destination(value: &str) -> Result<[u8; 20]> {
    let bytes = bs58::decode(value)
        .into_vec()
        .context("destination is not a base58 Solana account")?;
    let account: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("destination must be a 32-byte Solana account"))?;
    if account == [0; 32] || bs58::encode(account).into_string() != value {
        bail!("destination must be a canonical nonzero Solana account");
    }
    Ok(zkapi_types::solana_destination_binding(&account))
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    fn encode<T: Serialize>(value: &T) -> std::result::Result<String, JsValue> {
        let mut value = serde_json::to_value(value).map_err(js_error)?;
        stringify_chain_ids(&mut value);
        serde_json::to_string(&value).map_err(js_error)
    }

    /// Browser-visible protocol objects must never expose an exact u64 chain
    /// identity as a JavaScript Number. This also covers nested shared public
    /// input structs without changing their existing Rust/HTTP serialization.
    fn stringify_chain_ids(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(chain_id) = object.get_mut("chain_id") {
                    if let Some(number) = chain_id.as_u64() {
                        *chain_id = serde_json::Value::String(number.to_string());
                    }
                }
                for child in object.values_mut() {
                    stringify_chain_ids(child);
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    stringify_chain_ids(child);
                }
            }
            _ => {}
        }
    }

    fn decode<T: for<'de> Deserialize<'de>>(value: &str) -> std::result::Result<T, JsValue> {
        serde_json::from_str(value).map_err(js_error)
    }

    fn js_error(error: impl std::fmt::Display) -> JsValue {
        JsValue::from_str(&error.to_string())
    }

    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();
    }

    #[wasm_bindgen]
    pub fn browser_circuit_id() -> String {
        zkapi_proof::compact::CIRCUIT_ID.to_owned()
    }

    #[wasm_bindgen]
    pub fn browser_generate_deposit() -> std::result::Result<String, JsValue> {
        encode(&generate_deposit_params())
    }

    #[wasm_bindgen]
    pub fn browser_confirm_deposit(
        config_json: &str,
        args_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(&confirm_deposit(&decode(config_json)?, decode(args_json)?).map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub fn browser_wallet_status(
        state_json: Option<String>,
        journal_json: Option<String>,
    ) -> std::result::Result<String, JsValue> {
        let state = state_json.as_deref().map(decode).transpose()?;
        let journal = journal_json.as_deref().map(decode).transpose()?;
        encode(&wallet_status(state.as_ref(), journal.as_ref()))
    }

    #[wasm_bindgen]
    pub fn browser_prepare_request(
        config_json: &str,
        state_json: &str,
        args_json: &str,
        proving_key: &[u8],
    ) -> std::result::Result<String, JsValue> {
        encode(
            &prepare_request(
                &decode(config_json)?,
                &decode(state_json)?,
                decode(args_json)?,
                proving_key,
            )
            .map_err(js_error)?,
        )
    }

    #[wasm_bindgen]
    pub struct BrowserRequestProver {
        prover: RequestProver,
    }

    #[wasm_bindgen]
    impl BrowserRequestProver {
        #[wasm_bindgen(constructor)]
        pub fn new(proving_key: &[u8]) -> std::result::Result<BrowserRequestProver, JsValue> {
            Ok(Self {
                prover: RequestProver::from_bytes(proving_key).map_err(js_error)?,
            })
        }

        pub fn prepare_request(
            &self,
            config_json: &str,
            state_json: &str,
            args_json: &str,
        ) -> std::result::Result<String, JsValue> {
            encode(
                &prepare_request_with_prover(
                    &decode(config_json)?,
                    &decode(state_json)?,
                    decode(args_json)?,
                    &self.prover,
                )
                .map_err(js_error)?,
            )
        }
    }

    #[wasm_bindgen]
    pub fn browser_complete_response(
        config_json: &str,
        args_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(&complete_response(&decode(config_json)?, decode(args_json)?).map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub fn browser_check_unrecoverable_response(
        config_json: &str,
        state_json: &str,
        response_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(
            &check_unrecoverable_response(
                &decode(config_json)?,
                &decode(state_json)?,
                &decode(response_json)?,
            )
            .map_err(js_error)?,
        )
    }

    #[wasm_bindgen]
    pub fn browser_withdrawal_nullifier(state_json: &str) -> std::result::Result<String, JsValue> {
        encode(&withdrawal_nullifier(&decode(state_json)?))
    }

    #[wasm_bindgen]
    pub fn browser_successor_nullifier(state_json: &str) -> std::result::Result<String, JsValue> {
        encode(&successor_nullifier(&decode(state_json)?))
    }

    #[wasm_bindgen]
    pub fn browser_tree_path(
        snapshot_json: &str,
        note_id: u32,
        require_existing: bool,
    ) -> std::result::Result<String, JsValue> {
        encode(&tree_path(decode(snapshot_json)?, note_id, require_existing).map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub fn browser_prepare_withdrawal(
        config_json: &str,
        state_json: &str,
        args_json: &str,
        proving_key: &[u8],
    ) -> std::result::Result<String, JsValue> {
        encode(
            &prepare_withdrawal(
                &decode(config_json)?,
                &decode(state_json)?,
                decode(args_json)?,
                proving_key,
            )
            .map_err(js_error)?,
        )
    }
}

fn state_note_leaf(state: &BrowserNoteState) -> Felt252 {
    core::note_leaf(
        state.note_id,
        &core::registration_commitment(&state.secret_s),
        state.deposit_amount,
        state.expiry_ts,
    )
}

#[cfg(test)]
mod tests;
