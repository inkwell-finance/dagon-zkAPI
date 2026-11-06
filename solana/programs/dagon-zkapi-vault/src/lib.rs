#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer};
use dagon_zkapi_solana::{verify_request_bytes, verify_transition_bytes, verify_withdrawal_bytes};
use sha3::{Digest, Keccak256};
use zkapi_core::v2::EMPTY_MERKLE_ROOT;
use zkapi_types::{
    solana_chain_id, solana_deployment_binding, solana_destination_matches, Felt252,
    RequestPublicInputsV2, SolanaMerkleTransitionInputs, WithdrawalPublicInputsV2,
    PROTOCOL_VERSION,
};

declare_id!("7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H");

pub const VAULT_VERSION: u8 = 1;
pub const NOTE_STATUS_ACTIVE: u8 = 1;
pub const NOTE_STATUS_PENDING: u8 = 2;
// Status 3 is reserved for the removed two-phase challenge protocol.
pub const NOTE_STATUS_CLOSED: u8 = 4;
pub const NOTE_STATUS_RETIRED: u8 = 5;
pub const NULLIFIER_RELEASED: u8 = 0;
pub const NULLIFIER_CONSUMED: u8 = 1;
pub const NULLIFIER_CHALLENGED: u8 = 2;
pub const MAX_PAUSE_DURATION: u64 = 7 * 86_400;
pub const PAUSE_COOLDOWN: u64 = 86_400;
const EXPIRY_BUCKET_SECONDS: u64 = 86_400;
const MAX_CREDIT_UNITS: u64 = 9_007_199_254_740_991;
const MAX_OPERATION_BYTES: usize = 4_096;
const MAX_OPERATION_LIFETIME_SLOTS: u64 = 10_000;
const KIND_DEPOSIT: u8 = 1;

#[program]
pub mod dagon_zkapi_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, args: InitializeArgs) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        validate_initialize_configuration(&args, vault_key, ctx.accounts.treasury.key())?;
        let chain_id = solana_chain_id(&args.genesis_hash);
        let binding = solana_deployment_binding(
            &ctx.program_id.to_bytes(),
            &vault_key.to_bytes(),
            &args.genesis_hash,
        );
        let vault = &mut ctx.accounts.vault;
        vault.version = VAULT_VERSION;
        vault.bump = ctx.bumps.vault;
        vault.paused = false;
        vault.authority = ctx.accounts.authority.key();
        vault.treasury = ctx.accounts.treasury.key();
        vault.genesis_hash = args.genesis_hash;
        vault.chain_id = chain_id;
        vault.protocol_binding = *binding.as_bytes();
        vault.current_root = *EMPTY_MERKLE_ROOT.as_bytes();
        vault.next_note_id = 0;
        vault.note_ttl = args.note_ttl;
        vault.challenge_period = args.challenge_period;
        vault.request_charge_cap = args.request_charge_cap;
        vault.total_credits = 0;
        vault.state_signing_key_x = args.state_signing_key_x;
        vault.state_signing_key_y = args.state_signing_key_y;
        vault.clearance_signing_key_x = args.clearance_signing_key_x;
        vault.clearance_signing_key_y = args.clearance_signing_key_y;
        Ok(())
    }

    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        update_pause(&mut ctx.accounts.vault, paused, unix_timestamp()?)
    }

    pub fn initialize_operation(
        ctx: Context<InitializeOperation>,
        args: InitializeOperationArgs,
    ) -> Result<()> {
        require!(
            is_operation_kind(args.kind),
            VaultError::InvalidOperationKind
        );
        let total_len = usize::from(args.total_len);
        require!(
            total_len > 0 && total_len <= MAX_OPERATION_BYTES,
            VaultError::InvalidOperationLength
        );
        let slot = Clock::get()?.slot;
        require!(
            args.expires_at_slot > slot
                && args.expires_at_slot <= slot.saturating_add(MAX_OPERATION_LIFETIME_SLOTS),
            VaultError::InvalidOperationExpiry
        );
        require!(args.digest != [0; 32], VaultError::InvalidOperationDigest);

        let operation = &mut ctx.accounts.operation;
        operation.vault = ctx.accounts.vault.key();
        operation.owner = ctx.accounts.owner.key();
        operation.operation_id = args.operation_id;
        operation.kind = args.kind;
        operation.total_len = args.total_len;
        operation.written_len = 0;
        operation.digest = args.digest;
        operation.expires_at_slot = args.expires_at_slot;
        operation.payload = vec![0; total_len];
        operation.bump = ctx.bumps.operation;
        Ok(())
    }

    pub fn write_operation(
        ctx: Context<WriteOperation>,
        offset: u16,
        chunk: Vec<u8>,
    ) -> Result<()> {
        let operation = &mut ctx.accounts.operation;
        require!(
            Clock::get()?.slot <= operation.expires_at_slot,
            VaultError::OperationExpired
        );
        require!(
            !chunk.is_empty() && chunk.len() <= 800,
            VaultError::InvalidOperationLength
        );
        require!(
            offset == operation.written_len,
            VaultError::OperationWriteOutOfOrder
        );
        let end = usize::from(offset)
            .checked_add(chunk.len())
            .ok_or(VaultError::InvalidOperationLength)?;
        require!(
            end <= usize::from(operation.total_len),
            VaultError::InvalidOperationLength
        );
        operation.payload[usize::from(offset)..end].copy_from_slice(&chunk);
        operation.written_len =
            u16::try_from(end).map_err(|_| VaultError::InvalidOperationLength)?;
        Ok(())
    }

    /// Close an incomplete, stale, or otherwise abandoned staged operation and
    /// return its rent to the signer that created it.
    pub fn cancel_operation(_ctx: Context<CancelOperation>) -> Result<()> {
        Ok(())
    }

    pub fn execute_deposit(ctx: Context<ExecuteDeposit>, expected_note_id: u32) -> Result<()> {
        let payload: DepositPayload = decode_operation(&ctx.accounts.operation, KIND_DEPOSIT)?;
        require!(
            payload.expected_note_id == expected_note_id,
            VaultError::OperationMismatch
        );
        let vault = &mut ctx.accounts.vault;
        require!(!vault.paused, VaultError::Paused);
        require!(
            vault.next_note_id == expected_note_id,
            VaultError::StaleNoteId
        );
        require!(
            payload.amount > 0 && payload.amount <= MAX_CREDIT_UNITS,
            VaultError::InvalidAmount
        );
        let registration = checked_felt(payload.commitment)?;
        require!(registration != Felt252::ZERO, VaultError::InvalidField);
        let expiry = bucket_expiry(unix_timestamp()?, vault.note_ttl)?;
        require!(payload.expiry == expiry, VaultError::InvalidOperationExpiry);
        let new_root = verify_note_transition(
            vault,
            expected_note_id,
            payload.commitment,
            payload.amount,
            expiry,
            payload.new_root,
            true,
            &payload.transition_proof,
        )?;

        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.owner.to_account_info(),
                    to: vault.to_account_info(),
                },
            ),
            payload.amount,
        )?;
        vault.total_credits = vault
            .total_credits
            .checked_add(payload.amount)
            .ok_or(VaultError::ArithmeticOverflow)?;
        vault.current_root = *new_root.as_bytes();
        vault.next_note_id = vault
            .next_note_id
            .checked_add(1)
            .ok_or(VaultError::ArithmeticOverflow)?;

        let note = &mut ctx.accounts.note;
        note.vault = vault.key();
        note.note_id = expected_note_id;
        note.commitment = payload.commitment;
        note.deposit_amount = payload.amount;
        note.expiry = expiry;
        note.status = NOTE_STATUS_ACTIVE;
        note.bump = ctx.bumps.note;
        note.claimable_after = expiry;
        note.paused_offset = paused_duration_now(vault, unix_timestamp()?)?;
        ensure_solvency(vault)?;
        emit!(NoteDeposited {
            note_id: expected_note_id,
            commitment: payload.commitment,
            amount: payload.amount,
            expiry,
            new_root: vault.current_root,
        });
        Ok(())
    }

    pub fn execute_close(
        ctx: Context<ExecuteClose>,
        note_id: u32,
        payload: WithdrawalPayload,
    ) -> Result<()> {
        let now = unix_timestamp()?;
        validate_withdrawal(&ctx.accounts.vault, &ctx.accounts.note, &payload,
            &ctx.accounts.destination.key(), true, now)?;
        let inputs = &payload.public_inputs;
        require!(inputs.note_id == note_id, VaultError::NoteMismatch);
        require_unused_nullifier(&ctx.accounts.used_nullifier, false)?;
        verify_withdrawal_bytes(&inputs.to_wire()?, &payload.proof)
            .map_err(|_| VaultError::InvalidProof)?;
        write_nullifier(&ctx.accounts.used_nullifier, &ctx.accounts.owner,
            &ctx.accounts.system_program, ctx.accounts.vault.key(),
            inputs.withdrawal_nullifier, ctx.bumps.used_nullifier, NULLIFIER_CONSUMED)?;
        let deposit = ctx.accounts.note.deposit_amount;
        let final_balance = u64::try_from(inputs.final_balance).map_err(|_| VaultError::InvalidAmount)?;
        ctx.accounts.note.status = NOTE_STATUS_CLOSED;
        let vault = &mut ctx.accounts.vault;
        vault.total_credits = vault.total_credits.checked_sub(deposit)
            .ok_or(VaultError::ArithmeticOverflow)?;
        pay_from_vault(vault, &ctx.accounts.destination.to_account_info(), final_balance,
            deposit - final_balance)?;
        ensure_solvency(vault)?;
        emit!(MutualClose { note_id, nullifier: inputs.withdrawal_nullifier,
            final_balance, destination: ctx.accounts.destination.key(), new_root: vault.current_root });
        Ok(())
    }

    pub fn execute_escape(
        ctx: Context<ExecuteEscape>,
        note_id: u32,
        payload: WithdrawalPayload,
    ) -> Result<()> {
        let now = unix_timestamp()?;
        validate_withdrawal(&ctx.accounts.vault, &ctx.accounts.note, &payload,
            &ctx.accounts.destination.key(), false, now)?;
        let inputs = &payload.public_inputs;
        require!(inputs.note_id == note_id, VaultError::NoteMismatch);
        require_unused_nullifier(&ctx.accounts.used_nullifier, false)?;
        require_unused_nullifier(&ctx.accounts.next_nullifier, true)?;
        verify_withdrawal_bytes(&inputs.to_wire()?, &payload.proof)
            .map_err(|_| VaultError::InvalidProof)?;
        write_nullifier(&ctx.accounts.used_nullifier, &ctx.accounts.owner,
            &ctx.accounts.system_program, ctx.accounts.vault.key(),
            inputs.withdrawal_nullifier, ctx.bumps.used_nullifier, NULLIFIER_CONSUMED)?;
        write_nullifier(&ctx.accounts.next_nullifier, &ctx.accounts.owner,
            &ctx.accounts.system_program, ctx.accounts.vault.key(),
            inputs.next_nullifier, ctx.bumps.next_nullifier, NULLIFIER_CONSUMED)?;
        ctx.accounts.note.status = NOTE_STATUS_PENDING;
        let pending = &mut ctx.accounts.pending;
        pending.vault = ctx.accounts.vault.key();
        pending.note_id = note_id;
        pending.nullifier = inputs.withdrawal_nullifier;
        pending.next_nullifier = inputs.next_nullifier;
        pending.final_balance = u64::try_from(inputs.final_balance).map_err(|_| VaultError::InvalidAmount)?;
        pending.conceded = u64::try_from(inputs.conceded).map_err(|_| VaultError::InvalidAmount)?;
        pending.state_balance = pending.final_balance.checked_add(pending.conceded)
            .ok_or(VaultError::ArithmeticOverflow)?;
        pending.destination = ctx.accounts.destination.key();
        pending.deadline = now.checked_add(ctx.accounts.vault.challenge_period)
            .ok_or(VaultError::ArithmeticOverflow)?;
        pending.bump = ctx.bumps.pending;
        emit!(EscapeWithdrawalInitiated { note_id, nullifier: pending.nullifier,
            next_nullifier: pending.next_nullifier, final_balance: pending.final_balance,
            conceded: pending.conceded, destination: pending.destination, deadline: pending.deadline });
        Ok(())
    }

    pub fn execute_challenge(
        ctx: Context<ExecuteChallenge>,
        note_id: u32,
        payload: ChallengePayload,
    ) -> Result<()> {
        apply_escape_challenge(&ctx.accounts.vault, &mut ctx.accounts.note,
            &ctx.accounts.pending, &payload, note_id, unix_timestamp()?)?;
        ctx.accounts.used_nullifier.status = NULLIFIER_CHALLENGED;
        ctx.accounts.next_nullifier.status = NULLIFIER_RELEASED;
        emit!(EscapeWithdrawalDefeated { note_id, nullifier: ctx.accounts.pending.nullifier,
            next_nullifier: ctx.accounts.pending.next_nullifier });
        Ok(())
    }

    pub fn raise_escape_concession(
        ctx: Context<RaiseEscapeConcession>,
        note_id: u32,
        payload: ChallengePayload,
        amount: u128,
    ) -> Result<()> {
        apply_raise_concession(&ctx.accounts.vault, &ctx.accounts.note,
            &mut ctx.accounts.pending, &payload, note_id, amount, unix_timestamp()?)?;
        emit!(EscapeConcessionRaised { note_id, nullifier: ctx.accounts.pending.nullifier,
            conceded: ctx.accounts.pending.conceded, final_balance: ctx.accounts.pending.final_balance });
        Ok(())
    }

    pub fn retire_closed_leaf(
        ctx: Context<RetireClosedLeaf>,
        note_id: u32,
        new_root: [u8; 32],
        transition_proof: Vec<u8>,
    ) -> Result<()> {
        require!(ctx.accounts.note.status == NOTE_STATUS_CLOSED, VaultError::NoteNotClosed);
        let note = &ctx.accounts.note;
        let root = verify_note_transition(&ctx.accounts.vault, note_id, note.commitment,
            note.deposit_amount, note.expiry, new_root, false, &transition_proof)?;
        ctx.accounts.vault.current_root = *root.as_bytes();
        ctx.accounts.note.status = NOTE_STATUS_RETIRED;
        emit!(ClosedLeafRetired { note_id, new_root });
        Ok(())
    }

    pub fn finalize_escape(ctx: Context<FinalizeEscape>, note_id: u32) -> Result<()> {
        require!(
            ctx.accounts.note.note_id == note_id,
            VaultError::OperationMismatch
        );
        require!(
            ctx.accounts.note.status == NOTE_STATUS_PENDING,
            VaultError::NoteNotPending
        );
        require!(
            ctx.accounts.pending.note_id == note_id,
            VaultError::OperationMismatch
        );
        require!(
            unix_timestamp()? > ctx.accounts.pending.deadline,
            VaultError::ChallengeNotExpired
        );
        require_keys_eq!(
            ctx.accounts.pending.destination,
            ctx.accounts.destination.key()
        );
        let deposit = ctx.accounts.note.deposit_amount;
        let final_balance = ctx.accounts.pending.final_balance;
        let operator_share = deposit
            .checked_sub(final_balance)
            .ok_or(VaultError::InvalidAmount)?;
        let vault = &mut ctx.accounts.vault;
        vault.total_credits = vault
            .total_credits
            .checked_sub(deposit)
            .ok_or(VaultError::ArithmeticOverflow)?;
        ctx.accounts.note.status = NOTE_STATUS_CLOSED;
        pay_from_vault(
            vault,
            &ctx.accounts.destination.to_account_info(),
            final_balance,
            operator_share,
        )?;
        ensure_solvency(vault)?;
        emit!(EscapeWithdrawalFinalized {
            note_id,
            nullifier: ctx.accounts.pending.nullifier,
            final_balance,
            destination: ctx.accounts.destination.key(),
        });
        Ok(())
    }

    pub fn execute_claim_expired(ctx: Context<ExecuteClaimExpired>, note_id: u32) -> Result<()> {
        validate_expired_claim(&ctx.accounts.vault, &ctx.accounts.note, note_id, unix_timestamp()?)?;
        let amount = ctx.accounts.note.deposit_amount;
        let vault = &mut ctx.accounts.vault;
        ctx.accounts.note.status = NOTE_STATUS_CLOSED;
        vault.total_credits = vault
            .total_credits
            .checked_sub(amount)
            .ok_or(VaultError::ArithmeticOverflow)?;
        accrue_treasury(vault, amount)?;
        ensure_solvency(vault)?;
        emit!(ExpiredClaimed {
            note_id,
            amount,
            new_root: vault.current_root,
        });
        Ok(())
    }

    /// Anyone can flush accrued operator revenue to the pinned treasury. A
    /// treasury that cannot receive SOL can fail only this separate transaction.
    pub fn withdraw_treasury(ctx: Context<WithdrawTreasury>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let amount = vault.treasury_accrued;
        vault.treasury_accrued = 0;
        transfer_owned_lamports(&vault.to_account_info(), &ctx.accounts.treasury.to_account_info(), amount)?;
        ensure_solvency(vault)?;
        emit!(TreasuryWithdrawn { amount });
        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeArgs {
    pub genesis_hash: [u8; 32],
    pub note_ttl: u64,
    pub challenge_period: u64,
    pub request_charge_cap: u64,
    pub state_signing_key_x: [u8; 32],
    pub state_signing_key_y: [u8; 32],
    pub clearance_signing_key_x: [u8; 32],
    pub clearance_signing_key_y: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeOperationArgs {
    pub operation_id: [u8; 32],
    pub kind: u8,
    pub total_len: u16,
    pub digest: [u8; 32],
    pub expires_at_slot: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct DepositPayload {
    pub expected_note_id: u32,
    pub commitment: [u8; 32],
    pub amount: u64,
    pub expiry: u64,
    pub new_root: [u8; 32],
    pub transition_proof: Vec<u8>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawalPayload {
    pub destination: Pubkey,
    pub public_inputs: WithdrawalInputs,
    pub proof: Vec<u8>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ChallengePayload {
    pub note_id: u32,
    pub public_inputs: RequestInputs,
    pub proof: Vec<u8>,
}


#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RequestInputs {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: [u8; 32],
    pub active_root: [u8; 32],
    pub state_signing_key_x: [u8; 32],
    pub state_signing_key_y: [u8; 32],
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_nullifier: [u8; 32],
    pub authorization_tag: [u8; 32],
    pub anonymous_commitment_x: [u8; 32],
    pub anonymous_commitment_y: [u8; 32],
}

impl RequestInputs {
    fn to_wire(&self) -> Result<RequestPublicInputsV2> {
        Ok(RequestPublicInputsV2 {
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            contract_address: checked_felt(self.contract_address)?,
            active_root: checked_felt(self.active_root)?,
            state_signing_key_x: checked_felt(self.state_signing_key_x)?,
            state_signing_key_y: checked_felt(self.state_signing_key_y)?,
            request_time: self.request_time,
            solvency_bound: self.solvency_bound,
            request_nullifier: checked_felt(self.request_nullifier)?,
            authorization_tag: checked_felt(self.authorization_tag)?,
            anonymous_commitment_x: checked_felt(self.anonymous_commitment_x)?,
            anonymous_commitment_y: checked_felt(self.anonymous_commitment_y)?,
        })
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawalInputs {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: [u8; 32],
    pub registration: [u8; 32],
    pub state_signing_key_x: [u8; 32],
    pub state_signing_key_y: [u8; 32],
    pub clearance_signing_key_x: [u8; 32],
    pub clearance_signing_key_y: [u8; 32],
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub final_balance: u128,
    pub destination: [u8; 20],
    pub withdrawal_nullifier: [u8; 32],
    pub has_clearance: bool,
    pub next_nullifier: [u8; 32],
    pub conceded: u128,
    pub valid_until: u64,
}

impl WithdrawalInputs {
    fn to_wire(&self) -> Result<WithdrawalPublicInputsV2> {
        Ok(WithdrawalPublicInputsV2 {
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            contract_address: checked_felt(self.contract_address)?,
            registration: checked_felt(self.registration)?,
            state_signing_key_x: checked_felt(self.state_signing_key_x)?,
            state_signing_key_y: checked_felt(self.state_signing_key_y)?,
            clearance_signing_key_x: checked_felt(self.clearance_signing_key_x)?,
            clearance_signing_key_y: checked_felt(self.clearance_signing_key_y)?,
            note_id: self.note_id,
            deposit_amount: self.deposit_amount,
            expiry_ts: self.expiry_ts,
            final_balance: self.final_balance,
            destination: self.destination,
            withdrawal_nullifier: checked_felt(self.withdrawal_nullifier)?,
            has_clearance: self.has_clearance,
            next_nullifier: checked_felt(self.next_nullifier)?,
            conceded: self.conceded,
            valid_until: self.valid_until,
        })
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + VaultState::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: public payout account pinned in vault state.
    pub treasury: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetPaused<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, VaultState>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(args: InitializeOperationArgs)]
pub struct InitializeOperation<'info> {
    pub vault: Account<'info, VaultState>,
    #[account(
        init,
        payer = owner,
        space = OperationBuffer::space(usize::from(args.total_len)),
        seeds = [b"operation", vault.key().as_ref(), owner.key().as_ref(), &args.operation_id],
        bump
    )]
    pub operation: Account<'info, OperationBuffer>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WriteOperation<'info> {
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        constraint = operation.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = operation.owner == owner.key() @ VaultError::Unauthorized
    )]
    pub operation: Account<'info, OperationBuffer>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct CancelOperation<'info> {
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        close = owner,
        constraint = operation.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = operation.owner == owner.key() @ VaultError::Unauthorized
    )]
    pub operation: Account<'info, OperationBuffer>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(expected_note_id: u32)]
pub struct ExecuteDeposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        close = owner,
        constraint = operation.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = operation.owner == owner.key() @ VaultError::Unauthorized
    )]
    pub operation: Account<'info, OperationBuffer>,
    #[account(
        init,
        payer = owner,
        space = 8 + NoteState::INIT_SPACE,
        seeds = [b"note", vault.key().as_ref(), &expected_note_id.to_le_bytes()],
        bump
    )]
    pub note: Account<'info, NoteState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(note_id: u32, payload: WithdrawalPayload)]
pub struct ExecuteClose<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        constraint = note.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = note.note_id == note_id @ VaultError::OperationMismatch
    )]
    pub note: Account<'info, NoteState>,
    /// CHECK: PDA seeds checked here; owner, discriminator and status checked before use.
    #[account(mut, seeds = [b"nullifier", vault.key().as_ref(), &payload.public_inputs.withdrawal_nullifier], bump)]
    pub used_nullifier: UncheckedAccount<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: proof-bound payout destination.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(note_id: u32, payload: WithdrawalPayload)]
pub struct ExecuteEscape<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        constraint = note.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = note.note_id == note_id @ VaultError::OperationMismatch
    )]
    pub note: Account<'info, NoteState>,
    #[account(
        init,
        payer = owner,
        space = 8 + PendingWithdrawal::INIT_SPACE,
        seeds = [b"pending", vault.key().as_ref(), &note_id.to_le_bytes()],
        bump
    )]
    pub pending: Account<'info, PendingWithdrawal>,
    /// CHECK: validated and allocated with F7-tolerant create-or-update.
    #[account(mut, seeds = [b"nullifier", vault.key().as_ref(), &payload.public_inputs.withdrawal_nullifier], bump)]
    pub used_nullifier: UncheckedAccount<'info>,
    /// CHECK: validated and allocated with F7-tolerant create-or-update.
    #[account(mut, seeds = [b"nullifier", vault.key().as_ref(), &payload.public_inputs.next_nullifier], bump)]
    pub next_nullifier: UncheckedAccount<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: proof-bound and saved for finalization. Finalize must be able to
    /// credit it, or the note would stay Pending forever with the operator share
    /// locked: it must be writable (a runtime-demoted reserved key such as the
    /// System program or a sysvar is not) and neither the vault nor the pending
    /// account.
    #[account(mut @ VaultError::DestinationNotCreditable,
        constraint = creditable_destination(&destination, &vault.key(), &pending.key())
            @ VaultError::DestinationNotCreditable)]
    pub destination: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(note_id: u32)]
pub struct ExecuteChallenge<'info> {
    /// Root-free evidence does not contend for the vault write lock.
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        constraint = note.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = note.note_id == note_id @ VaultError::OperationMismatch
    )]
    pub note: Account<'info, NoteState>,
    #[account(
        mut,
        close = payer,
        seeds = [b"pending", vault.key().as_ref(), &note_id.to_le_bytes()],
        bump = pending.bump
    )]
    pub pending: Account<'info, PendingWithdrawal>,
    #[account(mut, seeds = [b"nullifier", vault.key().as_ref(), &pending.nullifier],
        bump = used_nullifier.bump, constraint = used_nullifier.status == NULLIFIER_CONSUMED @ VaultError::ReplayedNullifier)]
    pub used_nullifier: Account<'info, UsedNullifier>,
    #[account(mut, seeds = [b"nullifier", vault.key().as_ref(), &pending.next_nullifier],
        bump = next_nullifier.bump, constraint = next_nullifier.status == NULLIFIER_CONSUMED @ VaultError::ReplayedNullifier)]
    pub next_nullifier: Account<'info, UsedNullifier>,
    #[account(mut)]
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(note_id: u32)]
pub struct RaiseEscapeConcession<'info> {
    pub vault: Account<'info, VaultState>,
    #[account(constraint = note.vault == vault.key() @ VaultError::NoteMismatch,
        constraint = note.note_id == note_id @ VaultError::NoteMismatch)]
    pub note: Account<'info, NoteState>,
    #[account(mut, seeds = [b"pending", vault.key().as_ref(), &note_id.to_le_bytes()], bump = pending.bump)]
    pub pending: Account<'info, PendingWithdrawal>,
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(note_id: u32)]
pub struct FinalizeEscape<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        constraint = note.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = note.note_id == note_id @ VaultError::OperationMismatch
    )]
    pub note: Account<'info, NoteState>,
    /// The escaper paid this rent. Refund it to the proof-bound destination, not
    /// to whoever calls the permissionless finalize; it also keeps a dust payout
    /// to a fresh destination rent-exempt.
    #[account(
        mut,
        close = destination,
        seeds = [b"pending", vault.key().as_ref(), &note_id.to_le_bytes()],
        bump = pending.bump
    )]
    pub pending: Account<'info, PendingWithdrawal>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: must match the saved pending destination.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(note_id: u32)]
pub struct ExecuteClaimExpired<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        constraint = note.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = note.note_id == note_id @ VaultError::OperationMismatch
    )]
    pub note: Account<'info, NoteState>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawTreasury<'info> {
    #[account(mut, has_one = treasury)]
    pub vault: Account<'info, VaultState>,
    /// CHECK: the pinned treasury receives only separately withdrawn accrual.
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(note_id: u32)]
pub struct RetireClosedLeaf<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        constraint = note.vault == vault.key() @ VaultError::OperationMismatch,
        constraint = note.note_id == note_id @ VaultError::OperationMismatch
    )]
    pub note: Account<'info, NoteState>,
    pub payer: Signer<'info>,
}


#[account]
#[derive(InitSpace)]
pub struct VaultState {
    pub version: u8,
    pub bump: u8,
    pub paused: bool,
    pub authority: Pubkey,
    pub treasury: Pubkey,
    pub genesis_hash: [u8; 32],
    pub chain_id: u64,
    pub protocol_binding: [u8; 32],
    pub current_root: [u8; 32],
    pub next_note_id: u32,
    pub note_ttl: u64,
    pub challenge_period: u64,
    pub request_charge_cap: u64,
    pub total_credits: u64,
    pub state_signing_key_x: [u8; 32],
    pub state_signing_key_y: [u8; 32],
    pub clearance_signing_key_x: [u8; 32],
    pub clearance_signing_key_y: [u8; 32],
    pub paused_at: u64,
    pub last_pause_end: u64,
    pub total_paused_duration: u64,
    pub treasury_accrued: u64,
}

#[account]
#[derive(InitSpace)]
pub struct NoteState {
    pub vault: Pubkey,
    pub note_id: u32,
    pub commitment: [u8; 32],
    pub deposit_amount: u64,
    pub expiry: u64,
    pub status: u8,
    pub bump: u8,
    pub claimable_after: u64,
    pub paused_offset: u64,
}

#[account]
#[derive(InitSpace)]
pub struct PendingWithdrawal {
    pub vault: Pubkey,
    pub note_id: u32,
    pub nullifier: [u8; 32],
    pub next_nullifier: [u8; 32],
    pub state_balance: u64,
    pub conceded: u64,
    pub final_balance: u64,
    pub destination: Pubkey,
    pub deadline: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct UsedNullifier {
    pub vault: Pubkey,
    pub nullifier: [u8; 32],
    pub bump: u8,
    pub status: u8,
}

#[account]
pub struct OperationBuffer {
    pub vault: Pubkey,
    pub owner: Pubkey,
    pub operation_id: [u8; 32],
    pub kind: u8,
    pub total_len: u16,
    pub written_len: u16,
    pub digest: [u8; 32],
    pub expires_at_slot: u64,
    pub payload: Vec<u8>,
    pub bump: u8,
}

impl OperationBuffer {
    const FIXED_SPACE: usize = 8 + 32 + 32 + 32 + 1 + 2 + 2 + 32 + 8 + 4 + 1;

    pub fn space(payload_len: usize) -> usize {
        Self::FIXED_SPACE.saturating_add(payload_len)
    }
}

#[event]
pub struct NoteDeposited {
    pub note_id: u32,
    pub commitment: [u8; 32],
    pub amount: u64,
    pub expiry: u64,
    pub new_root: [u8; 32],
}

#[event]
pub struct MutualClose {
    pub note_id: u32,
    pub nullifier: [u8; 32],
    pub final_balance: u64,
    pub destination: Pubkey,
    pub new_root: [u8; 32],
}

#[event]
pub struct EscapeWithdrawalInitiated {
    pub note_id: u32,
    pub nullifier: [u8; 32],
    pub next_nullifier: [u8; 32],
    pub conceded: u64,
    pub final_balance: u64,
    pub destination: Pubkey,
    pub deadline: u64,
}

#[event]
pub struct EscapeWithdrawalDefeated {
    pub note_id: u32,
    pub nullifier: [u8; 32],
    pub next_nullifier: [u8; 32],
}

#[event]
pub struct ClosedLeafRetired {
    pub note_id: u32,
    pub new_root: [u8; 32],
}

#[event]
pub struct EscapeConcessionRaised {
    pub note_id: u32,
    pub nullifier: [u8; 32],
    pub conceded: u64,
    pub final_balance: u64,
}

#[event]
pub struct EscapeWithdrawalFinalized {
    pub note_id: u32,
    pub nullifier: [u8; 32],
    pub final_balance: u64,
    pub destination: Pubkey,
}

#[event]
pub struct ExpiredClaimed {
    pub note_id: u32,
    pub amount: u64,
    pub new_root: [u8; 32],
}

fn decode_operation<T: AnchorDeserialize>(operation: &OperationBuffer, kind: u8) -> Result<T> {
    require!(operation.kind == kind, VaultError::InvalidOperationKind);
    require!(
        Clock::get()?.slot <= operation.expires_at_slot,
        VaultError::OperationExpired
    );
    require!(
        operation.written_len == operation.total_len,
        VaultError::OperationIncomplete
    );
    require!(
        Keccak256::digest(&operation.payload).as_slice() == operation.digest,
        VaultError::InvalidOperationDigest
    );
    let mut bytes = operation.payload.as_slice();
    let value = T::deserialize(&mut bytes).map_err(|_| VaultError::InvalidOperationPayload)?;
    require!(bytes.is_empty(), VaultError::InvalidOperationPayload);
    Ok(value)
}

fn is_operation_kind(kind: u8) -> bool {
    kind == KIND_DEPOSIT
}

fn validate_initialize_configuration(
    args: &InitializeArgs,
    vault: Pubkey,
    treasury: Pubkey,
) -> Result<()> {
    require!(
        args.genesis_hash != [0; 32],
        VaultError::InvalidConfiguration
    );
    require!(args.note_ttl > 0, VaultError::InvalidConfiguration);
    require!(args.challenge_period > 0, VaultError::InvalidConfiguration);
    require!(
        args.request_charge_cap > 0 && args.request_charge_cap <= MAX_CREDIT_UNITS,
        VaultError::InvalidConfiguration
    );
    require!(
        treasury != Pubkey::default() && treasury != vault,
        VaultError::InvalidConfiguration
    );
    checked_felt(args.state_signing_key_x)?;
    checked_felt(args.state_signing_key_y)?;
    checked_felt(args.clearance_signing_key_x)?;
    checked_felt(args.clearance_signing_key_y)?;
    require!(
        args.state_signing_key_x != [0; 32] || args.state_signing_key_y != [0; 32],
        VaultError::InvalidConfiguration
    );
    require!(
        args.clearance_signing_key_x != [0; 32] || args.clearance_signing_key_y != [0; 32],
        VaultError::InvalidConfiguration
    );
    require!(
        args.state_signing_key_x != args.clearance_signing_key_x
            || args.state_signing_key_y != args.clearance_signing_key_y,
        VaultError::InvalidConfiguration
    );
    Ok(())
}

fn checked_felt(bytes: [u8; 32]) -> Result<Felt252> {
    Felt252::try_from_bytes_be(bytes).map_err(|_| error!(VaultError::InvalidField))
}

fn unix_timestamp() -> Result<u64> {
    u64::try_from(Clock::get()?.unix_timestamp).map_err(|_| error!(VaultError::InvalidClock))
}

fn bucket_expiry(now: u64, ttl: u64) -> Result<u64> {
    let raw = now.checked_add(ttl).ok_or(VaultError::ArithmeticOverflow)?;
    raw.checked_add(EXPIRY_BUCKET_SECONDS - 1)
        .and_then(|value| value.checked_div(EXPIRY_BUCKET_SECONDS))
        .and_then(|value| value.checked_mul(EXPIRY_BUCKET_SECONDS))
        .ok_or_else(|| error!(VaultError::ArithmeticOverflow))
}

fn validate_request(vault: &VaultState, inputs: &RequestInputs) -> Result<()> {
    require!(
        inputs.protocol_version == PROTOCOL_VERSION,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.chain_id == vault.chain_id,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.contract_address == vault.protocol_binding,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.state_signing_key_x == vault.state_signing_key_x,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.state_signing_key_y == vault.state_signing_key_y,
        VaultError::DeploymentMismatch
    );
    inputs.to_wire()?;
    Ok(())
}

fn validate_withdrawal(
    vault: &VaultState,
    note: &NoteState,
    payload: &WithdrawalPayload,
    destination: &Pubkey,
    clearance: bool,
    now: u64,
) -> Result<()> {
    require!(!effectively_paused(vault, now), VaultError::Paused);
    let inputs = &payload.public_inputs;
    require!(
        payload.destination == *destination,
        VaultError::DestinationMismatch
    );
    require!(
        solana_destination_matches(&inputs.destination, &destination.to_bytes()),
        VaultError::DestinationMismatch
    );
    require!(
        inputs.protocol_version == PROTOCOL_VERSION,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.chain_id == vault.chain_id,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.contract_address == vault.protocol_binding,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.state_signing_key_x == vault.state_signing_key_x,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.state_signing_key_y == vault.state_signing_key_y,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.clearance_signing_key_x == vault.clearance_signing_key_x,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.clearance_signing_key_y == vault.clearance_signing_key_y,
        VaultError::DeploymentMismatch
    );
    require!(
        inputs.has_clearance == clearance,
        VaultError::InvalidClearanceMode
    );
    require!(now <= inputs.valid_until, VaultError::ExitProofExpired);
    require!(note.status == NOTE_STATUS_ACTIVE, VaultError::NoteNotActive);
    require!(inputs.note_id == note.note_id && inputs.registration == note.commitment
        && inputs.deposit_amount == u128::from(note.deposit_amount)
        && inputs.expiry_ts == note.expiry, VaultError::NoteMismatch);
    let state_balance = inputs.final_balance.checked_add(inputs.conceded)
        .ok_or(VaultError::InvalidAmount)?;
    require!(
        state_balance <= u128::from(note.deposit_amount),
        VaultError::InvalidAmount
    );
    require!(now < claimable_at(vault, note, now)?, VaultError::NoteExpired);
    if clearance {
        require!(inputs.next_nullifier == [0; 32] && inputs.conceded == 0,
            VaultError::InvalidClearanceMode);
    } else {
        require!(inputs.next_nullifier != [0; 32]
            && inputs.next_nullifier != inputs.withdrawal_nullifier, VaultError::NotSuccessorNullifier);
    }
    inputs.to_wire()?;
    Ok(())
}

/// A payout account finalize can always credit: writable as seen by the
/// program (the runtime demotes reserved keys to read-only) and not one of the
/// program accounts the payout or the pending close debits.
pub fn creditable_destination(destination: &AccountInfo, vault: &Pubkey, pending: &Pubkey) -> bool {
    destination.is_writable && destination.key != vault && destination.key != pending
}

/// Only evidence of spending the successor defeats an escape. Historical roots
/// are deliberately not compared to the current tree.
pub fn apply_escape_challenge(
    vault: &VaultState,
    note: &mut NoteState,
    pending: &PendingWithdrawal,
    payload: &ChallengePayload,
    note_id: u32,
    now: u64,
) -> Result<()> {
    validate_pending_evidence(vault, note, pending, payload, note_id, now)?;
    require!(payload.public_inputs.request_nullifier == pending.next_nullifier,
        VaultError::NotSuccessorNullifier);
    verify_request_bytes(&payload.public_inputs.to_wire()?, &payload.proof)
        .map_err(|_| VaultError::InvalidProof)?;
    note.claimable_after = note.expiry.max(now.checked_add(vault.challenge_period)
        .ok_or(VaultError::ArithmeticOverflow)?);
    note.status = NOTE_STATUS_ACTIVE;
    Ok(())
}

pub fn apply_raise_concession(
    vault: &VaultState,
    note: &NoteState,
    pending: &mut PendingWithdrawal,
    payload: &ChallengePayload,
    note_id: u32,
    amount: u128,
    now: u64,
) -> Result<()> {
    validate_pending_evidence(vault, note, pending, payload, note_id, now)?;
    require!(payload.public_inputs.request_nullifier == pending.nullifier, VaultError::NullifierMismatch);
    let conceded = amount.min(payload.public_inputs.solvency_bound).min(u128::from(pending.state_balance));
    require!(conceded > u128::from(pending.conceded), VaultError::ConcessionNotRaised);
    verify_request_bytes(&payload.public_inputs.to_wire()?, &payload.proof)
        .map_err(|_| VaultError::InvalidProof)?;
    pending.conceded = conceded as u64;
    pending.final_balance = pending.state_balance - pending.conceded;
    Ok(())
}

fn validate_pending_evidence(
    vault: &VaultState, note: &NoteState, pending: &PendingWithdrawal,
    payload: &ChallengePayload, note_id: u32, now: u64,
) -> Result<()> {
    require!(payload.note_id == note_id && note.note_id == note_id && pending.note_id == note_id,
        VaultError::NoteMismatch);
    require!(note.status == NOTE_STATUS_PENDING, VaultError::NoteNotPending);
    require!(now <= pending.deadline, VaultError::ChallengeExpired);
    validate_request(vault, &payload.public_inputs)
}

pub fn effectively_paused(vault: &VaultState, now: u64) -> bool {
    vault.paused && now.saturating_sub(vault.paused_at) < MAX_PAUSE_DURATION
}

pub fn paused_duration_now(vault: &VaultState, now: u64) -> Result<u64> {
    vault.total_paused_duration.checked_add(if vault.paused {
        now.saturating_sub(vault.paused_at).min(MAX_PAUSE_DURATION)
    } else { 0 }).ok_or_else(|| error!(VaultError::ArithmeticOverflow))
}

pub fn claimable_at(vault: &VaultState, note: &NoteState, now: u64) -> Result<u64> {
    note.expiry.max(note.claimable_after)
        .checked_add(paused_duration_now(vault, now)?.checked_sub(note.paused_offset)
            .ok_or(VaultError::ArithmeticOverflow)?)
        .ok_or_else(|| error!(VaultError::ArithmeticOverflow))
}

pub fn update_pause(vault: &mut VaultState, paused: bool, now: u64) -> Result<()> {
    if paused {
        require!(!effectively_paused(vault, now), VaultError::Paused);
        let last_end = if vault.paused {
            vault.paused_at.checked_add(MAX_PAUSE_DURATION).ok_or(VaultError::ArithmeticOverflow)?
        } else { vault.last_pause_end };
        require!(last_end == 0 || now >= last_end.checked_add(PAUSE_COOLDOWN)
            .ok_or(VaultError::ArithmeticOverflow)?, VaultError::PauseCooldown);
        vault.total_paused_duration = paused_duration_now(vault, now)?;
        vault.paused_at = now;
        vault.last_pause_end = last_end;
        vault.paused = true;
    } else if vault.paused {
        vault.total_paused_duration = paused_duration_now(vault, now)?;
        vault.last_pause_end = now.min(vault.paused_at.checked_add(MAX_PAUSE_DURATION)
            .ok_or(VaultError::ArithmeticOverflow)?);
        vault.paused = false;
    }
    Ok(())
}

pub fn validate_expired_claim(vault: &VaultState, note: &NoteState, note_id: u32, now: u64) -> Result<()> {
    require!(!effectively_paused(vault, now), VaultError::Paused);
    require!(note.note_id == note_id, VaultError::NoteMismatch);
    require!(note.status == NOTE_STATUS_ACTIVE, VaultError::NoteNotActive);
    require!(now >= claimable_at(vault, note, now)?, VaultError::NoteNotExpired);
    Ok(())
}

fn verify_note_transition(
    vault: &VaultState,
    note_id: u32,
    commitment: [u8; 32],
    amount: u64,
    expiry: u64,
    new_root: [u8; 32],
    inserting: bool,
    proof: &[u8],
) -> Result<Felt252> {
    let old_root = checked_felt(vault.current_root)?;
    let new_root = checked_felt(new_root)?;
    let public = SolanaMerkleTransitionInputs {
        protocol_version: PROTOCOL_VERSION,
        chain_id: vault.chain_id,
        protocol_binding: checked_felt(vault.protocol_binding)?,
        old_root,
        new_root,
        note_id,
        commitment: checked_felt(commitment)?,
        amount,
        expiry,
        inserting,
    };
    verify_transition_bytes(&public, proof).map_err(|_| VaultError::InvalidProof)?;
    Ok(new_root)
}

fn nullifier_status(account: &AccountInfo) -> Result<u8> {
    if account.owner == &system_program::ID && account.data_is_empty() {
        return Ok(NULLIFIER_RELEASED);
    }
    require_keys_eq!(*account.owner, crate::ID, VaultError::InvalidNullifierAccount);
    let data = account.try_borrow_data()?;
    let state = UsedNullifier::try_deserialize(&mut data.as_ref())?;
    require!(state.status <= NULLIFIER_CHALLENGED, VaultError::InvalidNullifierAccount);
    Ok(state.status)
}

fn require_unused_nullifier(account: &AccountInfo, successor: bool) -> Result<()> {
    let status = nullifier_status(account)?;
    if successor && status == NULLIFIER_CHALLENGED {
        return err!(VaultError::SupersededState);
    }
    require!(status == NULLIFIER_RELEASED, VaultError::ReplayedNullifier);
    Ok(())
}

/// Pre-funding a System-owned PDA must not prevent an exit. Allocate and assign
/// it with PDA authority, topping up only the missing rent; never close it.
fn write_nullifier<'info>(
    account: &AccountInfo<'info>, payer: &Signer<'info>, system: &Program<'info, System>,
    vault: Pubkey, nullifier: [u8; 32], bump: u8, status: u8,
) -> Result<()> {
    nullifier_status(account)?;
    if account.owner == &system_program::ID {
        let space = 8 + UsedNullifier::INIT_SPACE;
        let rent = Rent::get()?.minimum_balance(space);
        let missing = rent.saturating_sub(account.lamports());
        if missing != 0 {
            system_program::transfer(CpiContext::new(system.to_account_info(),
                Transfer { from: payer.to_account_info(), to: account.clone() }), missing)?;
        }
        let bump_seed = [bump];
        let seeds: &[&[u8]] = &[b"nullifier", vault.as_ref(), &nullifier, &bump_seed];
        system_program::allocate(CpiContext::new_with_signer(system.to_account_info(),
            system_program::Allocate { account_to_allocate: account.clone() }, &[seeds]), space as u64)?;
        system_program::assign(CpiContext::new_with_signer(system.to_account_info(),
            system_program::Assign { account_to_assign: account.clone() }, &[seeds]), &crate::ID)?;
    }
    let state = UsedNullifier { vault, nullifier, bump, status };
    state.try_serialize(&mut &mut account.try_borrow_mut_data()?[..])?;
    Ok(())
}

fn pay_from_vault<'info>(
    vault: &mut Account<'info, VaultState>,
    destination: &AccountInfo<'info>,
    user_amount: u64,
    operator_amount: u64,
) -> Result<()> {
    transfer_owned_lamports(&vault.to_account_info(), destination, user_amount)?;
    accrue_treasury(vault, operator_amount)?;
    Ok(())
}

fn accrue_treasury(vault: &mut VaultState, amount: u64) -> Result<()> {
    vault.treasury_accrued = vault.treasury_accrued.checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    Ok(())
}

fn required_vault_lamports(vault: &VaultState, rent_reserve: u64) -> Result<u64> {
    rent_reserve.checked_add(vault.total_credits)
        .and_then(|amount| amount.checked_add(vault.treasury_accrued))
        .ok_or_else(|| error!(VaultError::ArithmeticOverflow))
}

#[event]
pub struct TreasuryWithdrawn {
    pub amount: u64,
}

fn transfer_owned_lamports<'info>(
    source: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let source_after = source
        .lamports()
        .checked_sub(amount)
        .ok_or(VaultError::InsufficientVaultFunds)?;
    let destination_after = destination
        .lamports()
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    **source.try_borrow_mut_lamports()? = source_after;
    **destination.try_borrow_mut_lamports()? = destination_after;
    Ok(())
}

fn ensure_solvency(vault: &Account<VaultState>) -> Result<()> {
    let account = vault.to_account_info();
    let rent_reserve = Rent::get()?.minimum_balance(account.data_len());
    let required = required_vault_lamports(vault, rent_reserve)?;
    require!(
        account.lamports() >= required,
        VaultError::InsufficientVaultFunds
    );
    Ok(())
}

#[error_code]
pub enum VaultError {
    #[msg("invalid vault configuration")]
    InvalidConfiguration,
    #[msg("vault is paused")]
    Paused,
    #[msg("invalid BN254 field element")]
    InvalidField,
    #[msg("invalid amount")]
    InvalidAmount,
    #[msg("arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("invalid clock")]
    InvalidClock,
    #[msg("stale note ID")]
    StaleNoteId,
    #[msg("note is not active")]
    NoteNotActive,
    #[msg("note is not pending withdrawal")]
    NoteNotPending,
    #[msg("note is not expired")]
    NoteNotExpired,
    #[msg("challenge window has expired")]
    ChallengeExpired,
    #[msg("challenge window has not expired")]
    ChallengeNotExpired,
    #[msg("deployment binding mismatch")]
    DeploymentMismatch,
    #[msg("withdrawal destination mismatch")]
    DestinationMismatch,
    #[msg("wrong withdrawal clearance mode")]
    InvalidClearanceMode,
    #[msg("withdrawal nullifier mismatch")]
    NullifierMismatch,
    #[msg("Groth16 proof is invalid")]
    InvalidProof,
    #[msg("unauthorized operation")]
    Unauthorized,
    #[msg("invalid operation kind")]
    InvalidOperationKind,
    #[msg("invalid operation payload length")]
    InvalidOperationLength,
    #[msg("invalid operation expiry")]
    InvalidOperationExpiry,
    #[msg("operation has expired")]
    OperationExpired,
    #[msg("operation payload is incomplete")]
    OperationIncomplete,
    #[msg("operation chunks must be written in order")]
    OperationWriteOutOfOrder,
    #[msg("operation payload digest mismatch")]
    InvalidOperationDigest,
    #[msg("operation payload is malformed")]
    InvalidOperationPayload,
    #[msg("operation does not match its execute instruction")]
    OperationMismatch,
    #[msg("vault does not have enough lamports for its credit liabilities")]
    InsufficientVaultFunds,
    #[msg("note is not closed")]
    NoteNotClosed,
    #[msg("state has been superseded")]
    SupersededState,
    #[msg("nullifier has already been consumed")]
    ReplayedNullifier,
    #[msg("concession was not raised")]
    ConcessionNotRaised,
    #[msg("exit proof has expired")]
    ExitProofExpired,
    #[msg("evidence does not spend the successor")]
    NotSuccessorNullifier,
    #[msg("note binding mismatch")]
    NoteMismatch,
    #[msg("pause cooldown has not elapsed")]
    PauseCooldown,
    #[msg("note is expired")]
    NoteExpired,
    #[msg("invalid nullifier account")]
    InvalidNullifierAccount,
    #[msg("withdrawal destination cannot be credited at finalization")]
    DestinationNotCreditable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initialize_args() -> InitializeArgs {
        InitializeArgs {
            genesis_hash: [3; 32],
            note_ttl: 86_400,
            challenge_period: 60,
            request_charge_cap: 1_000_000,
            state_signing_key_x: *Felt252::from_u64(1).as_bytes(),
            state_signing_key_y: *Felt252::from_u64(2).as_bytes(),
            clearance_signing_key_x: *Felt252::from_u64(3).as_bytes(),
            clearance_signing_key_y: *Felt252::from_u64(4).as_bytes(),
        }
    }

    #[test]
    fn initialize_configuration_rejects_self_treasury() {
        let vault = Pubkey::new_unique();
        assert!(validate_initialize_configuration(&initialize_args(), vault, vault).is_err());
    }

    #[test]
    fn initialize_configuration_requires_cluster_and_key_separation() {
        let vault = Pubkey::new_unique();
        let treasury = Pubkey::new_unique();
        let mut args = initialize_args();
        assert!(validate_initialize_configuration(&args, vault, treasury).is_ok());

        args.genesis_hash = [0; 32];
        assert!(validate_initialize_configuration(&args, vault, treasury).is_err());
        args = initialize_args();
        args.clearance_signing_key_x = args.state_signing_key_x;
        args.clearance_signing_key_y = args.state_signing_key_y;
        assert!(validate_initialize_configuration(&args, vault, treasury).is_err());
    }

    #[test]
    fn staged_payload_round_trip_and_size_are_bounded() {
        let payload = DepositPayload {
            expected_note_id: 7,
            commitment: *Felt252::from_u64(8).as_bytes(),
            amount: 700,
            expiry: 1_000,
            new_root: *Felt252::from_u64(9).as_bytes(),
            transition_proof: vec![3; 256],
        };
        let bytes = payload.try_to_vec().unwrap();
        assert!(bytes.len() > 256);
        assert!(bytes.len() <= MAX_OPERATION_BYTES);
        let decoded = DepositPayload::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded.expected_note_id, 7);
        assert_eq!(decoded.transition_proof.len(), 256);
    }

    #[test]
    fn expiry_is_rounded_up_to_a_day() {
        assert_eq!(bucket_expiry(86_400, 1).unwrap(), 172_800);
        assert_eq!(bucket_expiry(86_399, 1).unwrap(), 86_400);
    }

    fn test_vault() -> VaultState {
        VaultState {
            version: VAULT_VERSION,
            bump: 255,
            paused: false,
            authority: Pubkey::new_unique(),
            treasury: Pubkey::new_unique(),
            genesis_hash: [3; 32],
            chain_id: 1,
            protocol_binding: [1; 32],
            current_root: [5; 32],
            next_note_id: 1,
            note_ttl: 86_400,
            challenge_period: 60,
            request_charge_cap: 1,
            total_credits: 900,
            state_signing_key_x: [1; 32],
            state_signing_key_y: [2; 32],
            clearance_signing_key_x: [3; 32],
            clearance_signing_key_y: [4; 32],
            paused_at: 0,
            last_pause_end: 0,
            total_paused_duration: 0,
            treasury_accrued: 0,
        }
    }

    #[test]
    fn payout_ignores_empty_or_executable_treasury_and_preserves_accrued_liabilities() {
        for executable in [false, true] {
            let mut state = test_vault();
            let treasury_key = state.treasury;
            let mut treasury_lamports = 0;
            let mut treasury_data = [];
            let treasury_owner = system_program::ID;
            let treasury = AccountInfo::new(&treasury_key, false, true,
                &mut treasury_lamports, &mut treasury_data, &treasury_owner, executable, 0);
            let rent_reserve = Rent::default().minimum_balance(8 + VaultState::INIT_SPACE);
            let vault_key = Pubkey::new_unique();
            let mut vault_lamports = rent_reserve + state.total_credits;
            // Close a 700-lamport note; the remaining active liability is 200.
            state.total_credits -= 700;
            let mut vault_data = vec![0; 8 + VaultState::INIT_SPACE];
            state.try_serialize(&mut vault_data.as_mut_slice()).unwrap();
            let vault_info = AccountInfo::new(&vault_key, false, true, &mut vault_lamports,
                &mut vault_data, &crate::ID, false, 0);
            let mut vault = Account::<VaultState>::try_from(&vault_info).unwrap();
            let user_key = Pubkey::new_unique();
            let mut user_lamports = 1_000_000;
            let mut user_data = [];
            let user = AccountInfo::new(&user_key, false, true, &mut user_lamports,
                &mut user_data, &system_program::ID, false, 0);
            // The one-lamport treasury share is below rent exemption and its
            // recipient is deliberately absent from the payout path.
            pay_from_vault(&mut vault, &user, 699, 1).unwrap();
            assert_eq!(user.lamports(), 1_000_699);
            assert_eq!(treasury.lamports(), 0);
            assert_eq!(vault.treasury_accrued, 1);
            assert_eq!(vault_info.lamports(), required_vault_lamports(&vault, rent_reserve).unwrap());
            // Claim expiry accrues the entire remaining note without a transfer.
            vault.total_credits -= 200;
            accrue_treasury(&mut vault, 200).unwrap();
            assert_eq!(vault.treasury_accrued, 201);
            assert_eq!(vault_info.lamports(), required_vault_lamports(&vault, rent_reserve).unwrap());
            // A successful separate treasury withdrawal releases only accrual.
            let accrued = vault.treasury_accrued;
            vault.treasury_accrued = 0;
            transfer_owned_lamports(&vault_info, &user, accrued).unwrap();
            assert_eq!(vault_info.lamports(), rent_reserve);
            assert_eq!(required_vault_lamports(&vault, rent_reserve).unwrap(), rent_reserve);
        }
    }

    #[test]
    fn treasury_accrual_is_checked_and_included_in_solvency() {
        let mut vault = test_vault();
        accrue_treasury(&mut vault, 123).unwrap();
        assert_eq!(required_vault_lamports(&vault, 77).unwrap(), 1_100);
        vault.treasury_accrued = u64::MAX;
        assert!(accrue_treasury(&mut vault, 1).is_err());
        assert_eq!(vault.treasury_accrued, u64::MAX);
        assert!(required_vault_lamports(&vault, 0).is_err());
    }

    fn test_note() -> NoteState {
        NoteState {
            vault: Pubkey::new_unique(),
            note_id: 0,
            commitment: [6; 32],
            deposit_amount: 700,
            expiry: 1_000,
            status: NOTE_STATUS_ACTIVE,
            bump: 255,
            claimable_after: 1_000,
            paused_offset: 0,
        }
    }

    #[test]
    fn pause_is_bounded_and_preserves_the_exit_window() {
        let mut vault = test_vault();
        let note = test_note();
        update_pause(&mut vault, true, 900).unwrap();
        assert!(effectively_paused(&vault, 1_000));
        assert!(validate_expired_claim(&vault, &note, 0, 1_000).is_err());
        assert!(update_pause(&mut vault, true, 1_000).is_err());
        let end = 900 + MAX_PAUSE_DURATION;
        assert!(!effectively_paused(&vault, end));
        assert_eq!(claimable_at(&vault, &note, end).unwrap(), 1_000 + MAX_PAUSE_DURATION);
        assert!(validate_expired_claim(&vault, &note, 0, end).is_err());
        assert!(validate_expired_claim(&vault, &note, 0, 1_000 + MAX_PAUSE_DURATION).is_ok());
        assert!(update_pause(&mut vault, true, end + PAUSE_COOLDOWN - 1).is_err());
        update_pause(&mut vault, true, end + PAUSE_COOLDOWN).unwrap();
        assert_eq!(vault.total_paused_duration, MAX_PAUSE_DURATION);
        update_pause(&mut vault, false, end + PAUSE_COOLDOWN + 20).unwrap();
        assert_eq!(vault.total_paused_duration, MAX_PAUSE_DURATION + 20);
        assert!(update_pause(&mut vault, true, end + PAUSE_COOLDOWN + 21).is_err());
    }

    #[test]
    fn deposits_during_finished_pauses_do_not_inherit_old_pause_time() {
        let mut vault = test_vault();
        update_pause(&mut vault, true, 100).unwrap();
        update_pause(&mut vault, false, 200).unwrap();
        let mut note = test_note();
        note.paused_offset = paused_duration_now(&vault, 300).unwrap();
        assert_eq!(claimable_at(&vault, &note, 300).unwrap(), note.expiry);
        note.claimable_after = 1_100;
        assert!(validate_expired_claim(&vault, &note, 0, 1_099).is_err());
        assert!(validate_expired_claim(&vault, &note, 0, 1_100).is_ok());
        for status in [NOTE_STATUS_PENDING, NOTE_STATUS_CLOSED, NOTE_STATUS_RETIRED, 3] {
            note.status = status;
            assert!(validate_expired_claim(&vault, &note, 0, 2_000).is_err());
        }
    }

    #[test]
    fn nullifier_status_accepts_prefunding_but_rejects_replay_and_superseded_states() {
        let key = Pubkey::new_unique();
        let mut lamports = 123;
        let mut empty = [];
        let system_owner = system_program::ID;
        let account = AccountInfo::new(&key, false, true, &mut lamports, &mut empty,
            &system_owner, false, 0);
        assert!(require_unused_nullifier(&account, false).is_ok());
        assert!(require_unused_nullifier(&account, true).is_ok());
        let vault = Pubkey::new_unique();
        for status in [NULLIFIER_RELEASED, NULLIFIER_CONSUMED, NULLIFIER_CHALLENGED] {
            let mut data = vec![0; 8 + UsedNullifier::INIT_SPACE];
            UsedNullifier { vault, nullifier: [1; 32], bump: 255, status }
                .try_serialize(&mut data.as_mut_slice()).unwrap();
            let account = AccountInfo::new(&key, false, true, &mut lamports, &mut data,
                &crate::ID, false, 0);
            assert_eq!(require_unused_nullifier(&account, false).is_ok(), status == NULLIFIER_RELEASED);
            assert_eq!(require_unused_nullifier(&account, true).is_ok(), status == NULLIFIER_RELEASED);
        }
        let foreign_owner = Pubkey::new_unique();
        let account = AccountInfo::new(&key, false, true, &mut lamports, &mut empty,
            &foreign_owner, false, 0);
        assert!(nullifier_status(&account).is_err());
    }

    /// Host account in the runtime's input layout: the original data length
    /// sits 4 bytes before the key and the current length 8 bytes before the
    /// data, so Anchor's `close` (which resizes to 0) runs safely off-chain.
    struct HostAccount {
        key: [u8; 36],
        words: Vec<u64>,
        len: usize,
        lamports: u64,
        owner: Pubkey,
        is_signer: bool,
        is_writable: bool,
    }

    impl HostAccount {
        fn new(key: Pubkey, owner: Pubkey, lamports: u64, data: Vec<u8>, is_signer: bool,
            is_writable: bool) -> Self {
            let mut key_buf = [0u8; 36];
            key_buf[..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
            key_buf[4..].copy_from_slice(&key.to_bytes());
            let mut words = vec![0u64; 1 + data.len().div_ceil(8)];
            words[0] = data.len() as u64;
            for (index, byte) in data.iter().enumerate() {
                words[1 + index / 8] |= u64::from(*byte) << (8 * (index % 8));
            }
            Self { key: key_buf, words, len: data.len(), lamports, owner, is_signer, is_writable }
        }

        fn info(&mut self) -> AccountInfo<'_> {
            // SAFETY: Pubkey is a transparent, 1-aligned [u8; 32] inside `key`,
            // and `words` holds the 8-byte length followed by `len` data bytes
            // (little-endian packing, as the target is little-endian).
            let key = unsafe { &*(self.key[4..].as_ptr() as *const Pubkey) };
            let data = unsafe {
                std::slice::from_raw_parts_mut((self.words.as_mut_ptr() as *mut u8).add(8), self.len)
            };
            AccountInfo::new(key, self.is_signer, self.is_writable, &mut self.lamports, data,
                &self.owner, false, 0)
        }
    }

    fn serialized<T: AccountSerialize + Space>(value: &T) -> Vec<u8> {
        let mut data = vec![0; 8 + T::INIT_SPACE];
        value.try_serialize(&mut data.as_mut_slice()).unwrap();
        data
    }

    /// Threat: a third party front-runs the permissionless finalize to take the
    /// pending-account rent the escaper paid. The rent goes to the destination.
    #[test]
    fn finalize_refunds_pending_rent_to_destination_not_the_caller() {
        let vault_key = Pubkey::new_unique();
        let note_id = 3u32;
        let (pending_key, pending_bump) = Pubkey::find_program_address(
            &[b"pending", vault_key.as_ref(), &note_id.to_le_bytes()], &crate::ID);
        let destination_key = Pubkey::new_unique();
        let mut note = test_note();
        note.vault = vault_key;
        note.note_id = note_id;
        note.status = NOTE_STATUS_PENDING;
        let pending = PendingWithdrawal { vault: vault_key, note_id, nullifier: [1; 32],
            next_nullifier: [2; 32], state_balance: 700, conceded: 100, final_balance: 600,
            destination: destination_key, deadline: 10, bump: pending_bump };
        let rent = Rent::default().minimum_balance(8 + PendingWithdrawal::INIT_SPACE);
        let payer_before = 5_000_000;
        let mut hosts = [
            HostAccount::new(vault_key, crate::ID, 10_000_000, serialized(&test_vault()), false, true),
            HostAccount::new(Pubkey::new_unique(), crate::ID, 1_000_000, serialized(&note), false, true),
            HostAccount::new(pending_key, crate::ID, rent, serialized(&pending), false, true),
            HostAccount::new(Pubkey::new_unique(), system_program::ID, payer_before, vec![], true, true),
            HostAccount::new(destination_key, system_program::ID, 0, vec![], false, true),
        ];
        let infos: Vec<AccountInfo> = hosts.iter_mut().map(HostAccount::info).collect();
        let mut remaining = infos.as_slice();
        let accounts = FinalizeEscape::try_accounts(&crate::ID, &mut remaining,
            &note_id.to_le_bytes(), &mut Default::default(), &mut Default::default()).unwrap();
        accounts.exit(&crate::ID).unwrap();
        assert_eq!(infos[2].lamports(), 0);
        assert_eq!(*infos[2].owner, system_program::ID);
        assert!(infos[2].data_is_empty());
        assert_eq!(infos[3].lamports(), payer_before, "the caller must not collect the rent");
        assert_eq!(infos[4].lamports(), rent, "the escaper's rent is refunded to the destination");
    }

    /// Threat: a spent-down user escapes to a destination finalize can never
    /// credit, so the note stays Pending and the operator share is locked
    /// forever. Such destinations are refused when the escape is opened.
    #[test]
    fn escape_refuses_destinations_finalize_could_never_credit() {
        let (vault, pending, wallet) =
            (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let check = |key: Pubkey, writable: bool| {
            let mut host = HostAccount::new(key, system_program::ID, 0, vec![], false, writable);
            creditable_destination(&host.info(), &vault, &pending)
        };
        assert!(check(wallet, true));
        // The runtime demotes reserved keys (System program, sysvars, builtins)
        // to read-only even when the message marks them writable.
        assert!(!check(system_program::ID, false));
        assert!(!check(anchor_lang::solana_program::sysvar::clock::ID, false));
        // Vault == destination mints lamports; pending == destination is zeroed
        // by its own close. Both make every finalize fail.
        assert!(!check(vault, true));
        assert!(!check(pending, true));
    }
}

#[cfg(test)]
mod concession_tests;
