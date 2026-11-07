#![allow(unexpected_cfgs)]
//! Test-only relay that signs one cross-program call with its PDA
//! `["forwarder"]`, standing in for a future CCTP forwarder. Loaded only into
//! the local validator by the lifecycle test; never part of a deployment.
//!
//! Instruction data: `program_id (32) | n (u8) | n * (pubkey (32), is_signer
//! (u8), is_writable (u8)) | inner data`. Every account the inner instruction
//! names, plus its program, must be passed to this instruction.

use anchor_lang::solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process);

pub const FORWARDER_SEED: &[u8] = b"forwarder";

fn take(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], ProgramError> {
    bytes.get(at..at + len).ok_or(ProgramError::InvalidInstructionData)
}

fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (forwarder, bump) = Pubkey::find_program_address(&[FORWARDER_SEED], program_id);
    let target = Pubkey::try_from(take(data, 0, 32)?).map_err(|_| ProgramError::InvalidInstructionData)?;
    let count = usize::from(*data.get(32).ok_or(ProgramError::InvalidInstructionData)?);
    let mut metas = Vec::with_capacity(count);
    let mut offset = 33;
    for _ in 0..count {
        let key = Pubkey::try_from(take(data, offset, 32)?).map_err(|_| ProgramError::InvalidInstructionData)?;
        let flags = take(data, offset + 32, 2)?;
        metas.push(AccountMeta { pubkey: key, is_signer: flags[0] != 0, is_writable: flags[1] != 0 });
        offset += 34;
    }
    // Only this program's PDA may be signed for; other signers must already
    // be signers of the outer transaction.
    for meta in &metas {
        if meta.is_signer && meta.pubkey == forwarder {
            continue;
        }
        if meta.is_signer && !accounts.iter().any(|a| a.key == &meta.pubkey && a.is_signer) {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    let instruction = Instruction { program_id: target, accounts: metas, data: data[offset..].to_vec() };
    invoke_signed(&instruction, accounts, &[&[FORWARDER_SEED, &[bump]]])
}
