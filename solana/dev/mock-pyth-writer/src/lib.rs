//! Loaded at the Pyth receiver program ID on a disposable local validator (`--bpf-program`). Overwrites the whole data of
//! its first account with the instruction data, so a test can refresh a `PriceUpdateV2` account that the validator was
//! started with. This is a mock oracle updater: it performs no Wormhole/guardian verification.

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if account.owner != program_id || !account.is_writable {
        return Err(ProgramError::IllegalOwner);
    }
    let mut stored = account.try_borrow_mut_data()?;
    if stored.len() != data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    stored.copy_from_slice(data);
    Ok(())
}
