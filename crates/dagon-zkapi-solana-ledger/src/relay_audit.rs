//! Signing policy for a relayer key that pays fees and rent for users.
//!
//! A relayer must sign only transactions in which its key appears as the
//! fee payer and in an explicitly allowed account slot of an allowed
//! instruction: the vault operation `owner`/`payer`/`rent_payer`, the ATA
//! program's rent payer, CCTP's `event_rent_payer`, `receive_message`
//! payer/caller and `reclaim_event_account` payee. It is never a token
//! authority, never a System-program signer and never named by any other
//! program, so a signed transaction cannot move the relayer's tokens or SOL
//! except as fees and rent.

use anchor_lang::{Discriminator, ToAccountMetas};
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::{v0, AddressLookupTableAccount, Message};
use solana_pubkey::Pubkey;

use crate::{cctp, vault_program, ASSOCIATED_TOKEN_PROGRAM_ID, ATA_CREATE_IDEMPOTENT};

/// Index of `marker` in the Anchor account list built by `metas`.
fn slot(metas: Vec<anchor_lang::prelude::AccountMeta>, marker: Pubkey) -> usize {
    metas
        .iter()
        .position(|meta| meta.pubkey == marker)
        .expect("marker account present")
}

/// Account slots the relayer may occupy in vault instructions, derived from
/// the program's own Anchor account structs so they cannot drift.
fn vault_relayer_slots(data: &[u8]) -> Option<Vec<usize>> {
    use vault_program::{accounts, instruction};
    let m = Pubkey::new_from_array([0xA5; 32]);
    let d = Pubkey::default();
    let owner_slot = |metas| vec![slot(metas, m)];
    let starts = |discriminator: &[u8]| data.starts_with(discriminator);
    if starts(instruction::InitializeOperation::DISCRIMINATOR) {
        return Some(owner_slot(
            accounts::InitializeOperation {
                vault: d,
                operation: d,
                owner: m,
                system_program: d,
            }
            .to_account_metas(None),
        ));
    }
    if starts(instruction::WriteOperation::DISCRIMINATOR) {
        return Some(owner_slot(
            accounts::WriteOperation {
                vault: d,
                operation: d,
                owner: m,
            }
            .to_account_metas(None),
        ));
    }
    if starts(instruction::CancelOperation::DISCRIMINATOR) {
        return Some(owner_slot(
            accounts::CancelOperation {
                vault: d,
                operation: d,
                owner: m,
            }
            .to_account_metas(None),
        ));
    }
    if starts(instruction::ExecuteDeposit::DISCRIMINATOR) {
        return Some(owner_slot(
            accounts::ExecuteDeposit {
                vault: d,
                operation: d,
                note: d,
                owner: m,
                depositor: d,
                source_token: d,
                vault_token: d,
                mint: d,
                token_program: d,
                system_program: d,
            }
            .to_account_metas(None),
        ));
    }
    if starts(instruction::ExecuteClose::DISCRIMINATOR) {
        return Some(owner_slot(
            accounts::ExecuteClose {
                vault: d,
                note: d,
                used_nullifier: d,
                owner: m,
                destination_token: d,
                vault_token: d,
                mint: d,
                token_program: d,
                system_program: d,
            }
            .to_account_metas(None),
        ));
    }
    if starts(instruction::ExecuteEscape::DISCRIMINATOR) {
        return Some(owner_slot(
            accounts::ExecuteEscape {
                vault: d,
                note: d,
                pending: d,
                used_nullifier: d,
                next_nullifier: d,
                owner: m,
                destination: d,
                system_program: d,
            }
            .to_account_metas(None),
        ));
    }
    let payer_and_rent = |payer: usize| vec![payer, payer + 1];
    if starts(instruction::FinalizeEscape::DISCRIMINATOR) {
        return Some(payer_and_rent(slot(
            accounts::FinalizeEscape {
                vault: d,
                note: d,
                pending: d,
                payer: m,
                rent_payer: d,
                destination_token: d,
                vault_token: d,
                mint: d,
                token_program: d,
            }
            .to_account_metas(None),
            m,
        )));
    }
    if starts(instruction::ReleaseEscapePayout::DISCRIMINATOR) {
        return Some(payer_and_rent(slot(
            accounts::ReleaseEscapePayout {
                vault: d,
                note: d,
                pending: d,
                payer: m,
                rent_payer: d,
                destination_token: d,
                vault_token: d,
                mint: d,
                token_program: d,
            }
            .to_account_metas(None),
            m,
        )));
    }
    None
}

/// The account slots `relayer` may fill in an instruction of `program` with
/// `data`; `None` if the relayer may not appear in it at all.
fn allowed_slots(program: &Pubkey, data: &[u8], vault_program_id: &Pubkey) -> Option<Vec<usize>> {
    if program == vault_program_id {
        return vault_relayer_slots(data);
    }
    if *program == ASSOCIATED_TOKEN_PROGRAM_ID && data == [ATA_CREATE_IDEMPOTENT] {
        return Some(vec![0]);
    }
    if *program == cctp::MESSAGE_TRANSMITTER_V2 {
        if data.starts_with(&cctp::RECEIVE_MESSAGE_DISCRIMINATOR) {
            return Some(vec![0, 1]);
        }
        if data.starts_with(&cctp::RECLAIM_EVENT_ACCOUNT_DISCRIMINATOR) {
            return Some(vec![0]);
        }
    }
    if *program == cctp::TOKEN_MESSENGER_MINTER_V2
        && (data.starts_with(&cctp::DEPOSIT_FOR_BURN_DISCRIMINATOR)
            || data.starts_with(&cctp::DEPOSIT_FOR_BURN_WITH_HOOK_DISCRIMINATOR))
    {
        return Some(vec![1]);
    }
    // The relay's own lookup table: authority and rent payer of create/extend.
    if *program == cctp::ADDRESS_LOOKUP_TABLE_PROGRAM
        && (data.starts_with(&cctp::LOOKUP_TABLE_CREATE.to_le_bytes())
            || data.starts_with(&cctp::LOOKUP_TABLE_EXTEND.to_le_bytes()))
    {
        return Some(vec![1, 2]);
    }
    None
}

/// Refuse a legacy message unless `relayer` is its fee payer and every other
/// use of the relayer key is an allowed fee/rent-payer slot. Also refuses
/// messages whose instructions name an account index outside the message.
pub fn audit_relayer_message(
    message: &Message,
    relayer: &Pubkey,
    vault_program_id: &Pubkey,
) -> Result<(), String> {
    audit_keys(
        &message.account_keys,
        message.header.num_required_signatures,
        &message.instructions,
        relayer,
        vault_program_id,
    )
}

/// [`audit_relayer_message`] for a v0 message whose lookups resolve through
/// `tables` (the relayer must not be loaded from a table).
pub fn audit_relayer_v0_message(
    message: &v0::Message,
    tables: &[AddressLookupTableAccount],
    relayer: &Pubkey,
    vault_program_id: &Pubkey,
) -> Result<(), String> {
    let mut keys = message.account_keys.clone();
    let mut readonly = Vec::new();
    for lookup in &message.address_table_lookups {
        let table = tables
            .iter()
            .find(|table| table.key == lookup.account_key)
            .ok_or("a lookup names an unknown address table")?;
        let load = |indexes: &[u8]| -> Result<Vec<Pubkey>, String> {
            indexes
                .iter()
                .map(|index| {
                    table
                        .addresses
                        .get(usize::from(*index))
                        .copied()
                        .ok_or_else(|| "a lookup index is outside its table".to_string())
                })
                .collect()
        };
        keys.extend(load(&lookup.writable_indexes)?);
        readonly.extend(load(&lookup.readonly_indexes)?);
    }
    keys.extend(readonly);
    if keys[message.account_keys.len()..].contains(relayer) {
        return Err("the relayer key is loaded from a lookup table".into());
    }
    audit_keys(
        &keys,
        message.header.num_required_signatures,
        &message.instructions,
        relayer,
        vault_program_id,
    )
}

fn audit_keys(
    keys: &[Pubkey],
    num_required_signatures: u8,
    instructions: &[CompiledInstruction],
    relayer: &Pubkey,
    vault_program_id: &Pubkey,
) -> Result<(), String> {
    if keys.first() != Some(relayer) || num_required_signatures == 0 {
        return Err("the relayer must be the transaction fee payer".into());
    }
    if keys[1..].contains(relayer) {
        return Err("the relayer key appears twice in the account list".into());
    }
    for (index, instruction) in instructions.iter().enumerate() {
        let program = keys
            .get(usize::from(instruction.program_id_index))
            .ok_or("instruction program index is out of range")?;
        if program == relayer {
            return Err(format!("instruction {index} invokes the relayer key"));
        }
        let mut slots = Vec::new();
        for (position, account) in instruction.accounts.iter().enumerate() {
            if usize::from(*account) >= keys.len() {
                return Err(format!("instruction {index} account index is out of range"));
            }
            if *account == 0 {
                slots.push(position);
            }
        }
        if slots.is_empty() {
            continue;
        }
        let allowed = allowed_slots(program, &instruction.data, vault_program_id)
            .ok_or_else(|| format!("instruction {index} ({program}) may not name the relayer"))?;
        if let Some(position) = slots.iter().find(|position| !allowed.contains(position)) {
            return Err(format!(
                "instruction {index} ({program}) names the relayer in account slot {position}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};

    fn message(instructions: &[Instruction], payer: &Pubkey) -> Message {
        Message::new_with_blockhash(instructions, Some(payer), &Hash::new_unique())
    }

    #[test]
    fn relayer_may_only_pay_fees_and_rent() {
        let relayer = Pubkey::new_unique();
        let user = Pubkey::new_unique();
        let program = vault_program::ID;
        let mint = crate::USDC_MINT;
        let burn = cctp::deposit_for_burn_instruction(
            &cctp::CctpAccounts::new(mint),
            &user,
            &relayer,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &cctp::BurnParams {
                amount: 10,
                destination_domain: 6,
                mint_recipient: [1; 32],
                destination_caller: [0; 32],
                max_fee: 1,
                min_finality_threshold: cctp::FINALITY_STANDARD,
                hook_data: Vec::new(),
            },
        );
        audit_relayer_message(
            &message(std::slice::from_ref(&burn), &relayer),
            &relayer,
            &program,
        )
        .unwrap();

        // The relayer as burn owner, token authority or System signer.
        let as_owner = cctp::deposit_for_burn_instruction(
            &cctp::CctpAccounts::new(mint),
            &relayer,
            &user,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &cctp::BurnParams {
                amount: 10,
                destination_domain: 6,
                mint_recipient: [1; 32],
                destination_caller: [0; 32],
                max_fee: 1,
                min_finality_threshold: cctp::FINALITY_STANDARD,
                hook_data: Vec::new(),
            },
        );
        let token = cctp::transfer_checked_instruction(
            &Pubkey::new_unique(),
            &mint,
            &Pubkey::new_unique(),
            &relayer,
            1,
            6,
        );
        let system = Instruction {
            program_id: anchor_lang::system_program::ID,
            accounts: vec![
                AccountMeta::new(relayer, true),
                AccountMeta::new(user, false),
            ],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        for bad in [as_owner, token, system] {
            assert!(audit_relayer_message(&message(&[bad], &relayer), &relayer, &program).is_err());
        }
        // Someone else as fee payer.
        assert!(audit_relayer_message(&message(&[burn], &user), &relayer, &program).is_err());
        // The ATA program only as the rent payer of CreateIdempotent.
        let create = crate::create_usdc_ata_idempotent_instruction(&relayer, &user);
        audit_relayer_message(&message(&[create], &relayer), &relayer, &program).unwrap();
        let own_ata = crate::create_usdc_ata_idempotent_instruction(&user, &relayer);
        assert!(audit_relayer_message(&message(&[own_ata], &relayer), &relayer, &program).is_err());
    }

    #[test]
    fn vault_slots_follow_the_program_account_structs() {
        use vault_program::instruction;
        let slots = |data: &[u8]| vault_relayer_slots(data).unwrap();
        assert_eq!(slots(instruction::InitializeOperation::DISCRIMINATOR), [2]);
        assert_eq!(slots(instruction::WriteOperation::DISCRIMINATOR), [2]);
        assert_eq!(slots(instruction::CancelOperation::DISCRIMINATOR), [2]);
        assert_eq!(slots(instruction::ExecuteDeposit::DISCRIMINATOR), [3]);
        assert_eq!(slots(instruction::ExecuteClose::DISCRIMINATOR), [3]);
        assert_eq!(slots(instruction::ExecuteEscape::DISCRIMINATOR), [5]);
        assert_eq!(slots(instruction::FinalizeEscape::DISCRIMINATOR), [3, 4]);
        assert_eq!(
            slots(instruction::ReleaseEscapePayout::DISCRIMINATOR),
            [3, 4]
        );
        assert!(vault_relayer_slots(instruction::WithdrawTreasury::DISCRIMINATOR).is_none());
    }
}
