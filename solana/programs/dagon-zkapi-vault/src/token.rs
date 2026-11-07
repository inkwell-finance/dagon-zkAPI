//! Minimal classic SPL Token interface for the USDC vault.
//!
//! The vault pins Circle's USDC mint under the classic Token program and
//! rejects Token-2022 outright: every token account it reads must be owned by
//! `TOKEN_PROGRAM_ID`, and every CPI goes to that program. Token-2022 adds
//! transfer fees, transfer hooks, permanent delegates and confidential
//! balances, any of which would break the exact-amount solvency accounting.
//! The layouts below are classic Token's fixed `Pack` layouts.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::system_program;

use crate::{VaultError, VAULT_TOKEN_SEED};

/// Circle USDC on Solana mainnet.
pub const USDC_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
pub const USDC_DECIMALS: u8 = 6;
/// The classic SPL Token program; the only token program the vault accepts.
pub const TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// Token-2022; named only so tests can show it is rejected.
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

pub const TOKEN_ACCOUNT_LEN: usize = 165;
pub const MINT_LEN: usize = 82;
pub const ACCOUNT_STATE_INITIALIZED: u8 = 1;
pub const ACCOUNT_STATE_FROZEN: u8 = 2;
const TRANSFER_CHECKED: u8 = 12;
const INITIALIZE_ACCOUNT3: u8 = 18;

/// The fields of a classic Token account the vault relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenAccountView {
    pub key: Pubkey,
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub state: u8,
}

impl TokenAccountView {
    /// Initialized (not frozen) and of `mint`: a transfer into it succeeds.
    pub fn creditable(&self, mint: &Pubkey) -> bool {
        self.state == ACCOUNT_STATE_INITIALIZED && self.mint == *mint
    }
}

fn pubkey_at(data: &[u8], offset: usize) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[offset..offset + 32]);
    Pubkey::new_from_array(bytes)
}

/// Decode an initialized or frozen classic-Token account. Any other owner
/// (System, Token-2022, a forged program account) or layout is rejected.
pub fn read_token_account(info: &AccountInfo) -> Result<TokenAccountView> {
    require_keys_eq!(*info.owner, TOKEN_PROGRAM_ID, VaultError::InvalidTokenAccount);
    let data = info.try_borrow_data()?;
    require!(data.len() == TOKEN_ACCOUNT_LEN, VaultError::InvalidTokenAccount);
    let state = data[108];
    require!(
        state == ACCOUNT_STATE_INITIALIZED || state == ACCOUNT_STATE_FROZEN,
        VaultError::InvalidTokenAccount
    );
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&data[64..72]);
    Ok(TokenAccountView {
        key: info.key(),
        mint: pubkey_at(&data, 0),
        owner: pubkey_at(&data, 32),
        amount: u64::from_le_bytes(amount),
        state,
    })
}

/// The pinned mint must be an initialized classic-Token mint with 6 decimals.
pub fn require_usdc_mint(info: &AccountInfo) -> Result<()> {
    require_keys_eq!(info.key(), USDC_MINT, VaultError::InvalidMint);
    require_keys_eq!(*info.owner, TOKEN_PROGRAM_ID, VaultError::InvalidMint);
    let data = info.try_borrow_data()?;
    require!(
        data.len() == MINT_LEN && data[45] == 1 && data[44] == USDC_DECIMALS,
        VaultError::InvalidMint
    );
    Ok(())
}

/// `TransferChecked` through the classic Token program. The Token program
/// authenticates `authority` (owner or delegate of `source`, a signer here or
/// via `signer_seeds`), the mint of both accounts and the decimals.
pub fn transfer_checked<'info>(
    token_program: &AccountInfo<'info>,
    source: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    require_keys_eq!(token_program.key(), TOKEN_PROGRAM_ID, VaultError::InvalidTokenProgram);
    let mut data = Vec::with_capacity(10);
    data.push(TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(USDC_DECIMALS);
    let instruction = Instruction {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(source.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(authority.key(), true),
        ],
        data,
    };
    invoke_signed(
        &instruction,
        &[source.clone(), mint.clone(), destination.clone(), authority.clone(), token_program.clone()],
        signer_seeds,
    )
    .map_err(Into::into)
}

/// Create the vault's USDC account at its PDA, owned by the classic Token
/// program with the vault as token authority. A PDA pre-funded with lamports
/// by anyone is adopted (top up, allocate, assign) instead of blocking init.
pub fn create_vault_token_account<'info>(
    payer: &Signer<'info>,
    account: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    token_program: &AccountInfo<'info>,
    system: &Program<'info, System>,
    vault: Pubkey,
    bump: u8,
) -> Result<()> {
    require_keys_eq!(*account.owner, system_program::ID, VaultError::InvalidVaultTokenAccount);
    require!(account.data_is_empty(), VaultError::InvalidVaultTokenAccount);
    let bump_seed = [bump];
    let seeds: &[&[u8]] = &[VAULT_TOKEN_SEED, vault.as_ref(), &bump_seed];
    let rent = Rent::get()?.minimum_balance(TOKEN_ACCOUNT_LEN);
    let missing = rent.saturating_sub(account.lamports());
    if missing != 0 {
        system_program::transfer(
            CpiContext::new(system.to_account_info(), system_program::Transfer {
                from: payer.to_account_info(),
                to: account.clone(),
            }),
            missing,
        )?;
    }
    system_program::allocate(
        CpiContext::new_with_signer(system.to_account_info(),
            system_program::Allocate { account_to_allocate: account.clone() }, &[seeds]),
        TOKEN_ACCOUNT_LEN as u64,
    )?;
    system_program::assign(
        CpiContext::new_with_signer(system.to_account_info(),
            system_program::Assign { account_to_assign: account.clone() }, &[seeds]),
        &TOKEN_PROGRAM_ID,
    )?;
    let mut data = Vec::with_capacity(33);
    data.push(INITIALIZE_ACCOUNT3);
    data.extend_from_slice(vault.as_ref());
    let instruction = Instruction {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(account.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
        ],
        data,
    };
    invoke_signed(&instruction, &[account.clone(), mint.clone(), token_program.clone()], &[])
        .map_err(Into::into)
}

#[cfg(test)]
pub(crate) mod test_layout {
    use super::*;

    /// A classic Token account image in `Pack` layout.
    pub fn token_account_data(mint: Pubkey, owner: Pubkey, amount: u64, state: u8) -> Vec<u8> {
        let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
        data[..32].copy_from_slice(mint.as_ref());
        data[32..64].copy_from_slice(owner.as_ref());
        data[64..72].copy_from_slice(&amount.to_le_bytes());
        data[108] = state;
        data
    }

    pub fn mint_data(decimals: u8, initialized: bool) -> Vec<u8> {
        let mut data = vec![0u8; MINT_LEN];
        data[44] = decimals;
        data[45] = u8::from(initialized);
        data
    }
}
