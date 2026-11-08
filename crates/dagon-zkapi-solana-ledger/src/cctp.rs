//! Circle CCTP V2 on Solana: program pins, PDAs, instruction encoders and
//! read-only decoders used by the zkAPI relay.
//!
//! Everything here mirrors the published Anchor IDLs of
//! `message_transmitter_v2` and `token_messenger_minter_v2`
//! (`circlefin/solana-cctp-contracts`, `examples/target/idl/*.json`) and the
//! program sources they were generated from: instruction discriminators,
//! account order and writability, Borsh argument layouts and account data
//! offsets. Nothing here signs or talks to the network.

use anchor_lang::prelude::pubkey;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

/// MessageTransmitterV2 (same id on mainnet and devnet).
pub const MESSAGE_TRANSMITTER_V2: Pubkey = pubkey!("CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC");
/// TokenMessengerMinterV2 (same id on mainnet and devnet).
pub const TOKEN_MESSENGER_MINTER_V2: Pubkey =
    pubkey!("CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe");
/// CCTP domain of Solana.
pub const SOLANA_DOMAIN: u32 = 5;
/// Fast Transfer (confirmed) and Standard Transfer (finalized) thresholds.
pub const FINALITY_FAST: u32 = 1_000;
pub const FINALITY_STANDARD: u32 = 2_000;
/// `MessageTransmitter::EVENT_ACCOUNT_WINDOW_SECONDS`: a `MessageSent`
/// account can be reclaimed this long after its creation.
pub const EVENT_ACCOUNT_WINDOW_SECONDS: i64 = 5 * 24 * 60 * 60;
/// `UsedNonce` account size: discriminator + `is_used: bool`.
pub const USED_NONCE_ACCOUNT_LEN: usize = 9;

/// Anchor instruction discriminators (`sha256("global:<name>")[..8]`).
pub const DEPOSIT_FOR_BURN_DISCRIMINATOR: [u8; 8] = [215, 60, 61, 46, 114, 55, 128, 176];
pub const DEPOSIT_FOR_BURN_WITH_HOOK_DISCRIMINATOR: [u8; 8] =
    [111, 245, 62, 131, 204, 108, 223, 155];
pub const RECEIVE_MESSAGE_DISCRIMINATOR: [u8; 8] = [38, 144, 127, 225, 31, 225, 238, 25];
pub const RECLAIM_EVENT_ACCOUNT_DISCRIMINATOR: [u8; 8] = [94, 198, 180, 159, 131, 236, 15, 174];

/// Anchor account discriminators (`sha256("account:<Name>")[..8]`).
pub const MESSAGE_TRANSMITTER_ACCOUNT: [u8; 8] = [71, 40, 180, 142, 19, 203, 35, 252];
pub const TOKEN_MESSENGER_ACCOUNT: [u8; 8] = [162, 4, 242, 52, 147, 243, 221, 96];
pub const TOKEN_MINTER_ACCOUNT: [u8; 8] = [122, 133, 84, 63, 57, 159, 171, 206];
pub const MESSAGE_SENT_ACCOUNT: [u8; 8] = [131, 100, 133, 56, 166, 225, 151, 60];

/// SPL Token `TransferChecked` instruction tag.
const TOKEN_TRANSFER_CHECKED: u8 = 12;

/// Circle Forwarding Service hook magic (`bytes24`, zero padded).
pub const FORWARD_HOOK_MAGIC: &[u8; 12] = b"cctp-forward";
/// Marker of the zkAPI inbound-intent hook bytes after the forward hook.
pub const INBOUND_INTENT_MARKER: &[u8; 8] = b"DGNZK-IN";

/// Errors decoding CCTP bytes. Every variant is a client-input problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CctpError(pub String);

impl std::fmt::Display for CctpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CctpError {}

fn error(message: impl Into<String>) -> CctpError {
    CctpError(message.into())
}

fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}

/// The fixed CCTP accounts for one local token (USDC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CctpAccounts {
    pub mint: Pubkey,
    pub message_transmitter: Pubkey,
    pub token_messenger: Pubkey,
    pub token_minter: Pubkey,
    pub local_token: Pubkey,
    pub custody: Pubkey,
    pub sender_authority: Pubkey,
    /// `["message_transmitter_authority", TokenMessengerMinterV2]` under MT.
    pub message_transmitter_authority: Pubkey,
    pub message_transmitter_event_authority: Pubkey,
    pub token_messenger_event_authority: Pubkey,
}

impl CctpAccounts {
    pub fn new(mint: Pubkey) -> Self {
        let tmm = &TOKEN_MESSENGER_MINTER_V2;
        let mt = &MESSAGE_TRANSMITTER_V2;
        Self {
            mint,
            message_transmitter: pda(&[b"message_transmitter"], mt),
            token_messenger: pda(&[b"token_messenger"], tmm),
            token_minter: pda(&[b"token_minter"], tmm),
            local_token: pda(&[b"local_token", mint.as_ref()], tmm),
            custody: pda(&[b"custody", mint.as_ref()], tmm),
            sender_authority: pda(&[b"sender_authority"], tmm),
            message_transmitter_authority: pda(
                &[b"message_transmitter_authority", tmm.as_ref()],
                mt,
            ),
            message_transmitter_event_authority: pda(&[b"__event_authority"], mt),
            token_messenger_event_authority: pda(&[b"__event_authority"], tmm),
        }
    }
}

/// `["remote_token_messenger", domain as decimal string]` under TMM.
pub fn remote_token_messenger(domain: u32) -> Pubkey {
    pda(
        &[b"remote_token_messenger", domain.to_string().as_bytes()],
        &TOKEN_MESSENGER_MINTER_V2,
    )
}

/// `["token_pair", domain as decimal string, remote token]` under TMM.
pub fn token_pair(domain: u32, remote_token: &[u8; 32]) -> Pubkey {
    pda(
        &[b"token_pair", domain.to_string().as_bytes(), remote_token],
        &TOKEN_MESSENGER_MINTER_V2,
    )
}

/// `["used_nonce", nonce]` under MT.
pub fn used_nonce(nonce: &[u8; 32]) -> Pubkey {
    pda(&[b"used_nonce", nonce], &MESSAGE_TRANSMITTER_V2)
}

/// `["denylist_account", owner]` under TMM; a burn fails if it has data.
pub fn denylist_account(owner: &Pubkey) -> Pubkey {
    pda(
        &[b"denylist_account", owner.as_ref()],
        &TOKEN_MESSENGER_MINTER_V2,
    )
}

/// `DepositForBurnParams` (+ `hook_data` for the `_with_hook` variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnParams {
    pub amount: u64,
    pub destination_domain: u32,
    pub mint_recipient: [u8; 32],
    pub destination_caller: [u8; 32],
    pub max_fee: u64,
    pub min_finality_threshold: u32,
    /// Empty selects `deposit_for_burn`, non-empty `deposit_for_burn_with_hook`.
    pub hook_data: Vec<u8>,
}

/// `deposit_for_burn` / `deposit_for_burn_with_hook` (chosen by whether
/// `hook_data` is empty), accounts in IDL order including the event-CPI pair.
pub fn deposit_for_burn_instruction(
    accounts: &CctpAccounts,
    owner: &Pubkey,
    event_rent_payer: &Pubkey,
    burn_token_account: &Pubkey,
    message_sent_event_data: &Pubkey,
    params: &BurnParams,
) -> Instruction {
    let with_hook = !params.hook_data.is_empty();
    let mut data = Vec::with_capacity(8 + 92 + 4 + params.hook_data.len());
    data.extend_from_slice(if with_hook {
        &DEPOSIT_FOR_BURN_WITH_HOOK_DISCRIMINATOR
    } else {
        &DEPOSIT_FOR_BURN_DISCRIMINATOR
    });
    data.extend_from_slice(&params.amount.to_le_bytes());
    data.extend_from_slice(&params.destination_domain.to_le_bytes());
    data.extend_from_slice(&params.mint_recipient);
    data.extend_from_slice(&params.destination_caller);
    data.extend_from_slice(&params.max_fee.to_le_bytes());
    data.extend_from_slice(&params.min_finality_threshold.to_le_bytes());
    if with_hook {
        push_bytes(&mut data, &params.hook_data);
    }
    Instruction {
        program_id: TOKEN_MESSENGER_MINTER_V2,
        accounts: vec![
            AccountMeta::new_readonly(*owner, true),
            AccountMeta::new(*event_rent_payer, true),
            AccountMeta::new_readonly(accounts.sender_authority, false),
            AccountMeta::new(*burn_token_account, false),
            AccountMeta::new_readonly(denylist_account(owner), false),
            AccountMeta::new(accounts.message_transmitter, false),
            AccountMeta::new_readonly(accounts.token_messenger, false),
            AccountMeta::new_readonly(remote_token_messenger(params.destination_domain), false),
            AccountMeta::new_readonly(accounts.token_minter, false),
            AccountMeta::new(accounts.local_token, false),
            AccountMeta::new(accounts.mint, false),
            AccountMeta::new(*message_sent_event_data, true),
            AccountMeta::new_readonly(MESSAGE_TRANSMITTER_V2, false),
            AccountMeta::new_readonly(TOKEN_MESSENGER_MINTER_V2, false),
            AccountMeta::new_readonly(crate::vault_program::token::TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
            AccountMeta::new_readonly(accounts.token_messenger_event_authority, false),
            AccountMeta::new_readonly(TOKEN_MESSENGER_MINTER_V2, false),
        ],
        data,
    }
}

/// `receive_message` into TokenMessengerMinterV2 with the remaining accounts
/// of `handle_receive_{finalized,unfinalized}_message` in IDL order.
pub fn receive_message_instruction(
    accounts: &CctpAccounts,
    payer: &Pubkey,
    caller: &Pubkey,
    message: &[u8],
    attestation: &[u8],
    recipient_token_account: &Pubkey,
    fee_recipient_token_account: &Pubkey,
) -> Result<Instruction, CctpError> {
    let parsed = MessageV2::parse(message)?;
    let burn = BurnMessageV2::parse(parsed.body)?;
    let mut data = Vec::with_capacity(8 + 8 + message.len() + attestation.len());
    data.extend_from_slice(&RECEIVE_MESSAGE_DISCRIMINATOR);
    push_bytes(&mut data, message);
    push_bytes(&mut data, attestation);
    Ok(Instruction {
        program_id: MESSAGE_TRANSMITTER_V2,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*caller, true),
            AccountMeta::new_readonly(accounts.message_transmitter_authority, false),
            AccountMeta::new_readonly(accounts.message_transmitter, false),
            AccountMeta::new(used_nonce(&parsed.nonce), false),
            AccountMeta::new_readonly(TOKEN_MESSENGER_MINTER_V2, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
            AccountMeta::new_readonly(accounts.message_transmitter_event_authority, false),
            AccountMeta::new_readonly(MESSAGE_TRANSMITTER_V2, false),
            // Remaining accounts forwarded to the TokenMessengerMinter handler.
            AccountMeta::new_readonly(accounts.token_messenger, false),
            AccountMeta::new_readonly(remote_token_messenger(parsed.source_domain), false),
            AccountMeta::new_readonly(accounts.token_minter, false),
            AccountMeta::new(accounts.local_token, false),
            AccountMeta::new_readonly(token_pair(parsed.source_domain, &burn.burn_token), false),
            AccountMeta::new(*fee_recipient_token_account, false),
            AccountMeta::new(*recipient_token_account, false),
            AccountMeta::new(accounts.custody, false),
            AccountMeta::new_readonly(crate::vault_program::token::TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(accounts.token_messenger_event_authority, false),
            AccountMeta::new_readonly(TOKEN_MESSENGER_MINTER_V2, false),
        ],
        data,
    })
}

/// `reclaim_event_account`: closes a `MessageSent` account to its rent payer.
pub fn reclaim_event_account_instruction(
    accounts: &CctpAccounts,
    payee: &Pubkey,
    message_sent_event_data: &Pubkey,
    attestation: &[u8],
    destination_message: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(16 + attestation.len() + destination_message.len());
    data.extend_from_slice(&RECLAIM_EVENT_ACCOUNT_DISCRIMINATOR);
    push_bytes(&mut data, attestation);
    push_bytes(&mut data, destination_message);
    Instruction {
        program_id: MESSAGE_TRANSMITTER_V2,
        accounts: vec![
            AccountMeta::new(*payee, true),
            AccountMeta::new(accounts.message_transmitter, false),
            AccountMeta::new(*message_sent_event_data, false),
        ],
        data,
    }
}

/// Classic SPL Token `TransferChecked { amount, decimals }`.
pub fn transfer_checked_instruction(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(TOKEN_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: crate::vault_program::token::TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Borsh `Vec<u8>`: u32 LE length then the bytes.
fn push_bytes(data: &mut Vec<u8>, bytes: &[u8]) {
    data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(bytes);
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().expect("checked length")
}

fn be_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(array(bytes, at))
}

/// A uint256 big-endian field that must fit a u64.
fn be_u256_u64(bytes: &[u8], at: usize, label: &str) -> Result<u64, CctpError> {
    if bytes[at..at + 24].iter().any(|byte| *byte != 0) {
        return Err(error(format!("burn message {label} exceeds u64")));
    }
    Ok(u64::from_be_bytes(array(bytes, at + 24)))
}

/// A CCTP V2 message header (148 bytes) and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageV2<'a> {
    pub version: u32,
    pub source_domain: u32,
    pub destination_domain: u32,
    pub nonce: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub destination_caller: [u8; 32],
    pub min_finality_threshold: u32,
    pub finality_threshold_executed: u32,
    pub body: &'a [u8],
}

impl<'a> MessageV2<'a> {
    pub const HEADER_LEN: usize = 148;

    pub fn parse(bytes: &'a [u8]) -> Result<Self, CctpError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(error("CCTP message is shorter than its header"));
        }
        Ok(Self {
            version: be_u32(bytes, 0),
            source_domain: be_u32(bytes, 4),
            destination_domain: be_u32(bytes, 8),
            nonce: array(bytes, 12),
            sender: array(bytes, 44),
            recipient: array(bytes, 76),
            destination_caller: array(bytes, 108),
            min_finality_threshold: be_u32(bytes, 140),
            finality_threshold_executed: be_u32(bytes, 144),
            body: &bytes[Self::HEADER_LEN..],
        })
    }
}

/// A CCTP V2 `BurnMessage` body (228 bytes plus hook data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnMessageV2<'a> {
    pub version: u32,
    pub burn_token: [u8; 32],
    pub mint_recipient: [u8; 32],
    pub amount: u64,
    pub message_sender: [u8; 32],
    pub max_fee: u64,
    pub fee_executed: u64,
    pub expiration_block: u64,
    pub hook_data: &'a [u8],
}

impl<'a> BurnMessageV2<'a> {
    pub const FIXED_LEN: usize = 228;

    pub fn parse(body: &'a [u8]) -> Result<Self, CctpError> {
        if body.len() < Self::FIXED_LEN {
            return Err(error("CCTP burn message is shorter than its fixed fields"));
        }
        Ok(Self {
            version: be_u32(body, 0),
            burn_token: array(body, 4),
            mint_recipient: array(body, 36),
            amount: be_u256_u64(body, 68, "amount")?,
            message_sender: array(body, 100),
            max_fee: be_u256_u64(body, 132, "max fee")?,
            fee_executed: be_u256_u64(body, 164, "fee executed")?,
            expiration_block: be_u256_u64(body, 196, "expiration block")?,
            hook_data: &body[Self::FIXED_LEN..],
        })
    }
}

/// The Circle Forwarding Service version-0 hook at the start of `hook_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardHook<'a> {
    /// Owner of the USDC ATA the Forwarding Service creates, when requested.
    pub create_ata_owner: Option<[u8; 32]>,
    /// Developer-defined bytes after Circle's reserved fields.
    pub developer_data: &'a [u8],
}

impl<'a> ForwardHook<'a> {
    /// `bytes24 "cctp-forward" ‖ u32 BE version 0 ‖ u32 BE n ‖ n bytes`,
    /// where `n` is 0 or 33 (`0x01 ‖ owner`). Anything else is not ours.
    pub fn parse(hook: &'a [u8]) -> Result<Self, CctpError> {
        if hook.len() < 32
            || &hook[..12] != FORWARD_HOOK_MAGIC
            || hook[12..24].iter().any(|byte| *byte != 0)
        {
            return Err(error("hook data does not start with the cctp-forward hook"));
        }
        if be_u32(hook, 24) != 0 {
            return Err(error(
                "only version 0 of the cctp-forward hook is supported",
            ));
        }
        match be_u32(hook, 28) {
            0 => Ok(Self {
                create_ata_owner: None,
                developer_data: &hook[32..],
            }),
            33 if hook.len() >= 65 && hook[32] == 1 => Ok(Self {
                create_ata_owner: Some(array(hook, 33)),
                developer_data: &hook[65..],
            }),
            _ => Err(error("cctp-forward hook has unsupported reserved data")),
        }
    }
}

/// The fixed prefix of a zkAPI `InboundIntent` (version 1) carried after the
/// forward hook as `"DGNZK-IN" ‖ u16 LE len ‖ borsh(InboundIntent)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundIntentHead {
    pub version: u8,
    pub commitment: [u8; 32],
    pub emergency_owner: [u8; 32],
}

impl InboundIntentHead {
    pub fn parse(developer_data: &[u8]) -> Result<Self, CctpError> {
        if developer_data.len() < 10 || &developer_data[..8] != INBOUND_INTENT_MARKER {
            return Err(error("hook data carries no zkAPI inbound intent"));
        }
        let len = usize::from(u16::from_le_bytes(array(developer_data, 8)));
        let intent = &developer_data[10..];
        if intent.len() != len || len < 65 {
            return Err(error("zkAPI inbound intent length is inconsistent"));
        }
        let head = Self {
            version: intent[0],
            commitment: array(intent, 1),
            emergency_owner: array(intent, 33),
        };
        if head.version != 1 {
            return Err(error("unsupported zkAPI inbound intent version"));
        }
        Ok(head)
    }
}

fn account_body<'a>(
    data: &'a [u8],
    discriminator: &[u8; 8],
    min_len: usize,
    label: &str,
) -> Result<&'a [u8], CctpError> {
    if data.len() < min_len || &data[..8] != discriminator {
        return Err(error(format!(
            "{label} account data is not the expected layout"
        )));
    }
    Ok(data)
}

/// `MessageTransmitter.paused` (offset 8 + 4 × 32).
pub fn message_transmitter_paused(data: &[u8]) -> Result<bool, CctpError> {
    let data = account_body(
        data,
        &MESSAGE_TRANSMITTER_ACCOUNT,
        137,
        "MessageTransmitter",
    )?;
    decode_bool(data[136], "MessageTransmitter.paused")
}

/// `TokenMinter.paused` (offset 8 + 2 × 32).
pub fn token_minter_paused(data: &[u8]) -> Result<bool, CctpError> {
    let data = account_body(data, &TOKEN_MINTER_ACCOUNT, 73, "TokenMinter")?;
    decode_bool(data[72], "TokenMinter.paused")
}

/// `TokenMessenger.fee_recipient` (offset 8 + 3 × 32 + 4 + 1).
pub fn token_messenger_fee_recipient(data: &[u8]) -> Result<Pubkey, CctpError> {
    let data = account_body(data, &TOKEN_MESSENGER_ACCOUNT, 141, "TokenMessenger")?;
    Ok(Pubkey::new_from_array(array(data, 109)))
}

fn decode_bool(byte: u8, label: &str) -> Result<bool, CctpError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(error(format!("{label} is not a boolean"))),
    }
}

/// A `MessageSent` event account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSentAccount {
    pub rent_payer: Pubkey,
    pub created_at: i64,
    pub message: Vec<u8>,
}

impl MessageSentAccount {
    pub fn parse(data: &[u8]) -> Result<Self, CctpError> {
        let data = account_body(data, &MESSAGE_SENT_ACCOUNT, 52, "MessageSent")?;
        let len = u32::from_le_bytes(array(data, 48)) as usize;
        let message = data
            .get(52..52usize.saturating_add(len))
            .ok_or_else(|| error("MessageSent message is truncated"))?;
        Ok(Self {
            rent_payer: Pubkey::new_from_array(array(data, 8)),
            created_at: i64::from_le_bytes(array(data, 40)),
            message: message.to_vec(),
        })
    }
}

/// Whether `destination` carries the source-chain fields of `stored`, as
/// `Message::hash_source_fields` compares them in `reclaim_event_account`:
/// header bytes `0..12` and `44..144` and the total length (the nonce, the
/// executed finality and the body's executed fee are filled in by Iris).
pub fn same_source_fields(stored: &[u8], destination: &[u8]) -> bool {
    stored.len() >= MessageV2::HEADER_LEN
        && stored.len() == destination.len()
        && stored[..12] == destination[..12]
        && stored[44..144] == destination[44..144]
}

/// Address Lookup Table program. A `receive_message` with its 20 accounts,
/// the message, hook and attestation does not fit a legacy transaction, so
/// the relay sends it as a v0 transaction against its own lookup table.
pub const ADDRESS_LOOKUP_TABLE_PROGRAM: Pubkey =
    pubkey!("AddressLookupTab1e1111111111111111111111111");
/// `LOOKUP_TABLE_META_SIZE`: addresses start after the table metadata.
pub const LOOKUP_TABLE_META_SIZE: usize = 56;
/// Bincode `ProgramInstruction` variant tags.
pub const LOOKUP_TABLE_CREATE: u32 = 0;
pub const LOOKUP_TABLE_EXTEND: u32 = 2;

/// `[authority, recent_slot LE]` under the lookup table program.
pub fn lookup_table_address(authority: &Pubkey, recent_slot: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[authority.as_ref(), &recent_slot.to_le_bytes()],
        &ADDRESS_LOOKUP_TABLE_PROGRAM,
    )
}

/// `CreateLookupTable { recent_slot, bump_seed }` with `authority` also the
/// rent payer. Returns the instruction and the table address.
pub fn create_lookup_table_instruction(
    authority: &Pubkey,
    recent_slot: u64,
) -> (Instruction, Pubkey) {
    let (table, bump) = lookup_table_address(authority, recent_slot);
    let mut data = LOOKUP_TABLE_CREATE.to_le_bytes().to_vec();
    data.extend_from_slice(&recent_slot.to_le_bytes());
    data.push(bump);
    (
        Instruction {
            program_id: ADDRESS_LOOKUP_TABLE_PROGRAM,
            accounts: vec![
                AccountMeta::new(table, false),
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new(*authority, true),
                AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
            ],
            data,
        },
        table,
    )
}

/// `ExtendLookupTable { new_addresses }` (bincode `Vec`: u64 LE length).
pub fn extend_lookup_table_instruction(
    table: &Pubkey,
    authority: &Pubkey,
    addresses: &[Pubkey],
) -> Instruction {
    let mut data = LOOKUP_TABLE_EXTEND.to_le_bytes().to_vec();
    data.extend_from_slice(&(addresses.len() as u64).to_le_bytes());
    for address in addresses {
        data.extend_from_slice(address.as_ref());
    }
    Instruction {
        program_id: ADDRESS_LOOKUP_TABLE_PROGRAM,
        accounts: vec![
            AccountMeta::new(*table, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
        ],
        data,
    }
}

/// A decoded lookup table account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupTable {
    pub deactivation_slot: u64,
    pub last_extended_slot: u64,
    pub authority: Option<Pubkey>,
    pub addresses: Vec<Pubkey>,
}

impl LookupTable {
    pub fn parse(data: &[u8]) -> Result<Self, CctpError> {
        if data.len() < LOOKUP_TABLE_META_SIZE
            || u32::from_le_bytes(array(data, 0)) != 1
            || !(data.len() - LOOKUP_TABLE_META_SIZE).is_multiple_of(32)
        {
            return Err(error("account is not an address lookup table"));
        }
        let authority = match data[21] {
            0 => None,
            1 => Some(Pubkey::new_from_array(array(data, 22))),
            _ => return Err(error("lookup table authority tag is invalid")),
        };
        Ok(Self {
            deactivation_slot: u64::from_le_bytes(array(data, 4)),
            last_extended_slot: u64::from_le_bytes(array(data, 12)),
            authority,
            addresses: data[LOOKUP_TABLE_META_SIZE..]
                .as_chunks::<32>()
                .0
                .iter()
                .map(|chunk| Pubkey::new_from_array(*chunk))
                .collect(),
        })
    }
}

/// Accounts of every USDC `receive_message` that a lookup table can hold
/// (no signer, no per-message account).
pub fn receive_lookup_addresses(
    accounts: &CctpAccounts,
    fee_recipient_token_account: &Pubkey,
) -> Vec<Pubkey> {
    vec![
        accounts.message_transmitter_authority,
        accounts.message_transmitter,
        TOKEN_MESSENGER_MINTER_V2,
        anchor_lang::system_program::ID,
        accounts.message_transmitter_event_authority,
        MESSAGE_TRANSMITTER_V2,
        accounts.token_messenger,
        accounts.token_minter,
        accounts.local_token,
        *fee_recipient_token_account,
        accounts.custody,
        crate::vault_program::token::TOKEN_PROGRAM_ID,
        accounts.token_messenger_event_authority,
        crate::ASSOCIATED_TOKEN_PROGRAM_ID,
        accounts.mint,
    ]
}

/// Per-source-domain accounts of a `receive_message` (`remote_token_messenger`
/// and `token_pair` for the message's burn token).
pub fn receive_domain_addresses(message: &[u8]) -> Result<[Pubkey; 2], CctpError> {
    let parsed = MessageV2::parse(message)?;
    let burn = BurnMessageV2::parse(parsed.body)?;
    Ok([
        remote_token_messenger(parsed.source_domain),
        token_pair(parsed.source_domain, &burn.burn_token),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn key(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn discriminators_are_anchor_sighashes() {
        let global = |name: &str| -> [u8; 8] {
            hash(format!("global:{name}").as_bytes())[..8]
                .try_into()
                .unwrap()
        };
        let account = |name: &str| -> [u8; 8] {
            hash(format!("account:{name}").as_bytes())[..8]
                .try_into()
                .unwrap()
        };
        assert_eq!(global("deposit_for_burn"), DEPOSIT_FOR_BURN_DISCRIMINATOR);
        assert_eq!(
            global("deposit_for_burn_with_hook"),
            DEPOSIT_FOR_BURN_WITH_HOOK_DISCRIMINATOR
        );
        assert_eq!(global("receive_message"), RECEIVE_MESSAGE_DISCRIMINATOR);
        assert_eq!(
            global("reclaim_event_account"),
            RECLAIM_EVENT_ACCOUNT_DISCRIMINATOR
        );
        assert_eq!(account("MessageTransmitter"), MESSAGE_TRANSMITTER_ACCOUNT);
        assert_eq!(account("TokenMessenger"), TOKEN_MESSENGER_ACCOUNT);
        assert_eq!(account("TokenMinter"), TOKEN_MINTER_ACCOUNT);
        assert_eq!(account("MessageSent"), MESSAGE_SENT_ACCOUNT);
    }

    /// Live mainnet PDAs recorded in the design (RPC, 2026-11-07).
    #[test]
    fn pdas_match_live_mainnet_accounts() {
        let accounts = CctpAccounts::new(crate::vault_program::token::USDC_MINT);
        assert_eq!(
            accounts.message_transmitter.to_string(),
            "W1k5ijkaSTo5iA5zChNpfzcy796fLhkBxfmJuR8W8HU"
        );
        assert_eq!(
            accounts.token_messenger.to_string(),
            "AawthJCGRmggpfv9MMWV6Jmo9cue4gL9wUZgRBShg58W"
        );
        assert_eq!(
            accounts.token_minter.to_string(),
            "E1bQJ8eMMn3zmeSewW3HQ8zmJr7KR75JonbwAtWx2bux"
        );
        assert_eq!(
            accounts.local_token.to_string(),
            "CRBBbuLCyrkQy4dCTHxqstSmDQv4ajBeUVb9qUdMVaP1"
        );
    }

    #[test]
    fn deposit_for_burn_golden_bytes() {
        let accounts = CctpAccounts::new(key(9));
        let mut params = BurnParams {
            amount: 1_000_000,
            destination_domain: 6,
            mint_recipient: [0x11; 32],
            destination_caller: [0; 32],
            max_fee: 500,
            min_finality_threshold: FINALITY_FAST,
            hook_data: Vec::new(),
        };
        let plain =
            deposit_for_burn_instruction(&accounts, &key(1), &key(2), &key(3), &key(4), &params);
        assert_eq!(
            hex(&plain.data),
            format!(
                "d73c3d2e723780b0{}{}{}{}{}{}",
                "40420f0000000000",
                "06000000",
                "11".repeat(32),
                "00".repeat(32),
                "f401000000000000",
                "e8030000"
            )
        );
        params.hook_data = vec![0xaa, 0xbb];
        let hooked =
            deposit_for_burn_instruction(&accounts, &key(1), &key(2), &key(3), &key(4), &params);
        assert_eq!(&hooked.data[..8], &DEPOSIT_FOR_BURN_WITH_HOOK_DISCRIMINATOR);
        assert_eq!(plain.data.len(), 96);
        assert_eq!(&hooked.data[8..96], &plain.data[8..96]);
        assert_eq!(hex(&hooked.data[96..]), "02000000aabb");
        let metas: Vec<_> = plain
            .accounts
            .iter()
            .map(|meta| (meta.pubkey, meta.is_signer, meta.is_writable))
            .collect();
        assert_eq!(
            metas,
            vec![
                (key(1), true, false),
                (key(2), true, true),
                (accounts.sender_authority, false, false),
                (key(3), false, true),
                (denylist_account(&key(1)), false, false),
                (accounts.message_transmitter, false, true),
                (accounts.token_messenger, false, false),
                (remote_token_messenger(6), false, false),
                (accounts.token_minter, false, false),
                (accounts.local_token, false, true),
                (key(9), false, true),
                (key(4), true, true),
                (MESSAGE_TRANSMITTER_V2, false, false),
                (TOKEN_MESSENGER_MINTER_V2, false, false),
                (crate::vault_program::token::TOKEN_PROGRAM_ID, false, false),
                (anchor_lang::system_program::ID, false, false),
                (accounts.token_messenger_event_authority, false, false),
                (TOKEN_MESSENGER_MINTER_V2, false, false),
            ]
        );
        assert_eq!(hooked.accounts, plain.accounts);
    }

    fn message(source: u32, nonce: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; MessageV2::HEADER_LEN];
        bytes[0..4].copy_from_slice(&1u32.to_be_bytes());
        bytes[4..8].copy_from_slice(&source.to_be_bytes());
        bytes[8..12].copy_from_slice(&SOLANA_DOMAIN.to_be_bytes());
        bytes[12..44].fill(nonce);
        bytes[76..108].copy_from_slice(TOKEN_MESSENGER_MINTER_V2.as_ref());
        bytes[140..144].copy_from_slice(&FINALITY_FAST.to_be_bytes());
        bytes[144..148].copy_from_slice(&FINALITY_FAST.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn burn_body(recipient: [u8; 32], amount: u64, hook: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; BurnMessageV2::FIXED_LEN];
        body[0..4].copy_from_slice(&1u32.to_be_bytes());
        body[4..36].fill(0x22);
        body[36..68].copy_from_slice(&recipient);
        body[92..100].copy_from_slice(&amount.to_be_bytes());
        body[188..196].copy_from_slice(&7u64.to_be_bytes());
        body.extend_from_slice(hook);
        body
    }

    #[test]
    fn receive_and_reclaim_golden_bytes() {
        let accounts = CctpAccounts::new(key(9));
        let body = burn_body([0x33; 32], 5_000_000, &[]);
        let bytes = message(6, 0x44, &body);
        let parsed = MessageV2::parse(&bytes).unwrap();
        let burn = BurnMessageV2::parse(parsed.body).unwrap();
        assert_eq!((parsed.source_domain, parsed.nonce), (6, [0x44; 32]));
        assert_eq!((burn.amount, burn.fee_executed), (5_000_000, 7));
        let attestation = [0x55u8; 130];
        let instruction = receive_message_instruction(
            &accounts,
            &key(1),
            &key(1),
            &bytes,
            &attestation,
            &key(3),
            &key(4),
        )
        .unwrap();
        assert_eq!(
            &instruction.data[..8],
            &[38, 144, 127, 225, 31, 225, 238, 25]
        );
        assert_eq!(
            &instruction.data[8..12],
            &(bytes.len() as u32).to_le_bytes()
        );
        assert_eq!(&instruction.data[12..12 + bytes.len()], &bytes[..]);
        assert_eq!(
            &instruction.data[12 + bytes.len()..16 + bytes.len()],
            &130u32.to_le_bytes()
        );
        assert_eq!(instruction.data.len(), 16 + bytes.len() + 130);
        let keys: Vec<_> = instruction
            .accounts
            .iter()
            .map(|meta| meta.pubkey)
            .collect();
        assert_eq!(keys[4], used_nonce(&[0x44; 32]));
        assert_eq!(keys[10], remote_token_messenger(6));
        assert_eq!(keys[13], token_pair(6, &[0x22; 32]));
        assert_eq!(keys[14], key(4));
        assert_eq!(keys[15], key(3));
        assert_eq!(instruction.accounts.len(), 20);
        let writable: Vec<_> = instruction
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, meta)| meta.is_writable)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(writable, vec![0, 4, 12, 14, 15, 16]);

        let reclaim = reclaim_event_account_instruction(&accounts, &key(1), &key(5), &[1, 2], &[3]);
        assert_eq!(hex(&reclaim.data), "5ec6b49f83ec0fae0200000001020100000003");
        assert_eq!(
            reclaim
                .accounts
                .iter()
                .map(|meta| (meta.pubkey, meta.is_signer, meta.is_writable))
                .collect::<Vec<_>>(),
            vec![
                (key(1), true, true),
                (accounts.message_transmitter, false, true),
                (key(5), false, true)
            ]
        );
    }

    #[test]
    fn transfer_checked_golden_bytes() {
        let instruction = transfer_checked_instruction(&key(1), &key(2), &key(3), &key(4), 258, 6);
        assert_eq!(hex(&instruction.data), "0c020100000000000006");
        assert_eq!(
            instruction
                .accounts
                .iter()
                .map(|meta| (meta.pubkey, meta.is_signer, meta.is_writable))
                .collect::<Vec<_>>(),
            vec![
                (key(1), false, true),
                (key(2), false, false),
                (key(3), false, true),
                (key(4), true, false)
            ]
        );
    }

    #[test]
    fn hooks_and_intents_decode_strictly() {
        let static_hook = "636374702d666f72776172640000000000000000000000000000000000000000";
        let bytes: Vec<u8> = (0..static_hook.len() / 2)
            .map(|i| u8::from_str_radix(&static_hook[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let hook = ForwardHook::parse(&bytes).unwrap();
        assert_eq!(hook.create_ata_owner, None);
        assert!(hook.developer_data.is_empty());

        let mut intent = vec![1u8];
        intent.extend_from_slice(&[7; 32]);
        intent.extend_from_slice(&[8; 32]);
        intent.extend_from_slice(&[0; 40]);
        let mut extended = bytes[..28].to_vec();
        extended.extend_from_slice(&33u32.to_be_bytes());
        extended.push(1);
        extended.extend_from_slice(&[8; 32]);
        extended.extend_from_slice(INBOUND_INTENT_MARKER);
        extended.extend_from_slice(&(intent.len() as u16).to_le_bytes());
        extended.extend_from_slice(&intent);
        let hook = ForwardHook::parse(&extended).unwrap();
        assert_eq!(hook.create_ata_owner, Some([8; 32]));
        let head = InboundIntentHead::parse(hook.developer_data).unwrap();
        assert_eq!(head.commitment, [7; 32]);
        assert_eq!(head.emergency_owner, [8; 32]);

        let mut truncated = extended.clone();
        truncated.pop();
        let hook = ForwardHook::parse(&truncated).unwrap();
        assert!(InboundIntentHead::parse(hook.developer_data).is_err());
        let mut wrong_version = extended.clone();
        wrong_version[27] = 1;
        assert!(ForwardHook::parse(&wrong_version).is_err());
        assert!(ForwardHook::parse(b"not a hook at all, definitely not").is_err());
    }

    #[test]
    fn state_decoders_read_documented_offsets() {
        let mut mt = MESSAGE_TRANSMITTER_ACCOUNT.to_vec();
        mt.resize(200, 0);
        assert!(!message_transmitter_paused(&mt).unwrap());
        mt[136] = 1;
        assert!(message_transmitter_paused(&mt).unwrap());
        mt[136] = 2;
        assert!(message_transmitter_paused(&mt).is_err());
        let mut minter = TOKEN_MINTER_ACCOUNT.to_vec();
        minter.resize(74, 0);
        minter[72] = 1;
        assert!(token_minter_paused(&minter).unwrap());
        assert!(token_minter_paused(&mt).is_err());
        let mut messenger = TOKEN_MESSENGER_ACCOUNT.to_vec();
        messenger.resize(145, 0);
        messenger[109..141].copy_from_slice(&[6; 32]);
        assert_eq!(token_messenger_fee_recipient(&messenger).unwrap(), key(6));
        let mut sent = MESSAGE_SENT_ACCOUNT.to_vec();
        sent.extend_from_slice(&[2; 32]);
        sent.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        sent.extend_from_slice(&3u32.to_le_bytes());
        sent.extend_from_slice(&[9, 9, 9]);
        let parsed = MessageSentAccount::parse(&sent).unwrap();
        assert_eq!(
            (parsed.rent_payer, parsed.created_at, parsed.message),
            (key(2), 1_700_000_000, vec![9, 9, 9])
        );
    }

    #[test]
    fn reclaim_source_fields_ignore_nonce_and_executed_values() {
        let stored = message(5, 0, &[1, 2, 3]);
        let mut attested = stored.clone();
        attested[12..44].fill(0x99);
        attested[144..148].copy_from_slice(&2_000u32.to_be_bytes());
        assert!(same_source_fields(&stored, &attested));
        attested[50] ^= 1;
        assert!(!same_source_fields(&stored, &attested));
    }

    /// Cross-check against the SDK's golden vectors
    /// (`sdk/test/fixtures/cctp-vectors.json`, produced by
    /// `sdk/services/zkapiCctp.mjs`), including two real mainnet transactions.
    #[test]
    fn encoders_match_sdk_golden_vectors_and_mainnet_transactions() {
        use std::str::FromStr;
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../sdk/test/fixtures/cctp-vectors.json"))
                .unwrap();
        let pubkey = |value: &serde_json::Value| Pubkey::from_str(value.as_str().unwrap()).unwrap();
        let bytes = |value: &serde_json::Value| -> Vec<u8> {
            let text = value.as_str().unwrap().trim_start_matches("0x");
            (0..text.len() / 2)
                .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
                .collect()
        };
        let bytes32 = |value: &serde_json::Value| -> [u8; 32] { bytes(value).try_into().unwrap() };
        let metas = |value: &serde_json::Value| -> Vec<(Pubkey, bool, bool)> {
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|meta| {
                    (
                        pubkey(&meta["pubkey"]),
                        meta["signer"].as_bool().unwrap(),
                        meta["writable"].as_bool().unwrap(),
                    )
                })
                .collect()
        };
        let ours = |instruction: &Instruction| -> Vec<(Pubkey, bool, bool)> {
            instruction
                .accounts
                .iter()
                .map(|meta| (meta.pubkey, meta.is_signer, meta.is_writable))
                .collect()
        };
        let mint = pubkey(&vectors["constants"]["usdc_mint"]);
        let accounts = CctpAccounts::new(mint);
        let pdas = &vectors["pdas"];
        for (expected, actual) in [
            ("messageTransmitter", accounts.message_transmitter),
            (
                "messageTransmitterAuthority",
                accounts.message_transmitter_authority,
            ),
            (
                "messageTransmitterEventAuthority",
                accounts.message_transmitter_event_authority,
            ),
            ("tokenMessenger", accounts.token_messenger),
            ("tokenMinter", accounts.token_minter),
            ("senderAuthority", accounts.sender_authority),
            (
                "tokenMessengerEventAuthority",
                accounts.token_messenger_event_authority,
            ),
            ("localToken", accounts.local_token),
            ("custody", accounts.custody),
        ] {
            assert_eq!(pubkey(&pdas[expected]), actual, "{expected}");
        }
        for (domain, address) in pdas["remote_token_messenger"].as_object().unwrap() {
            assert_eq!(
                remote_token_messenger(domain.parse().unwrap()),
                pubkey(address)
            );
        }
        for (domain, pair) in pdas["token_pair"].as_object().unwrap() {
            let mut remote = [0u8; 32];
            remote[12..].copy_from_slice(&bytes(&pair["remote_token"]));
            assert_eq!(
                token_pair(domain.parse().unwrap(), &remote),
                pubkey(&pair["address"])
            );
        }
        assert_eq!(
            used_nonce(&bytes32(&pdas["used_nonce"]["nonce"])),
            pubkey(&pdas["used_nonce"]["address"])
        );
        assert_eq!(
            denylist_account(&pubkey(&pdas["denylist_account"]["owner"])),
            pubkey(&pdas["denylist_account"]["address"])
        );
        let fee_recipient = pubkey(&pdas["feeRecipientTokenAccount"]);

        // receive_message for the synthetic message.
        let message_bytes = bytes(&vectors["message"]["bytes"]);
        let receive = &vectors["receive_message"];
        let payer = pubkey(&receive["payer"]);
        let recipient = Pubkey::new_from_array(
            BurnMessageV2::parse(MessageV2::parse(&message_bytes).unwrap().body)
                .unwrap()
                .mint_recipient,
        );
        let instruction = receive_message_instruction(
            &accounts,
            &payer,
            &payer,
            &message_bytes,
            &bytes(&receive["attestation"]),
            &recipient,
            &fee_recipient,
        )
        .unwrap();
        assert_eq!(instruction.data, bytes(&receive["data"]));
        assert_eq!(ours(&instruction), metas(&receive["keys"]));

        // deposit_for_burn and deposit_for_burn_with_hook.
        for name in ["deposit_for_burn", "deposit_for_burn_with_hook"] {
            let vector = &vectors[name];
            let input = &vector["input"];
            let owner = pubkey(&input["owner"]);
            let params = BurnParams {
                amount: input["amount"].as_str().unwrap().parse().unwrap(),
                destination_domain: input["destinationDomain"].as_u64().unwrap() as u32,
                mint_recipient: bytes32(&input["mintRecipient"]),
                destination_caller: bytes32(&input["destinationCaller"]),
                max_fee: input["maxFee"].as_str().unwrap().parse().unwrap(),
                min_finality_threshold: input["minFinalityThreshold"].as_u64().unwrap() as u32,
                hook_data: input.get("hookData").map(&bytes).unwrap_or_default(),
            };
            let burn_account = Pubkey::new_from_array(
                dagon_zkapi_profile::usdc_associated_token_address(&owner.to_bytes()),
            );
            let instruction = deposit_for_burn_instruction(
                &accounts,
                &owner,
                &pubkey(&input["eventRentPayer"]),
                &burn_account,
                &pubkey(&input["messageSentEventData"]),
                &params,
            );
            assert_eq!(instruction.data, bytes(&vector["data"]), "{name}");
            assert_eq!(ours(&instruction), metas(&vector["keys"]), "{name}");
        }

        // reclaim_event_account.
        let reclaim = &vectors["reclaim_event_account"];
        let instruction = reclaim_event_account_instruction(
            &accounts,
            &pubkey(&reclaim["input"]["payee"]),
            &pubkey(&reclaim["input"]["messageSentEventData"]),
            &bytes(&reclaim["input"]["attestation"]),
            &bytes(&reclaim["input"]["destinationMessage"]),
        );
        assert_eq!(instruction.data, bytes(&reclaim["data"]));
        assert_eq!(ours(&instruction), metas(&reclaim["keys"]));

        // The inbound hook names the emergency key as ATA owner and intent owner.
        let ek = pubkey(&vectors["emergency_key"]["public_key"]);
        let hook_bytes = bytes(&vectors["inbound_intent"]["inbound_hook"]);
        let hook = ForwardHook::parse(&hook_bytes).unwrap();
        assert_eq!(hook.create_ata_owner, Some(ek.to_bytes()));
        let head = InboundIntentHead::parse(hook.developer_data).unwrap();
        assert_eq!(head.emergency_owner, ek.to_bytes());
        assert_eq!(
            head.commitment,
            bytes32(&vectors["inbound_intent"]["input"]["commitment"])
        );
        let create = bytes(&vectors["forward_hook"]["create_ata"]);
        assert_eq!(
            ForwardHook::parse(&create).unwrap().create_ata_owner,
            Some(pubkey(&vectors["forward_hook"]["create_ata_owner"]).to_bytes())
        );

        // Real mainnet receive_message: same data and account list.
        let mainnet = &vectors["mainnet"]["receive_message"];
        let keys: Vec<Pubkey> = mainnet["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(&pubkey)
            .collect();
        let instruction = receive_message_instruction(
            &accounts,
            &keys[0],
            &keys[1],
            &bytes(&mainnet["message"]),
            &bytes(&mainnet["attestation"]),
            &keys[15],
            &keys[14],
        )
        .unwrap();
        assert_eq!(instruction.data, bytes(&mainnet["data"]));
        assert_eq!(
            instruction
                .accounts
                .iter()
                .map(|meta| meta.pubkey)
                .collect::<Vec<_>>(),
            keys
        );

        // Real mainnet deposit_for_burn_with_hook: re-encode its decoded params.
        let mainnet = &vectors["mainnet"]["deposit_for_burn_with_hook"];
        let data = bytes(&mainnet["data"]);
        let keys: Vec<Pubkey> = mainnet["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(&pubkey)
            .collect();
        let hook_len = u32::from_le_bytes(data[96..100].try_into().unwrap()) as usize;
        let params = BurnParams {
            amount: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            destination_domain: u32::from_le_bytes(data[16..20].try_into().unwrap()),
            mint_recipient: data[20..52].try_into().unwrap(),
            destination_caller: data[52..84].try_into().unwrap(),
            max_fee: u64::from_le_bytes(data[84..92].try_into().unwrap()),
            min_finality_threshold: u32::from_le_bytes(data[92..96].try_into().unwrap()),
            hook_data: data[100..100 + hook_len].to_vec(),
        };
        let instruction = deposit_for_burn_instruction(
            &CctpAccounts::new(keys[10]),
            &keys[0],
            &keys[1],
            &keys[3],
            &keys[11],
            &params,
        );
        assert_eq!(instruction.data, data);
        assert_eq!(
            instruction
                .accounts
                .iter()
                .map(|meta| meta.pubkey)
                .collect::<Vec<_>>(),
            keys
        );
    }
}
