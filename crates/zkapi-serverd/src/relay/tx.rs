//! Relay transaction builders and signing.
//!
//! Every message the relayer signs is built here or by the Solana ledger,
//! and passes [`audit_relayer_message`] / [`audit_relayer_v0_message`]
//! first: the relayer is the fee payer and otherwise only a rent payer
//! (vault operation owner/payer, ATA creation payer, CCTP event-rent payer,
//! receive payer/caller, reclaim payee, its own lookup table). Every
//! ek-facing transaction carries the ek's fee transfer, so the relayer is
//! paid atomically. Ek-facing transactions leave the relay unsigned
//! ([`unsigned`]); the relay adds its (and a burn's event key's)
//! signature in [`complete`] only when it broadcasts the ek-signed bytes.

use dagon_zkapi_solana_ledger::{
    cctp, compute_unit_limit_instruction, create_usdc_ata_idempotent_instruction,
    proof_compute_budget_instructions,
    relay_audit::{audit_relayer_message, audit_relayer_v0_message},
    solana_v0, AddressLookupTableAccount, SolanaHash as Hash, SolanaInstruction as Instruction,
    SolanaMessage as Message, SolanaPubkey as Pubkey, VersionedMessage, USDC_DECIMALS, USDC_MINT,
};
use solana_keypair::Keypair;
use solana_signer::Signer;

/// A wire transaction: shortvec signature count, signatures, message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub bytes: Vec<u8>,
    /// Base58 of the first (fee payer's) signature: the transaction id.
    pub signature: String,
}

/// Sign a legacy `message` after the relayer audit; required signers
/// without a keypair here keep an all-zero slot for the user to fill.
pub fn sign(
    message: &Message,
    relayer: &Keypair,
    others: &[&Keypair],
    vault_program: &Pubkey,
) -> Result<SignedTransaction, String> {
    audit_relayer_message(message, &relayer.pubkey(), vault_program)?;
    let required = usize::from(message.header.num_required_signatures);
    sign_bytes(
        &message.serialize(),
        &message.account_keys[..required],
        relayer,
        others,
    )
}

/// [`sign`] for a v0 message resolved through `tables`.
pub fn sign_v0(
    message: &solana_v0::Message,
    tables: &[AddressLookupTableAccount],
    relayer: &Keypair,
    vault_program: &Pubkey,
) -> Result<SignedTransaction, String> {
    audit_relayer_v0_message(message, tables, &relayer.pubkey(), vault_program)?;
    let required = usize::from(message.header.num_required_signatures);
    sign_bytes(
        &VersionedMessage::V0(message.clone()).serialize(),
        &message.account_keys[..required],
        relayer,
        &[],
    )
}

fn sign_bytes(
    message_bytes: &[u8],
    required: &[Pubkey],
    relayer: &Keypair,
    others: &[&Keypair],
) -> Result<SignedTransaction, String> {
    if required.len() >= 128 {
        return Err("too many required signatures".into());
    }
    let signers: Vec<&Keypair> = std::iter::once(relayer)
        .chain(others.iter().copied())
        .collect();
    for signer in &signers {
        if !required.contains(&signer.pubkey()) {
            return Err(format!("{} is not a required signer", signer.pubkey()));
        }
    }
    let mut bytes = Vec::with_capacity(1 + 64 * required.len() + message_bytes.len());
    bytes.push(required.len() as u8);
    for key in required {
        match signers.iter().find(|signer| signer.pubkey() == *key) {
            Some(signer) => bytes.extend_from_slice(signer.sign_message(message_bytes).as_ref()),
            None => bytes.extend_from_slice(&[0; 64]),
        }
    }
    bytes.extend_from_slice(message_bytes);
    if bytes.len() > 1_232 {
        return Err(format!(
            "transaction is {} bytes, above the packet limit",
            bytes.len()
        ));
    }
    let signature = bs58::encode(&bytes[1..65]).into_string();
    Ok(SignedTransaction { bytes, signature })
}

/// Audit `message` and serialize it with every signature slot zeroed.
pub fn unsigned(
    message: &Message,
    relayer: &Pubkey,
    vault_program: &Pubkey,
) -> Result<Vec<u8>, String> {
    audit_relayer_message(message, relayer, vault_program)?;
    unsigned_bytes(
        &message.serialize(),
        usize::from(message.header.num_required_signatures),
    )
}

/// [`unsigned`] for a v0 message resolved through `tables`.
pub fn unsigned_v0(
    message: &solana_v0::Message,
    tables: &[AddressLookupTableAccount],
    relayer: &Pubkey,
    vault_program: &Pubkey,
) -> Result<Vec<u8>, String> {
    audit_relayer_v0_message(message, tables, relayer, vault_program)?;
    unsigned_bytes(
        &VersionedMessage::V0(message.clone()).serialize(),
        usize::from(message.header.num_required_signatures),
    )
}

fn unsigned_bytes(message_bytes: &[u8], required: usize) -> Result<Vec<u8>, String> {
    if required == 0 || required >= 128 {
        return Err("invalid required signature count".into());
    }
    let mut bytes = Vec::with_capacity(1 + 64 * required + message_bytes.len());
    bytes.push(required as u8);
    bytes.resize(1 + 64 * required, 0);
    bytes.extend_from_slice(message_bytes);
    if bytes.len() > 1_232 {
        return Err(format!(
            "transaction is {} bytes, above the packet limit",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// The message bytes of a wire transaction.
pub fn message_bytes(bytes: &[u8]) -> Result<&[u8], String> {
    let required = usize::from(*bytes.first().ok_or("empty transaction")?);
    if required == 0 || required >= 128 || bytes.len() <= 1 + 64 * required {
        return Err("malformed transaction".into());
    }
    Ok(&bytes[1 + 64 * required..])
}

/// Index of the last instruction of `program` in a wire transaction (the
/// vault `execute_deposit` of an atomic deposit).
pub fn last_program_instruction(bytes: &[u8], program: &Pubkey) -> Option<u8> {
    let versioned: VersionedMessage = bincode::deserialize(message_bytes(bytes).ok()?).ok()?;
    let keys = versioned.static_account_keys();
    versioned
        .instructions()
        .iter()
        .rposition(|ix| keys.get(usize::from(ix.program_id_index)) == Some(program))
        .and_then(|index| u8::try_from(index).ok())
}

/// Fill the relayer's (and `others`') signature slots of a submitted wire
/// transaction, keeping every other slot (the ek's) as submitted. The
/// caller has already matched the message to the one the relay prepared and
/// audited; the ek's signature is verified by the simulation that follows.
pub fn complete(
    bytes: &[u8],
    relayer: &Keypair,
    others: &[&Keypair],
) -> Result<SignedTransaction, String> {
    let message = message_bytes(bytes)?;
    let versioned: VersionedMessage =
        bincode::deserialize(message).map_err(|error| format!("malformed message: {error}"))?;
    if versioned.serialize() != message {
        return Err("non-canonical message".into());
    }
    let required = usize::from(versioned.header().num_required_signatures);
    if usize::from(bytes[0]) != required {
        return Err("signature count differs from the message".into());
    }
    let keys = &versioned.static_account_keys()[..required];
    let signers: Vec<&Keypair> = std::iter::once(relayer)
        .chain(others.iter().copied())
        .collect();
    if signers
        .iter()
        .any(|signer| !keys.contains(&signer.pubkey()))
    {
        return Err("a relay key is not a required signer".into());
    }
    let mut out = bytes.to_vec();
    for (index, key) in keys.iter().enumerate() {
        if let Some(signer) = signers.iter().find(|signer| signer.pubkey() == *key) {
            out[1 + 64 * index..1 + 64 * (index + 1)]
                .copy_from_slice(signer.sign_message(message).as_ref());
        }
    }
    let signature = bs58::encode(&out[1..65]).into_string();
    Ok(SignedTransaction {
        bytes: out,
        signature,
    })
}

fn ata(owner: &Pubkey) -> Pubkey {
    Pubkey::new_from_array(dagon_zkapi_profile::usdc_associated_token_address(
        &owner.to_bytes(),
    ))
}

/// `TransferChecked(ATA(owner) → fee_account, fee)` signed by `owner`, or
/// nothing for a zero fee.
pub fn fee_transfer(owner: &Pubkey, fee_account: &Pubkey, fee: u64) -> Option<Instruction> {
    (fee > 0).then(|| {
        cctp::transfer_checked_instruction(
            &ata(owner),
            &USDC_MINT,
            fee_account,
            owner,
            fee,
            USDC_DECIMALS,
        )
    })
}

/// Atomically fund, initialize, write and consume an ek-owned deposit buffer,
/// returned unsigned. Only this builder may contain relay System transfers:
/// the ledger messages cannot name the relay at all, and the rent
/// advance/refund are constructed here.
#[allow(clippy::too_many_arguments)]
pub fn unsigned_deposit(
    relayer: &Pubkey,
    owner: &Pubkey,
    stages: &[Message],
    operation_rent: u64,
    note_rent: u64,
    table: &AddressLookupTableAccount,
    blockhash: &Hash,
    vault_program: &Pubkey,
) -> Result<Vec<u8>, String> {
    use dagon_zkapi_solana_ledger::AccountMeta;
    let transfer = |from: Pubkey, to: Pubkey, lamports: u64| Instruction {
        program_id: Pubkey::default(),
        accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
        data: [
            2u32.to_le_bytes().as_slice(),
            lamports.to_le_bytes().as_slice(),
        ]
        .concat(),
    };
    let advance = operation_rent
        .checked_add(note_rent)
        .ok_or("rent overflow")?;
    let mut instructions = vec![transfer(*relayer, *owner, advance)];
    for stage in stages {
        if stage.header.num_required_signatures != 1
            || stage.account_keys.first() != Some(owner)
            || stage.account_keys.contains(relayer)
        {
            return Err("deposit stages must be owned solely by the emergency key".into());
        }
        for ix in &stage.instructions {
            let program_id = *stage
                .account_keys
                .get(usize::from(ix.program_id_index))
                .ok_or("invalid deposit program index")?;
            let accounts = ix
                .accounts
                .iter()
                .map(|index| {
                    let index = usize::from(*index);
                    Ok(AccountMeta {
                        pubkey: *stage
                            .account_keys
                            .get(index)
                            .ok_or("invalid deposit account index")?,
                        is_signer: stage.is_signer(index),
                        is_writable: stage.is_maybe_writable(index, None),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            instructions.push(Instruction {
                program_id,
                accounts,
                data: ix.data.clone(),
            });
        }
    }
    // The buffer closes to ek during execute. Return exactly the advance
    // not consumed by NoteState rent, even when ek held SOL before this tx.
    instructions.push(transfer(*owner, *relayer, operation_rent));
    let message = compile_v0(relayer, &instructions, table, blockhash)?;
    // Audit the ledger instructions under the ordinary restrictive policy,
    // before adding the two fixed System transfers above.
    let inner = compile_v0(
        relayer,
        &instructions[1..instructions.len() - 1],
        table,
        blockhash,
    )?;
    audit_relayer_v0_message(&inner, std::slice::from_ref(table), relayer, vault_program)?;
    let required = usize::from(message.header.num_required_signatures);
    if required != 2 || !message.account_keys[..required].contains(owner) {
        return Err("atomic deposit requires exactly relay and emergency-key signatures".into());
    }
    unsigned_bytes(&VersionedMessage::V0(message).serialize(), required)
}

/// `[fee TransferChecked?, deposit_for_burn(_with_hook)]` paid by the relayer,
/// burning `params.amount` from `ATA(owner)`.
pub fn burn_message(
    relayer: &Pubkey,
    owner: &Pubkey,
    event_account: &Pubkey,
    fee_account: &Pubkey,
    fee: u64,
    params: &cctp::BurnParams,
    blockhash: &Hash,
) -> Message {
    let mut instructions: Vec<Instruction> =
        fee_transfer(owner, fee_account, fee).into_iter().collect();
    instructions.push(cctp::deposit_for_burn_instruction(
        &cctp::CctpAccounts::new(USDC_MINT),
        owner,
        relayer,
        &ata(owner),
        event_account,
        params,
    ));
    Message::new_with_blockhash(&instructions, Some(relayer), blockhash)
}

/// `[fee TransferChecked?, TransferChecked(amount → destination)]`.
pub fn sweep_message(
    relayer: &Pubkey,
    owner: &Pubkey,
    destination: &Pubkey,
    fee_account: &Pubkey,
    fee: u64,
    amount: u64,
    blockhash: &Hash,
) -> Message {
    let mut instructions: Vec<Instruction> =
        fee_transfer(owner, fee_account, fee).into_iter().collect();
    instructions.push(cctp::transfer_checked_instruction(
        &ata(owner),
        &USDC_MINT,
        destination,
        owner,
        amount,
        USDC_DECIMALS,
    ));
    Message::new_with_blockhash(&instructions, Some(relayer), blockhash)
}

fn compile_v0(
    relayer: &Pubkey,
    instructions: &[Instruction],
    table: &AddressLookupTableAccount,
    blockhash: &Hash,
) -> Result<solana_v0::Message, String> {
    solana_v0::Message::try_compile(
        relayer,
        instructions,
        std::slice::from_ref(table),
        *blockhash,
    )
    .map_err(|error| error.to_string())
}

/// Compute budget of a fallback receive: two secp256k1 recoveries plus the
/// unfinalized-message handler exceed the 200k per-instruction default.
pub const RECEIVE_COMPUTE_UNITS: u32 = 400_000;

/// `[SetComputeUnitLimit(400k), receive_message]` as a v0 message over the
/// relay's lookup `table`, signed by the relayer alone (payer and caller)
/// and minting to the existing `ATA(owner)`. With the D2 inbound hook (312
/// bytes) an atomic `[CreateIdempotent, receive_message, ek fee transfer]`
/// is 1,326 bytes and `[receive_message, fee transfer]` 1,284 — above the
/// 1,232-byte packet — so a fallback receive is a bounded relayer subsidy
/// (only the never-closable `used_nonce` rent and one signature) and never
/// creates an account the ek could close for the rent.
pub fn receive_message(
    relayer: &Pubkey,
    owner: &Pubkey,
    message: &[u8],
    attestation: &[u8],
    fee_recipient_token_account: &Pubkey,
    table: &AddressLookupTableAccount,
    blockhash: &Hash,
) -> Result<solana_v0::Message, String> {
    let receive = cctp::receive_message_instruction(
        &cctp::CctpAccounts::new(USDC_MINT),
        relayer,
        relayer,
        message,
        attestation,
        &ata(owner),
        fee_recipient_token_account,
    )
    .map_err(|error| error.to_string())?;
    compile_v0(
        relayer,
        &[
            compute_unit_limit_instruction(RECEIVE_COMPUTE_UNITS),
            receive,
        ],
        table,
        blockhash,
    )
}

/// `[heap, CU limit, CreateIdempotent(ATA(owner))?, exit, fee TransferChecked?]`
/// as a v0 message: `exit` is the vault `execute_close`/`execute_escape`
/// with the relayer as `owner` paying `ATA(owner)`; the ek pays the fee in
/// the same transaction (from the close payout, or prepaid for an escape),
/// so an invalid proof rolls back the ATA creation too.
#[allow(clippy::too_many_arguments)]
pub fn exit_message(
    relayer: &Pubkey,
    owner: &Pubkey,
    create_ata: bool,
    exit: Instruction,
    fee_account: &Pubkey,
    fee: u64,
    table: &AddressLookupTableAccount,
    blockhash: &Hash,
) -> Result<solana_v0::Message, String> {
    let mut instructions = proof_compute_budget_instructions().to_vec();
    if create_ata {
        instructions.push(create_usdc_ata_idempotent_instruction(relayer, owner));
    }
    instructions.push(exit);
    instructions.extend(fee_transfer(owner, fee_account, fee));
    compile_v0(relayer, &instructions, table, blockhash)
}

/// Create the relay's lookup table at `recent_slot` and fill it with
/// `addresses`; returns the message and the table address.
pub fn create_lookup_table_message(
    relayer: &Pubkey,
    recent_slot: u64,
    addresses: &[Pubkey],
    blockhash: &Hash,
) -> (Message, Pubkey) {
    let (create, table) = cctp::create_lookup_table_instruction(relayer, recent_slot);
    let extend = cctp::extend_lookup_table_instruction(&table, relayer, addresses);
    (
        Message::new_with_blockhash(&[create, extend], Some(relayer), blockhash),
        table,
    )
}

/// Append `addresses` to the relay's lookup table.
pub fn extend_lookup_table_message(
    relayer: &Pubkey,
    table: &Pubkey,
    addresses: &[Pubkey],
    blockhash: &Hash,
) -> Message {
    Message::new_with_blockhash(
        &[cctp::extend_lookup_table_instruction(
            table, relayer, addresses,
        )],
        Some(relayer),
        blockhash,
    )
}

/// `reclaim_event_account` returning a `MessageSent` account's rent.
pub fn reclaim_message(
    relayer: &Pubkey,
    event_account: &Pubkey,
    attestation: &[u8],
    destination_message: &[u8],
    blockhash: &Hash,
) -> Message {
    Message::new_with_blockhash(
        &[cctp::reclaim_event_account_instruction(
            &cctp::CctpAccounts::new(USDC_MINT),
            relayer,
            event_account,
            attestation,
            destination_message,
        )],
        Some(relayer),
        blockhash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dagon_zkapi_solana_ledger::CLASSIC_TOKEN_PROGRAM_ID;

    fn vault() -> Pubkey {
        Pubkey::new_from_array(dagon_zkapi_profile::SharedProfile::embedded().program_id())
    }

    fn signer_keys(message: &Message) -> Vec<Pubkey> {
        message.account_keys[..usize::from(message.header.num_required_signatures)].to_vec()
    }

    fn params(hook: Vec<u8>) -> cctp::BurnParams {
        cctp::BurnParams {
            amount: 9_000_000,
            destination_domain: 6,
            mint_recipient: [0x11; 32],
            destination_caller: [0; 32],
            max_fee: 60_000,
            min_finality_threshold: cctp::FINALITY_STANDARD,
            hook_data: hook,
        }
    }

    /// The burn is paid by the relayer, signed by relayer + event keypair,
    /// and needs only the user's ek signature; the relayer is no token
    /// authority, and its signature verifies over the exact message.
    #[test]
    fn burn_shape_and_partial_signatures() {
        let relayer = Keypair::new();
        let ek = Keypair::new();
        let event = Keypair::new();
        let fee_account = Pubkey::new_unique();
        // Includes the largest hook the relay accepts (it must fit a packet).
        for (fee, hook) in [
            (1_234, vec![1, 2, 3]),
            (0, Vec::new()),
            (1_234, vec![7; super::super::service::MAX_HOOK_BYTES]),
        ] {
            let message = burn_message(
                &relayer.pubkey(),
                &ek.pubkey(),
                &event.pubkey(),
                &fee_account,
                fee,
                &params(hook.clone()),
                &Hash::new_unique(),
            );
            let mut signers = signer_keys(&message);
            assert_eq!(signers.remove(0), relayer.pubkey());
            signers.sort();
            let mut expected = vec![ek.pubkey(), event.pubkey()];
            expected.sort();
            assert_eq!(signers, expected);
            assert_eq!(message.instructions.len(), if fee > 0 { 2 } else { 1 });
            if fee > 0 {
                let transfer = &message.instructions[0];
                assert_eq!(
                    message.account_keys[usize::from(transfer.program_id_index)],
                    CLASSIC_TOKEN_PROGRAM_ID
                );
                assert_eq!(&transfer.data[..1], &[12]);
                assert_eq!(&transfer.data[1..9], &fee.to_le_bytes());
                assert_eq!(
                    message.account_keys[usize::from(transfer.accounts[3])],
                    ek.pubkey()
                );
                assert_eq!(
                    message.account_keys[usize::from(transfer.accounts[2])],
                    fee_account
                );
            }
            let signed = sign(&message, &relayer, &[&event], &vault()).unwrap();
            let count = usize::from(signed.bytes[0]);
            assert_eq!(count, 3);
            let message_bytes = &signed.bytes[1 + 64 * count..];
            assert_eq!(message_bytes, message.serialize().as_slice());
            for (index, key) in message.account_keys[..count].iter().enumerate() {
                let slot = &signed.bytes[1 + 64 * index..1 + 64 * (index + 1)];
                if *key == ek.pubkey() {
                    assert_eq!(slot, [0u8; 64]);
                } else {
                    // Ed25519 is deterministic: the slot is the key's
                    // signature over exactly these message bytes.
                    let keypair = [&relayer, &event]
                        .into_iter()
                        .find(|keypair| keypair.pubkey() == *key)
                        .unwrap();
                    assert_eq!(slot, keypair.sign_message(message_bytes).as_ref());
                }
            }
            assert_eq!(
                signed.signature,
                bs58::encode(&signed.bytes[1..65]).into_string()
            );
        }
    }

    #[test]
    fn sweep_receive_reclaim_and_ata_shapes() {
        let relayer = Keypair::new();
        let ek = Keypair::new();
        let blockhash = Hash::new_unique();
        let sweep = sweep_message(
            &relayer.pubkey(),
            &ek.pubkey(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            10,
            990,
            &blockhash,
        );
        assert_eq!(signer_keys(&sweep), vec![relayer.pubkey(), ek.pubkey()]);
        assert_eq!(sweep.instructions.len(), 2);
        sign(&sweep, &relayer, &[], &vault()).unwrap();

        // A forwarded inbound burn with the D2 hook's real size (312 bytes:
        // forward hook with ATA owner + DGNZK-IN intent, as in cctp-vectors).
        let mut body = vec![0u8; 228];
        body[36..68].copy_from_slice(ata(&ek.pubkey()).as_ref());
        body[92..100].copy_from_slice(&5_000_000u64.to_be_bytes());
        body.extend_from_slice(&[0x77; 312]);
        let mut message = vec![0u8; 148];
        message[0..4].copy_from_slice(&1u32.to_be_bytes());
        message[4..8].copy_from_slice(&6u32.to_be_bytes());
        message[8..12].copy_from_slice(&5u32.to_be_bytes());
        message.extend_from_slice(&body);
        let fee_recipient = Pubkey::new_unique();
        let fee_account = Pubkey::new_unique();
        let mut addresses =
            cctp::receive_lookup_addresses(&cctp::CctpAccounts::new(USDC_MINT), &fee_recipient);
        addresses.extend(cctp::receive_domain_addresses(&message).unwrap());
        addresses.push(fee_account);
        let (create_table, table_address) =
            create_lookup_table_message(&relayer.pubkey(), 77, &addresses, &blockhash);
        sign(&create_table, &relayer, &[], &vault()).unwrap();
        sign(
            &extend_lookup_table_message(&relayer.pubkey(), &table_address, &addresses, &blockhash),
            &relayer,
            &[],
            &vault(),
        )
        .unwrap();
        let table = AddressLookupTableAccount {
            key: table_address,
            addresses,
        };
        let receive = receive_message(
            &relayer.pubkey(),
            &ek.pubkey(),
            &message,
            &[0; 130],
            &fee_recipient,
            &table,
            &blockhash,
        )
        .unwrap();
        assert_eq!(
            receive.account_keys[..usize::from(receive.header.num_required_signatures)],
            [relayer.pubkey()]
        );
        // SetComputeUnitLimit(400k), receive_message.
        assert_eq!(receive.instructions.len(), 2);
        assert_eq!(
            receive.instructions[0].data,
            compute_unit_limit_instruction(RECEIVE_COMPUTE_UNITS).data
        );
        let signed = sign_v0(&receive, std::slice::from_ref(&table), &relayer, &vault()).unwrap();
        assert_eq!(signed.bytes.len(), 1_178);
        assert_eq!(signed.bytes[0], 1);
        assert_eq!(signed.bytes[65], 0x80, "versioned message prefix");
        // The atomic variants decided first do not fit one packet with this
        // hook (1,326 and 1,284 bytes), which is why receive is relayer-only.
        let create = create_usdc_ata_idempotent_instruction(&relayer.pubkey(), &ek.pubkey());
        let receive_ix = cctp::receive_message_instruction(
            &cctp::CctpAccounts::new(USDC_MINT),
            &relayer.pubkey(),
            &relayer.pubkey(),
            &message,
            &[0; 130],
            &ata(&ek.pubkey()),
            &fee_recipient,
        )
        .unwrap();
        let fee = fee_transfer(&ek.pubkey(), &fee_account, 1).unwrap();
        for (instructions, size) in [
            (vec![create, receive_ix.clone(), fee.clone()], 1_326),
            (vec![receive_ix, fee], 1_284),
        ] {
            let atomic = compile_v0(&relayer.pubkey(), &instructions, &table, &blockhash).unwrap();
            let signatures = usize::from(atomic.header.num_required_signatures);
            let bytes = 1 + 64 * signatures + VersionedMessage::V0(atomic).serialize().len();
            assert_eq!(bytes, size);
        }
        // Without the table the same receive cannot be sent at all.
        let legacy = Message::new_with_blockhash(
            &[cctp::receive_message_instruction(
                &cctp::CctpAccounts::new(USDC_MINT),
                &relayer.pubkey(),
                &relayer.pubkey(),
                &message,
                &[0; 130],
                &ata(&ek.pubkey()),
                &fee_recipient,
            )
            .unwrap()],
            Some(&relayer.pubkey()),
            &blockhash,
        );
        assert!(sign(&legacy, &relayer, &[], &vault()).is_err());
        // A table that loads the relayer key is refused.
        let mut poisoned = table.clone();
        poisoned.addresses[0] = relayer.pubkey();
        let error = sign_v0(&receive, &[poisoned], &relayer, &vault()).unwrap_err();
        assert!(error.contains("lookup table"), "{error}");

        let reclaim = reclaim_message(
            &relayer.pubkey(),
            &Pubkey::new_unique(),
            &[1; 130],
            &message,
            &blockhash,
        );
        assert_eq!(signer_keys(&reclaim), vec![relayer.pubkey()]);
        sign(&reclaim, &relayer, &[], &vault()).unwrap();
    }

    /// A relayed close is one atomic v0 transaction: ATA creation, the
    /// relayer-owned vault close and the ek's fee transfer, so a bad proof
    /// leaves no relayer-funded account behind. An escape carries no ATA
    /// creation. Both fit one packet with maximal withdrawal inputs.
    #[test]
    fn exits_are_atomic_and_fit_a_packet() {
        use dagon_zkapi_vault as vault_program;
        use vault_program::{accounts, instruction};
        let relayer = Keypair::new();
        let ek = Keypair::new();
        let vault_state = Pubkey::new_unique();
        let vault_token = Pubkey::new_unique();
        let fee_account = Pubkey::new_unique();
        let system = Pubkey::default();
        let felt = [7; 32];
        let payload = vault_program::WithdrawalPayload {
            public_inputs: vault_program::WithdrawalInputs {
                protocol_version: u16::MAX,
                chain_id: u64::MAX,
                contract_address: felt,
                registration: felt,
                state_signing_key_x: felt,
                state_signing_key_y: felt,
                clearance_signing_key_x: felt,
                clearance_signing_key_y: felt,
                note_id: u32::MAX,
                deposit_amount: u128::MAX,
                expiry_ts: u64::MAX,
                final_balance: u128::MAX,
                destination: [9; 20],
                withdrawal_nullifier: felt,
                has_clearance: true,
                next_nullifier: felt,
                conceded: u128::MAX,
                valid_until: u64::MAX,
            },
            proof: vec![3; 256],
        };
        let program = vault();
        let close = Instruction {
            program_id: program,
            accounts: anchor_lang::ToAccountMetas::to_account_metas(
                &accounts::ExecuteClose {
                    vault: vault_state,
                    note: Pubkey::new_unique(),
                    used_nullifier: Pubkey::new_unique(),
                    owner: relayer.pubkey(),
                    destination_token: ata(&ek.pubkey()),
                    vault_token,
                    mint: USDC_MINT,
                    token_program: dagon_zkapi_solana_ledger::CLASSIC_TOKEN_PROGRAM_ID,
                    system_program: system,
                },
                None,
            ),
            data: anchor_lang::InstructionData::data(&instruction::ExecuteClose {
                note_id: u32::MAX,
                payload: payload.clone(),
            }),
        };
        let escape = Instruction {
            program_id: program,
            accounts: anchor_lang::ToAccountMetas::to_account_metas(
                &accounts::ExecuteEscape {
                    vault: vault_state,
                    note: Pubkey::new_unique(),
                    pending: Pubkey::new_unique(),
                    used_nullifier: Pubkey::new_unique(),
                    next_nullifier: Pubkey::new_unique(),
                    owner: relayer.pubkey(),
                    destination: ata(&ek.pubkey()),
                    system_program: system,
                },
                None,
            ),
            data: anchor_lang::InstructionData::data(&instruction::ExecuteEscape {
                note_id: u32::MAX,
                payload,
            }),
        };
        let table = AddressLookupTableAccount {
            key: Pubkey::new_unique(),
            addresses: vec![vault_state, vault_token, USDC_MINT, system, fee_account],
        };
        for (exit, create_ata, instructions) in [(close, true, 5), (escape, false, 4)] {
            let message = exit_message(
                &relayer.pubkey(),
                &ek.pubkey(),
                create_ata,
                exit,
                &fee_account,
                269_293,
                &table,
                &Hash::new_unique(),
            )
            .unwrap();
            assert_eq!(
                message.account_keys[..usize::from(message.header.num_required_signatures)],
                [relayer.pubkey(), ek.pubkey()]
            );
            assert_eq!(message.instructions.len(), instructions);
            let fee = message.instructions.last().unwrap();
            assert_eq!(
                message.account_keys[usize::from(fee.program_id_index)],
                dagon_zkapi_solana_ledger::CLASSIC_TOKEN_PROGRAM_ID
            );
            let signed =
                sign_v0(&message, std::slice::from_ref(&table), &relayer, &program).unwrap();
            assert!(signed.bytes.len() <= 1_232, "{} bytes", signed.bytes.len());
        }
    }

    /// The relayer refuses to sign a message in which it is not the fee
    /// payer, appears as a token authority, or with a foreign signer.
    #[test]
    fn signing_refuses_messages_outside_the_policy() {
        let relayer = Keypair::new();
        let user = Keypair::new();
        let blockhash = Hash::new_unique();
        let user_paid = sweep_message(
            &user.pubkey(),
            &user.pubkey(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            1,
            1,
            &blockhash,
        );
        assert!(sign(&user_paid, &relayer, &[], &vault()).is_err());
        let relayer_tokens = sweep_message(
            &relayer.pubkey(),
            &relayer.pubkey(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            1,
            1,
            &blockhash,
        );
        assert!(sign(&relayer_tokens, &relayer, &[], &vault()).is_err());
        let sweep = sweep_message(
            &relayer.pubkey(),
            &user.pubkey(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            1,
            1,
            &blockhash,
        );
        assert!(sign(&sweep, &relayer, &[&Keypair::new()], &vault()).is_err());
    }
}
