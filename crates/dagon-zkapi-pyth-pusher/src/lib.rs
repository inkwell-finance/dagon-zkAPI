//! Operator Pyth price pusher for the Dagon zkAPI profile.
//!
//! The server pins one SOL/USD account: the Pyth push-oracle PDA
//! `[push_shard_id (u16 LE), feed_id]` of the shared profile. The push oracle
//! lets any payer update that account, so the operator keeps it fresh itself,
//! with Pyth's official mechanism: a signed Hermes update is written to a
//! Wormhole encoded-VAA account, verified against the guardian set
//! (`VerifyEncodedVaaV1`, full verification), and posted by the push oracle
//! through the Pyth receiver, which checks the Merkle proof against the
//! verified root. The pusher is not trusted: it cannot write anything the
//! guardians did not sign, the push oracle only accepts newer updates, and the
//! server independently checks owner, full verification, feed, age and
//! confidence of whatever it reads.
//!
//! This module holds the pure parts: Hermes update decoding, price-account
//! decoding, and the instructions and packets of one push.

use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use dagon_zkapi_profile::{parse_base58_32, SharedProfile};
use pythnet_sdk::{
    messages::Message,
    wire::{
        from_slice,
        v1::{AccumulatorUpdateData, Proof},
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message as SolanaMessage;
use solana_pubkey::Pubkey;

/// Maximum serialized size of a Solana transaction.
pub const PACKET_BYTES: usize = 1232;
/// Seed of the payer's reusable encoded-VAA account (`create_with_seed`):
/// no second signature per push, and a leftover from an interrupted push is
/// found and closed at the same address.
pub const ENCODED_VAA_SEED: &str = "dagon-pyth-vaa";
/// `EncodedVaa` header: discriminator, status, write authority, version, length.
pub const ENCODED_VAA_HEADER: usize = 46;
/// `PriceUpdateV2` account size.
pub const PRICE_UPDATE_LEN: usize = 134;
/// Compute-unit limit of a create/init/write packet. Measured on the cloned
/// mainnet programs: 3,019 CU; the limit bounds the priority fee paid.
pub const WRITE_PACKET_COMPUTE_UNITS: u32 = 20_000;
/// Bound the temporary account and number of paid write packets even for a
/// malicious Hermes response. Current 19-guardian VAAs fit comfortably.
pub const MAX_VAA_BYTES: usize = 4096;
/// Hard per-transaction ceiling, including the base and priority fee.
pub const MAX_TRANSACTION_FEE: u64 = 50_000;

/// Compute-unit limit of the verify/update/close packet. Measured on the
/// cloned mainnet programs: 132,085-135,094 CU for a 3-signature VAA. Each
/// guardian signature costs one 25,000 CU `secp256k1_recover`, so the limit
/// grows with the VAA's signature count (up to the 1.4M transaction maximum).
pub fn post_packet_compute_units(signatures: u8) -> u32 {
    (120_000 + 30_000 * u32::from(signatures)).min(1_400_000)
}

fn anchor_discriminator(namespace: &str, name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("{namespace}:{name}"));
    hash[..8].try_into().expect("8 bytes")
}

/// Every account a push touches, derived from the shared profile.
#[derive(Debug, Clone)]
pub struct PythAccounts {
    pub receiver: Pubkey,
    pub push_oracle: Pubkey,
    pub wormhole: Pubkey,
    pub config: Pubkey,
    pub price_account: Pubkey,
    pub feed_id: [u8; 32],
    pub shard_id: u16,
}

impl PythAccounts {
    pub fn from_profile(profile: &SharedProfile) -> Self {
        let key = |name: &str, value: &str| {
            Pubkey::new_from_array(parse_base58_32(name, value).expect("validated profile"))
        };
        let receiver = key("receiver", &profile.pyth.receiver_program);
        Self {
            receiver,
            push_oracle: key("push oracle", &profile.pyth.push_oracle_program),
            wormhole: key("wormhole", &profile.pyth.wormhole_program),
            config: Pubkey::find_program_address(&[b"config"], &receiver).0,
            price_account: Pubkey::new_from_array(profile.pyth_push_account()),
            feed_id: profile.pyth_feed_id(),
            shard_id: profile.pyth.push_shard_id,
        }
    }

    /// The receiver's fee treasury `treasury_id` (`["treasury", [id]]`).
    pub fn treasury(&self, treasury_id: u8) -> Pubkey {
        Pubkey::find_program_address(&[b"treasury", &[treasury_id]], &self.receiver).0
    }

    /// The Wormhole guardian set a VAA names (`["GuardianSet", index BE]`).
    pub fn guardian_set(&self, index: u32) -> Pubkey {
        Pubkey::find_program_address(&[b"GuardianSet", &index.to_be_bytes()], &self.wormhole).0
    }

    pub fn encoded_vaa(&self, payer: &Pubkey) -> Pubkey {
        Pubkey::create_with_seed(payer, ENCODED_VAA_SEED, &self.wormhole).expect("valid seed")
    }
}

/// One guardian-signed SOL/USD update, as Hermes serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedUpdate {
    pub vaa: Vec<u8>,
    pub message: Vec<u8>,
    pub proof: Vec<[u8; 20]>,
    pub publish_time: i64,
    pub price: i64,
    pub confidence: u64,
    pub exponent: i32,
}

impl SignedUpdate {
    /// The guardian set index in the VAA header (version, index BE, signatures).
    pub fn guardian_set_index(&self) -> u32 {
        u32::from_be_bytes(self.vaa[1..5].try_into().expect("checked length"))
    }
}

/// The binary update of a Hermes `/v2/updates/price/latest` response body.
pub fn hermes_binary(body: &Value) -> Result<Vec<u8>> {
    let binary = &body["binary"];
    let data = binary["data"]
        .as_array()
        .filter(|data| data.len() == 1)
        .and_then(|data| data[0].as_str())
        .context("Hermes response must carry exactly one binary update")?;
    match binary["encoding"].as_str() {
        Some("base64") => Ok(base64::engine::general_purpose::STANDARD.decode(data)?),
        Some("hex") => {
            ensure!(data.is_ascii() && data.len() % 2 == 0, "invalid hex update");
            (0..data.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&data[i..i + 2], 16).context("invalid hex update"))
                .collect()
        }
        other => bail!("unsupported Hermes encoding {other:?}"),
    }
}

/// Decode a PNAU accumulator update and select the profile feed's price message.
pub fn parse_update(binary: &[u8], feed_id: &[u8; 32]) -> Result<SignedUpdate> {
    let update = AccumulatorUpdateData::try_from_slice(binary)
        .map_err(|e| anyhow::anyhow!("invalid Pyth accumulator update: {e:?}"))?;
    let Proof::WormholeMerkle { vaa, updates } = update.proof;
    let vaa: Vec<u8> = vaa.into();
    ensure!(
        vaa.len() >= 6
            && vaa.len() <= MAX_VAA_BYTES
            && vaa[0] == 1
            && vaa.len() >= 6 + 66 * usize::from(vaa[5]),
        "malformed VAA"
    );
    for update in updates {
        let message: Vec<u8> = update.message.into();
        let decoded = from_slice::<byteorder::BE, Message>(&message)
            .map_err(|e| anyhow::anyhow!("invalid Pyth message: {e:?}"))?;
        if let Message::PriceFeedMessage(price) = decoded {
            if &price.feed_id == feed_id {
                return Ok(SignedUpdate {
                    vaa,
                    message,
                    proof: update.proof.to_vec(),
                    publish_time: price.publish_time,
                    price: price.price,
                    confidence: price.conf,
                    exponent: price.exponent,
                });
            }
        }
    }
    bail!("Hermes update does not carry the profile's feed")
}

/// The security and freshness fields of a `PriceUpdateV2` account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnChainPrice {
    pub publish_time: i64,
    pub posted_slot: u64,
}

pub fn decode_price_account(data: &[u8], feed_id: &[u8; 32]) -> Result<OnChainPrice> {
    ensure!(
        data.len() == PRICE_UPDATE_LEN
            && data[..8] == anchor_discriminator("account", "PriceUpdateV2"),
        "not a PriceUpdateV2 account"
    );
    ensure!(data[40] == 1, "price account is not fully verified");
    ensure!(
        &data[41..73] == feed_id,
        "price account carries another feed"
    );
    Ok(OnChainPrice {
        publish_time: i64::from_le_bytes(data[93..101].try_into()?),
        posted_slot: u64::from_le_bytes(data[125..133].try_into()?),
    })
}

pub fn init_encoded_vaa(wormhole: &Pubkey, payer: &Pubkey, encoded: &Pubkey) -> Instruction {
    Instruction {
        program_id: *wormhole,
        accounts: vec![
            AccountMeta::new_readonly(*payer, true),
            AccountMeta::new(*encoded, false),
        ],
        data: anchor_discriminator("global", "init_encoded_vaa").to_vec(),
    }
}

pub fn write_encoded_vaa(
    wormhole: &Pubkey,
    payer: &Pubkey,
    encoded: &Pubkey,
    index: u32,
    chunk: &[u8],
) -> Instruction {
    let mut data = anchor_discriminator("global", "write_encoded_vaa").to_vec();
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    data.extend_from_slice(chunk);
    Instruction {
        program_id: *wormhole,
        accounts: vec![
            AccountMeta::new_readonly(*payer, true),
            AccountMeta::new(*encoded, false),
        ],
        data,
    }
}

pub fn verify_encoded_vaa(
    wormhole: &Pubkey,
    payer: &Pubkey,
    encoded: &Pubkey,
    guardian_set: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: *wormhole,
        accounts: vec![
            AccountMeta::new_readonly(*payer, true),
            AccountMeta::new(*encoded, false),
            AccountMeta::new_readonly(*guardian_set, false),
        ],
        data: anchor_discriminator("global", "verify_encoded_vaa_v1").to_vec(),
    }
}

pub fn close_encoded_vaa(wormhole: &Pubkey, payer: &Pubkey, encoded: &Pubkey) -> Instruction {
    Instruction {
        program_id: *wormhole,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*encoded, false),
        ],
        data: anchor_discriminator("global", "close_encoded_vaa").to_vec(),
    }
}

/// Push-oracle `update_price_feed(PostUpdateParams, shard_id, feed_id)` (Borsh).
pub fn update_price_feed(
    accounts: &PythAccounts,
    payer: &Pubkey,
    encoded: &Pubkey,
    update: &SignedUpdate,
    treasury_id: u8,
) -> Instruction {
    let mut data = anchor_discriminator("global", "update_price_feed").to_vec();
    data.extend_from_slice(&(update.message.len() as u32).to_le_bytes());
    data.extend_from_slice(&update.message);
    data.extend_from_slice(&(update.proof.len() as u32).to_le_bytes());
    for hash in &update.proof {
        data.extend_from_slice(hash);
    }
    data.push(treasury_id);
    data.extend_from_slice(&accounts.shard_id.to_le_bytes());
    data.extend_from_slice(&accounts.feed_id);
    Instruction {
        program_id: accounts.push_oracle,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(accounts.receiver, false),
            AccountMeta::new_readonly(*encoded, false),
            AccountMeta::new_readonly(accounts.config, false),
            AccountMeta::new(accounts.treasury(treasury_id), false),
            AccountMeta::new(accounts.price_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data,
    }
}

/// Serialized size of a single-signer legacy transaction.
pub fn packet_size(instructions: &[Instruction], payer: &Pubkey) -> usize {
    let message = SolanaMessage::new(instructions, Some(payer));
    1 + 64 * usize::from(message.header.num_required_signatures) + message.serialize().len()
}

fn budget(units: u32, micro_lamports: u64) -> [Instruction; 2] {
    [
        ComputeBudgetInstruction::set_compute_unit_limit(units),
        ComputeBudgetInstruction::set_compute_unit_price(micro_lamports),
    ]
}

/// The packets of one push, in order, each signed by the payer only:
/// create + init + write, (more writes,) then verify + update + close. Every
/// packet fits the Solana packet limit; state carries over between them.
pub fn push_packets(
    accounts: &PythAccounts,
    payer: &Pubkey,
    update: &SignedUpdate,
    treasury_id: u8,
    encoded_rent_lamports: u64,
    priority_micro_lamports: u64,
) -> Result<Vec<Vec<Instruction>>> {
    let wormhole = &accounts.wormhole;
    let encoded = accounts.encoded_vaa(payer);
    let vaa = &update.vaa;
    let write_budget = || budget(WRITE_PACKET_COMPUTE_UNITS, priority_micro_lamports);
    let with = |head: &[Instruction], tail: &[Instruction]| [head, tail].concat();
    // Capacity of a packet for one write chunk; 2 bytes of slack for the
    // compact-u16 instruction-data length growing past 127.
    let capacity = |fixed: &[Instruction], at_end: bool, index: u32| {
        let empty = write_encoded_vaa(wormhole, payer, &encoded, index, &[]);
        let probe = if at_end {
            with(&[empty], fixed)
        } else {
            with(fixed, &[empty])
        };
        PACKET_BYTES.saturating_sub(packet_size(&probe, payer) + 2)
    };
    let first: Vec<Instruction> = [
        write_budget().to_vec(),
        vec![
            solana_system_interface::instruction::create_account_with_seed(
                payer,
                &encoded,
                payer,
                ENCODED_VAA_SEED,
                encoded_rent_lamports,
                (ENCODED_VAA_HEADER + vaa.len()) as u64,
                wormhole,
            ),
            init_encoded_vaa(wormhole, payer, &encoded),
        ],
    ]
    .concat();
    let post = [
        verify_encoded_vaa(
            wormhole,
            payer,
            &encoded,
            &accounts.guardian_set(update.guardian_set_index()),
        ),
        update_price_feed(accounts, payer, &encoded, update, treasury_id),
        close_encoded_vaa(wormhole, payer, &encoded),
    ];
    let post_budget = budget(
        post_packet_compute_units(update.vaa[5]),
        priority_micro_lamports,
    );

    let mut packets = Vec::new();
    let take = capacity(&first, false, 0).min(vaa.len());
    ensure!(take > 0, "no room for the VAA in the first packet");
    packets.push(with(
        &first,
        &[write_encoded_vaa(
            wormhole,
            payer,
            &encoded,
            0,
            &vaa[..take],
        )],
    ));
    let mut offset = take;
    loop {
        let index = offset as u32;
        let last_fixed = with(&post_budget, &post);
        let rest = &vaa[offset..];
        if rest.is_empty() {
            packets.push(last_fixed);
            break;
        }
        if rest.len() <= capacity(&last_fixed, true, index) {
            let write = write_encoded_vaa(wormhole, payer, &encoded, index, rest);
            packets.push(with(&post_budget, &with(&[write], &post)));
            break;
        }
        let take = capacity(&write_budget(), false, index).min(rest.len());
        packets.push(with(
            &write_budget(),
            &[write_encoded_vaa(
                wormhole,
                payer,
                &encoded,
                index,
                &rest[..take],
            )],
        ));
        offset += take;
    }
    for packet in &packets {
        ensure!(
            packet_size(packet, payer) <= PACKET_BYTES,
            "push packet exceeds the Solana packet limit"
        );
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/mainnet-sol-usd-update.json"
        ))
        .unwrap()
    }

    fn recorded() -> (PythAccounts, SignedUpdate, Value) {
        let profile = SharedProfile::embedded();
        let accounts = PythAccounts::from_profile(profile);
        let fixture = fixture();
        let binary = hermes_binary(&fixture["hermes_response"]).unwrap();
        let update = parse_update(&binary, &accounts.feed_id).unwrap();
        (accounts, update, fixture)
    }

    fn b64(value: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value.as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn recorded_hermes_update_decodes_to_the_profile_feed() {
        let (accounts, update, fixture) = recorded();
        assert_eq!(
            update.publish_time,
            fixture["publish_time"].as_i64().unwrap()
        );
        assert_eq!(&update.message[1..33], &accounts.feed_id);
        assert!(update.price > 0 && update.exponent < 0);
        let mut other = accounts.feed_id;
        other[0] ^= 1;
        let binary = hermes_binary(&fixture["hermes_response"]).unwrap();
        assert!(parse_update(&binary, &other).is_err());
        let mut corrupt = binary.clone();
        corrupt[0] = b'X';
        assert!(parse_update(&corrupt, &accounts.feed_id).is_err());
    }

    #[test]
    fn profile_accounts_are_the_pinned_mainnet_accounts() {
        let accounts = PythAccounts::from_profile(SharedProfile::embedded());
        assert_eq!(
            accounts.price_account.to_string(),
            "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE"
        );
        let (_, update, fixture) = recorded();
        let instructions = fixture["mainnet_instructions"].as_array().unwrap();
        let verify = instructions
            .iter()
            .find(|i| {
                b64(&i["data"])[..8] == anchor_discriminator("global", "verify_encoded_vaa_v1")
            })
            .unwrap();
        assert_eq!(
            verify["accounts"][2],
            accounts
                .guardian_set(update.guardian_set_index())
                .to_string()
        );
        let update_ix = instructions
            .iter()
            .find(|i| i["accounts"][5] == accounts.price_account.to_string())
            .unwrap();
        assert_eq!(update_ix["accounts"][3], accounts.config.to_string());
        let data = b64(&update_ix["data"]);
        let treasury_id = data[data.len() - 35];
        assert_eq!(
            update_ix["accounts"][4],
            accounts.treasury(treasury_id).to_string()
        );
    }

    #[test]
    fn instructions_match_the_mainnet_push_byte_for_byte() {
        let (accounts, update, fixture) = recorded();
        let payer = Pubkey::new_unique();
        let encoded = accounts.encoded_vaa(&payer);
        let instructions = fixture["mainnet_instructions"].as_array().unwrap();
        let mainnet = |program: &Pubkey, discriminator: [u8; 8]| -> Vec<Vec<u8>> {
            instructions
                .iter()
                .filter(|i| i["program"] == program.to_string())
                .map(|i| b64(&i["data"]))
                .filter(|data| data[..8] == discriminator)
                .collect()
        };
        let updates: Vec<Vec<u8>> = mainnet(
            &accounts.push_oracle,
            anchor_discriminator("global", "update_price_feed"),
        )
        .into_iter()
        .filter(|data| data[data.len() - 32..] == accounts.feed_id)
        .collect();
        assert_eq!(updates.len(), 1);
        let treasury_id = updates[0][updates[0].len() - 35];
        let ours = update_price_feed(&accounts, &payer, &encoded, &update, treasury_id);
        assert_eq!(ours.data, updates[0], "UpdatePriceFeed data");
        // The VAA written by mainnet is exactly the VAA the recorded update carries.
        let mut written = Vec::new();
        for data in mainnet(
            &accounts.wormhole,
            anchor_discriminator("global", "write_encoded_vaa"),
        ) {
            let index = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
            let chunk = &data[16..];
            written.resize(written.len().max(index + chunk.len()), 0);
            written[index..index + chunk.len()].copy_from_slice(chunk);
            let ours = write_encoded_vaa(&accounts.wormhole, &payer, &encoded, index as u32, chunk);
            assert_eq!(ours.data, data);
        }
        assert_eq!(written, update.vaa);
        for name in [
            "init_encoded_vaa",
            "verify_encoded_vaa_v1",
            "close_encoded_vaa",
        ] {
            assert_eq!(
                mainnet(&accounts.wormhole, anchor_discriminator("global", name)).len(),
                1,
                "{name}"
            );
        }
    }

    #[test]
    fn packets_fit_and_write_the_whole_vaa_before_verification() {
        let (accounts, mut update, _) = recorded();
        let payer = Pubkey::new_unique();
        // Also a VAA with every signature of a 19-guardian set.
        for extra in [0usize, 16 * 66] {
            let mut vaa = update.vaa.clone();
            vaa.splice(6..6, std::iter::repeat_n(0u8, extra));
            update.vaa = vaa;
            let packets = push_packets(&accounts, &payer, &update, 7, 1, 10_000).unwrap();
            let mut written = vec![0u8; update.vaa.len()];
            let mut covered = 0;
            let mut verified = false;
            for packet in &packets {
                assert!(packet_size(packet, &payer) <= PACKET_BYTES);
                let signers = SolanaMessage::new(packet, Some(&payer))
                    .header
                    .num_required_signatures;
                assert_eq!(signers, 1, "the payer is the only signer");
                for ix in packet {
                    if ix.program_id != accounts.wormhole {
                        continue;
                    }
                    if ix.data[..8] == anchor_discriminator("global", "write_encoded_vaa") {
                        assert!(!verified);
                        let index = u32::from_le_bytes(ix.data[8..12].try_into().unwrap()) as usize;
                        written[index..index + ix.data.len() - 16].copy_from_slice(&ix.data[16..]);
                        covered += ix.data.len() - 16;
                    }
                    if ix.data[..8] == anchor_discriminator("global", "verify_encoded_vaa_v1") {
                        verified = true;
                    }
                }
            }
            assert!(verified);
            assert_eq!(covered, update.vaa.len());
            assert_eq!(written, update.vaa);
        }
    }

    #[test]
    fn price_account_decoding_requires_full_verification_and_the_feed() {
        let feed = [7u8; 32];
        let mut data = vec![0u8; PRICE_UPDATE_LEN];
        data[..8].copy_from_slice(&anchor_discriminator("account", "PriceUpdateV2"));
        data[40] = 1;
        data[41..73].copy_from_slice(&feed);
        data[93..101].copy_from_slice(&1_793_978_746i64.to_le_bytes());
        data[125..133].copy_from_slice(&42u64.to_le_bytes());
        assert_eq!(
            decode_price_account(&data, &feed).unwrap(),
            OnChainPrice {
                publish_time: 1_793_978_746,
                posted_slot: 42
            }
        );
        assert!(decode_price_account(&data, &[8; 32]).is_err());
        data[40] = 0;
        assert!(decode_price_account(&data, &feed).is_err());
        assert!(decode_price_account(&data[..100], &feed).is_err());
    }

    #[test]
    fn hermes_hex_and_base64_bodies_are_equivalent() {
        let (_, _, fixture) = recorded();
        let binary = hermes_binary(&fixture["hermes_response"]).unwrap();
        let hex: String = binary.iter().map(|b| format!("{b:02x}")).collect();
        let body = serde_json::json!({"binary": {"encoding": "hex", "data": [hex]}});
        assert_eq!(hermes_binary(&body).unwrap(), binary);
        assert!(
            hermes_binary(&serde_json::json!({"binary": {"encoding": "hex", "data": []}})).is_err()
        );
        assert!(hermes_binary(&serde_json::json!({
            "binary": {"encoding": "hex", "data": ["a€"]}
        }))
        .is_err());
    }
}
