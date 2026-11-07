//! The Dagon zkAPI Solana deployment profile.
//!
//! `solana/profile/shared.json` is the single source of truth for every
//! protocol, economic, asset and program-build parameter. It is compiled into
//! every operator binary, so no deployment can change it at runtime and a local
//! validator stack runs exactly the parameters mainnet runs.
//!
//! A network differs from another only through its identity file
//! (`solana/profile/<network>.identity.json`, or one generated for a local
//! validator). The identity schema admits exactly the network-identity keys, and
//! [`parity_violations`] rejects every difference between two effective
//! profiles outside [`IDENTITY_KEYS`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use solana_pubkey::Pubkey;

/// The shared profile, embedded at build time.
pub const SHARED_PROFILE_JSON: &str = include_str!("../../../solana/profile/shared.json");
/// The checked-in mainnet-beta identity.
pub const MAINNET_IDENTITY_JSON: &str =
    include_str!("../../../solana/profile/mainnet-beta.identity.json");

pub const PROFILE_SCHEMA: &str = "dagon-zkapi.solana-profile.v1";
pub const IDENTITY_SCHEMA: &str = "dagon-zkapi.solana-identity.v1";
pub const MAINNET_BETA: &str = "mainnet-beta";
pub const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
pub const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
/// Seed prefix of the vault-state PDA: `["vault", authority]`.
pub const VAULT_SEED: &[u8] = b"vault";
/// Seed prefix of the vault's USDC token account PDA: `["vault-token", vault_state]`.
pub const VAULT_TOKEN_SEED: &[u8] = b"vault-token";
/// The only asset: Circle USDC on Solana, under the classic SPL Token program.
pub const USDC_SYMBOL: &str = "USDC";
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// One base unit is one micro-USDC, which the protocol bills as one micro-USD.
pub const USDC_DECIMALS: u8 = 6;
/// Classic SPL Token. Token-2022 is rejected everywhere.
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// The only keys that may differ between two deployments of the profile.
///
/// `network`, `rpc_url` and `genesis_hash` name the cluster; `chain_id` and
/// `deployment_binding` are derived from the genesis hash, program and vault.
/// The vault authority, vault PDA and treasury token account are
/// per-deployment accounts, and the signing keys are derived from
/// per-deployment secret seeds.
pub const IDENTITY_KEYS: &[&str] = &[
    "network",
    "rpc_url",
    "genesis_hash",
    "chain_id",
    "deployment_binding",
    "vault_authority",
    "vault_state",
    "treasury_token_account",
    "state_signing_key",
    "clearance_signing_key",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedProfile {
    pub schema: String,
    pub protocol: ProtocolProfile,
    pub program: ProgramProfile,
    pub asset: AssetProfile,
    pub vault: VaultProfile,
    pub server: ServerProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolProfile {
    pub protocol_version: u16,
    pub circuit_id: String,
    pub transition_circuit_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramProfile {
    /// The ID declared in the program (`declare_id!`); part of the binary.
    pub program_id: String,
    pub loader: String,
    /// Always `null`: the program is immutable on every network.
    pub upgrade_authority: Option<String>,
    /// `solana-verify` executable hash: sha256 of the `.so` (or of the
    /// program-data bytes) with trailing zero bytes removed.
    pub executable_sha256: String,
}

/// The vault's only asset. Validation pins exactly Circle USDC (6 decimals)
/// under the classic SPL Token program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetProfile {
    pub symbol: String,
    pub mint: String,
    pub decimals: u8,
    pub token_program: String,
    pub associated_token_program: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultProfile {
    pub version: u8,
    /// Smallest lease, in USDC base units (micro-USD).
    pub request_charge_cap: u64,
    pub note_ttl_seconds: u64,
    pub challenge_period_seconds: u64,
    /// Compiled into the program (`MAX_PAUSE_DURATION`).
    pub max_pause_seconds: u64,
    /// Compiled into the program (`PAUSE_COOLDOWN`).
    pub pause_cooldown_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerProfile {
    pub lease_ttl_seconds: u64,
    pub settlement_grace_seconds: u64,
    pub settlement_poll_seconds: u64,
    pub raise_lead_seconds: u64,
}

/// Decode a canonical, nonzero base58 32-byte Solana identity.
pub fn parse_base58_32(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes: [u8; 32] = bs58::decode(value)
        .into_vec()
        .with_context(|| format!("{name} is not base58"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to 32 bytes"))?;
    ensure!(
        bytes != [0; 32] && bs58::encode(bytes).into_string() == value,
        "{name} must be a nonzero canonical base58 identity"
    );
    Ok(bytes)
}

fn parse_hex_32(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{name} must be 64 lowercase hex digits"
    );
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).expect("validated hex");
    }
    Ok(out)
}

impl SharedProfile {
    /// The profile compiled into this binary. Its validity is a unit test.
    pub fn embedded() -> &'static SharedProfile {
        static PROFILE: LazyLock<SharedProfile> = LazyLock::new(|| {
            SharedProfile::parse(SHARED_PROFILE_JSON).expect("embedded Solana profile is valid")
        });
        &PROFILE
    }

    pub fn parse(json: &str) -> anyhow::Result<Self> {
        let profile: SharedProfile =
            serde_json::from_str(json).context("invalid Solana shared profile")?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.schema == PROFILE_SCHEMA,
            "unsupported profile schema {}",
            self.schema
        );
        ensure!(
            self.protocol.protocol_version == 2,
            "unsupported protocol version"
        );
        ensure!(
            !self.protocol.circuit_id.is_empty(),
            "circuit ID is required"
        );
        ensure!(
            !self.protocol.transition_circuit_id.is_empty(),
            "transition circuit ID is required"
        );
        parse_base58_32("program ID", &self.program.program_id)?;
        ensure!(
            self.program.loader == UPGRADEABLE_LOADER,
            "program must use the upgradeable loader"
        );
        ensure!(
            self.program.upgrade_authority.is_none(),
            "the program upgrade authority must be revoked (null)"
        );
        parse_hex_32("program executable sha256", &self.program.executable_sha256)?;
        let asset = &self.asset;
        ensure!(
            asset.symbol == USDC_SYMBOL
                && asset.mint == USDC_MINT
                && asset.decimals == USDC_DECIMALS
                && asset.token_program == TOKEN_PROGRAM
                && asset.associated_token_program == ASSOCIATED_TOKEN_PROGRAM,
            "the asset must be Circle USDC (6 decimals) under the classic SPL Token program"
        );
        let vault = &self.vault;
        ensure!(vault.version > 0, "vault version is required");
        ensure!(
            vault.request_charge_cap > 0,
            "request charge cap must be positive"
        );
        ensure!(vault.note_ttl_seconds > 0, "note TTL must be positive");
        ensure!(
            vault.challenge_period_seconds > 0,
            "challenge period must be positive"
        );
        ensure!(
            vault.max_pause_seconds > 0 && vault.pause_cooldown_seconds > 0,
            "pause bounds must be positive"
        );
        let server = &self.server;
        ensure!(server.lease_ttl_seconds > 0, "lease TTL must be positive");
        ensure!(
            server.settlement_poll_seconds > 0,
            "settlement poll must be positive"
        );
        ensure!(server.raise_lead_seconds > 0, "raise lead must be positive");
        Ok(())
    }

    pub fn program_id(&self) -> [u8; 32] {
        parse_base58_32("program ID", &self.program.program_id).expect("validated")
    }

    pub fn executable_sha256(&self) -> [u8; 32] {
        parse_hex_32("program executable sha256", &self.program.executable_sha256)
            .expect("validated")
    }

    pub fn usdc_mint(&self) -> [u8; 32] {
        parse_base58_32("USDC mint", &self.asset.mint).expect("validated")
    }

    pub fn token_program(&self) -> [u8; 32] {
        parse_base58_32("token program", &self.asset.token_program).expect("validated")
    }

    pub fn associated_token_program(&self) -> [u8; 32] {
        parse_base58_32(
            "associated token program",
            &self.asset.associated_token_program,
        )
        .expect("validated")
    }

    /// The profile as compared by [`parity_violations`] (without its schema tag).
    pub fn to_value(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("profile serializes");
        value.as_object_mut().expect("object").remove("schema");
        value
    }
}

/// The `solana-verify` executable hash: sha256 over the program bytes with
/// trailing zero bytes removed. Applies equally to a built `.so` and to the
/// program-data bytes after the upgradeable-loader metadata, so a deployed
/// program can be compared with a local build.
pub fn executable_sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    Sha256::digest(&bytes[..end]).into()
}

/// Lowercase hex, the profile's encoding of hashes.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The vault-state PDA of `authority` under the profile's program.
pub fn vault_state_address(program_id: &[u8; 32], authority: &[u8; 32]) -> [u8; 32] {
    Pubkey::find_program_address(
        &[VAULT_SEED, authority],
        &Pubkey::new_from_array(*program_id),
    )
    .0
    .to_bytes()
}

/// The vault's USDC token account: PDA `["vault-token", vault_state]` of the
/// program, created by `initialize` with the vault state as token authority.
pub fn vault_token_address(program_id: &[u8; 32], vault_state: &[u8; 32]) -> [u8; 32] {
    Pubkey::find_program_address(
        &[VAULT_TOKEN_SEED, vault_state],
        &Pubkey::new_from_array(*program_id),
    )
    .0
    .to_bytes()
}

/// The canonical USDC associated token account of `owner`:
/// PDA `[owner, token_program, mint]` of the associated token program.
pub fn usdc_associated_token_address(owner: &[u8; 32]) -> [u8; 32] {
    let profile = SharedProfile::embedded();
    Pubkey::find_program_address(
        &[owner, &profile.token_program(), &profile.usdc_mint()],
        &Pubkey::new_from_array(profile.associated_token_program()),
    )
    .0
    .to_bytes()
}

/// A network identity file. Undeployed accounts are `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    pub schema: String,
    pub network: String,
    pub genesis_hash: String,
    pub vault_authority: Option<String>,
    pub vault_state: Option<String>,
    /// The classic-Token USDC account (any owner) that receives treasury
    /// withdrawals, pinned in the vault at initialization.
    pub treasury_token_account: Option<String>,
}

/// A complete identity ready for operator use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedIdentity {
    pub genesis_hash: [u8; 32],
    pub vault_authority: [u8; 32],
    pub vault_state: [u8; 32],
    pub treasury_token_account: [u8; 32],
}

impl NetworkIdentity {
    pub fn parse(json: &str) -> anyhow::Result<Self> {
        let identity: NetworkIdentity =
            serde_json::from_str(json).context("invalid Solana network identity")?;
        ensure!(
            identity.schema == IDENTITY_SCHEMA,
            "unsupported identity schema {}",
            identity.schema
        );
        ensure!(
            !identity.network.is_empty()
                && identity
                    .network
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "network label must be lowercase [a-z0-9-]"
        );
        parse_base58_32("genesis hash", &identity.genesis_hash)?;
        ensure!(
            (identity.network == MAINNET_BETA) == (identity.genesis_hash == MAINNET_GENESIS_HASH),
            "the mainnet-beta label and the mainnet genesis hash must go together"
        );
        Ok(identity)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("reading Solana identity {}", path.display()))?;
        Self::parse(&json).with_context(|| format!("in {}", path.display()))
    }

    pub fn mainnet() -> Self {
        Self::parse(MAINNET_IDENTITY_JSON).expect("checked-in mainnet identity is valid")
    }

    /// Require every account; check the vault PDA against the profile's
    /// program and that the treasury is neither the vault nor its token account.
    pub fn resolve(&self, shared: &SharedProfile) -> anyhow::Result<ResolvedIdentity> {
        let required = |name: &str, value: &Option<String>| -> anyhow::Result<[u8; 32]> {
            let value = value.as_deref().ok_or_else(|| {
                anyhow::anyhow!("{} identity has no {name} (undeployed)", self.network)
            })?;
            parse_base58_32(name, value)
        };
        let resolved = ResolvedIdentity {
            genesis_hash: parse_base58_32("genesis hash", &self.genesis_hash)?,
            vault_authority: required("vault_authority", &self.vault_authority)?,
            vault_state: required("vault_state", &self.vault_state)?,
            treasury_token_account: required(
                "treasury_token_account",
                &self.treasury_token_account,
            )?,
        };
        ensure!(
            resolved.vault_state
                == vault_state_address(&shared.program_id(), &resolved.vault_authority),
            "vault_state is not the vault PDA of vault_authority under the profile program"
        );
        ensure!(
            resolved.treasury_token_account != resolved.vault_state
                && resolved.treasury_token_account
                    != vault_token_address(&shared.program_id(), &resolved.vault_state),
            "treasury_token_account must not be the vault or its token account"
        );
        Ok(resolved)
    }
}

/// Build an effective profile: the shared profile, a network identity, and
/// optional facts observed on chain (program bytes, vault fields, asset accounts).
pub fn effective_profile(
    shared: &SharedProfile,
    identity: Map<String, Value>,
    observed: Map<String, Value>,
) -> Value {
    serde_json::json!({
        "profile": shared.to_value(),
        "identity": Value::Object(identity),
        "observed": Value::Object(observed),
    })
}

fn flatten(prefix: Vec<String>, value: &Value, out: &mut BTreeMap<Vec<String>, Value>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                let mut path = prefix.clone();
                path.push(key.clone());
                flatten(path, child, out);
            }
        }
        other => {
            out.insert(prefix, other.clone());
        }
    }
}

fn is_identity_path(path: &[String]) -> bool {
    path.len() == 2 && path[0] == "identity" && IDENTITY_KEYS.contains(&path[1].as_str())
}

/// Every difference between two effective profiles outside [`IDENTITY_KEYS`].
///
/// Each leaf of `profile.*` and `observed.*` must be present in both and
/// equal. Leaves under `identity.*` may differ only when their top-level key
/// is an identity key; an unknown identity key is itself a violation.
pub fn parity_violations(local: &Value, reference: &Value) -> Vec<String> {
    let (mut left, mut right) = (BTreeMap::new(), BTreeMap::new());
    flatten(Vec::new(), local, &mut left);
    flatten(Vec::new(), reference, &mut right);
    let mut violations = Vec::new();
    for key in left
        .keys()
        .chain(right.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if key.first().is_some_and(|part| part == "identity") && !is_identity_path(key) {
            violations.push(format!("{}: not an allowed identity key", key.join(".")));
            continue;
        }
        let (a, b) = (left.get(key), right.get(key));
        if a == b || is_identity_path(key) {
            continue;
        }
        let show = |v: Option<&Value>| v.map_or("<missing>".to_string(), Value::to_string);
        violations.push(format!(
            "{}: local {} != reference {}",
            key.join("."),
            show(a),
            show(b)
        ));
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn embedded_profile_is_valid() {
        let profile = SharedProfile::embedded();
        assert_eq!(profile.protocol.circuit_id, "zkapi-v2-concession-v1");
        assert!(profile.program.upgrade_authority.is_none());
    }

    #[test]
    fn profile_matches_the_constants_compiled_into_the_program() {
        let profile = SharedProfile::embedded();
        assert_eq!(profile.program_id(), dagon_zkapi_vault::ID.to_bytes());
        assert_eq!(
            profile.usdc_mint(),
            dagon_zkapi_vault::token::USDC_MINT.to_bytes()
        );
        assert_eq!(
            profile.token_program(),
            dagon_zkapi_vault::token::TOKEN_PROGRAM_ID.to_bytes()
        );
        assert_ne!(
            profile.token_program(),
            dagon_zkapi_vault::token::TOKEN_2022_PROGRAM_ID.to_bytes()
        );
        assert_eq!(
            profile.asset.decimals,
            dagon_zkapi_vault::token::USDC_DECIMALS
        );
        assert_eq!(VAULT_TOKEN_SEED, dagon_zkapi_vault::VAULT_TOKEN_SEED);
        assert_eq!(profile.vault.version, dagon_zkapi_vault::VAULT_VERSION);
        assert_eq!(
            profile.vault.max_pause_seconds,
            dagon_zkapi_vault::MAX_PAUSE_DURATION
        );
        assert_eq!(
            profile.vault.pause_cooldown_seconds,
            dagon_zkapi_vault::PAUSE_COOLDOWN
        );
    }

    #[test]
    fn profile_rejects_unknown_fields_and_upgradeable_programs() {
        let mut value: Value = serde_json::from_str(SHARED_PROFILE_JSON).unwrap();
        value["vault"]["test_override"] = json!(1);
        assert!(SharedProfile::parse(&value.to_string()).is_err());
        let mut value: Value = serde_json::from_str(SHARED_PROFILE_JSON).unwrap();
        value["program"]["upgrade_authority"] =
            json!("7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H");
        assert!(SharedProfile::parse(&value.to_string()).is_err());
    }

    #[test]
    fn request_charge_cap_is_exactly_one_dollar_of_usdc() {
        let profile = SharedProfile::embedded();
        assert_eq!(profile.vault.request_charge_cap, 1_000_000);
        assert_eq!(
            profile.vault.request_charge_cap,
            10u64.pow(u32::from(profile.asset.decimals)),
            "1_000_000 base units at 6 decimals is exactly $1.00"
        );
    }

    #[test]
    fn asset_is_pinned_to_classic_usdc() {
        for (field, value) in [
            ("symbol", json!("USDT")),
            (
                "mint",
                json!("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
            ),
            ("decimals", json!(9)),
            (
                "token_program",
                json!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
            ),
            (
                "associated_token_program",
                json!("11111111111111111111111111111111"),
            ),
        ] {
            let mut value_json: Value = serde_json::from_str(SHARED_PROFILE_JSON).unwrap();
            value_json["asset"][field] = value;
            assert!(
                SharedProfile::parse(&value_json.to_string()).is_err(),
                "{field}"
            );
        }
        let mut value: Value = serde_json::from_str(SHARED_PROFILE_JSON).unwrap();
        value.as_object_mut().unwrap().remove("asset");
        assert!(SharedProfile::parse(&value.to_string()).is_err());
    }

    #[test]
    fn token_addresses_are_the_canonical_pdas() {
        // ATA seeds are `[owner, token program, mint]` under the ATA program.
        let owner = [5u8; 32];
        let profile = SharedProfile::embedded();
        let expected = Pubkey::find_program_address(
            &[
                &owner,
                &Pubkey::from_str_const(TOKEN_PROGRAM).to_bytes(),
                &Pubkey::from_str_const(USDC_MINT).to_bytes(),
            ],
            &Pubkey::from_str_const(ASSOCIATED_TOKEN_PROGRAM),
        )
        .0
        .to_bytes();
        assert_eq!(usdc_associated_token_address(&owner), expected);
        let vault = vault_state_address(&profile.program_id(), &[5; 32]);
        let (address, _) = Pubkey::find_program_address(
            &[dagon_zkapi_vault::VAULT_TOKEN_SEED, &vault],
            &dagon_zkapi_vault::ID,
        );
        assert_eq!(
            vault_token_address(&profile.program_id(), &vault),
            address.to_bytes()
        );
    }

    fn local_identity(authority: [u8; 32]) -> NetworkIdentity {
        let program = SharedProfile::embedded().program_id();
        NetworkIdentity::parse(
            &json!({
                "schema": IDENTITY_SCHEMA,
                "network": "localnet",
                "genesis_hash": bs58::encode([7u8; 32]).into_string(),
                "vault_authority": bs58::encode(authority).into_string(),
                "vault_state": bs58::encode(vault_state_address(&program, &authority)).into_string(),
                "treasury_token_account": bs58::encode(usdc_associated_token_address(&[9u8; 32])).into_string(),
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn identity_schema_is_closed_and_resolves_the_vault_pda() {
        let identity = local_identity([5; 32]);
        identity.resolve(SharedProfile::embedded()).unwrap();
        let mut wrong = identity.clone();
        wrong.vault_state = Some(bs58::encode([8u8; 32]).into_string());
        assert!(wrong.resolve(SharedProfile::embedded()).is_err());
        let mut wrong = identity.clone();
        wrong.treasury_token_account = None;
        assert!(wrong.resolve(SharedProfile::embedded()).is_err());
        let mut wrong = identity.clone();
        let program = SharedProfile::embedded().program_id();
        let vault = vault_state_address(&program, &[5; 32]);
        wrong.treasury_token_account =
            Some(bs58::encode(vault_token_address(&program, &vault)).into_string());
        assert!(
            wrong.resolve(SharedProfile::embedded()).is_err(),
            "the vault's own token account cannot be the treasury"
        );
        let mut value = serde_json::to_value(&identity).unwrap();
        value["treasury"] = json!(bs58::encode([9u8; 32]).into_string());
        assert!(
            NetworkIdentity::parse(&value.to_string()).is_err(),
            "the removed treasury wallet key is rejected"
        );
        let mut value = serde_json::to_value(&identity).unwrap();
        value["challenge_period_seconds"] = json!(40);
        assert!(
            NetworkIdentity::parse(&value.to_string()).is_err(),
            "identity cannot carry shared parameters"
        );
        let mut value = serde_json::to_value(&identity).unwrap();
        value["network"] = json!(MAINNET_BETA);
        assert!(
            NetworkIdentity::parse(&value.to_string()).is_err(),
            "mainnet label needs mainnet genesis"
        );
    }

    #[test]
    fn checked_in_mainnet_identity_parses_but_is_not_deployed_yet() {
        let mainnet = NetworkIdentity::mainnet();
        assert_eq!(mainnet.network, MAINNET_BETA);
        assert!(mainnet.resolve(SharedProfile::embedded()).is_err());
    }

    fn effective(identity: &NetworkIdentity, observed: Value) -> Value {
        let identity = serde_json::to_value(identity)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let mut identity = identity;
        identity.remove("schema");
        effective_profile(
            SharedProfile::embedded(),
            identity,
            observed.as_object().unwrap().clone(),
        )
    }

    #[test]
    fn parity_allows_only_identity_differences() {
        let observed = json!({ "vault": { "challenge_period_seconds": 86400 } });
        let local = effective(&local_identity([5; 32]), observed.clone());
        let mut reference = effective(&NetworkIdentity::mainnet(), observed);
        assert_eq!(parity_violations(&local, &reference), Vec::<String>::new());

        reference["observed"]["vault"]["challenge_period_seconds"] = json!(40);
        assert_eq!(parity_violations(&local, &reference).len(), 1);
        reference["observed"]["vault"]["challenge_period_seconds"] = json!(86400);

        let mut drifted = local.clone();
        drifted["profile"]["asset"]["decimals"] = json!(9);
        assert_eq!(parity_violations(&drifted, &reference).len(), 1);

        let mut extra = local.clone();
        extra["identity"]["test_override"] = json!(true);
        assert_eq!(parity_violations(&extra, &reference).len(), 1);

        let mut missing = local;
        missing["observed"].as_object_mut().unwrap().remove("vault");
        let violations = parity_violations(&missing, &reference);
        assert!(
            violations
                .iter()
                .any(|v| v.starts_with("observed.vault.challenge_period_seconds")),
            "{violations:?}"
        );
    }

    #[test]
    fn parity_rejects_nested_identity_and_dotted_key_collisions() {
        let local = serde_json::json!({
            "identity": {"rpc_url": {"challenge_period_seconds": 40}},
        });
        assert!(!parity_violations(&local, &local).is_empty());
        let local = serde_json::json!({
            "observed": {"vault": {"challenge_period_seconds": 40}},
            "observed.vault.challenge_period_seconds": 86400,
        });
        let reference = serde_json::json!({
            "observed": {"vault": {"challenge_period_seconds": 86400}},
            "observed.vault.challenge_period_seconds": 86400,
        });
        assert!(!parity_violations(&local, &reference).is_empty());
    }
}
