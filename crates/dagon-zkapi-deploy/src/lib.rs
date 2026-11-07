//! Profile-bound initialization and chain observations shared with the local lifecycle test.
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::Engine;
use dagon_zkapi_profile::{
    effective_profile, executable_sha256, to_hex, NetworkIdentity, SharedProfile,
    UPGRADEABLE_LOADER,
};
use dagon_zkapi_vault as vault;
use pyth_solana_receiver_sdk::price_update::{PriceUpdateV2, VerificationLevel};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use std::{str::FromStr, sync::LazyLock, time::Duration};
use zkapi_proof::compact::CompactSigner;

pub const FEATURE_PROGRAM: &str = "Feature111111111111111111111111111111111111";
// FEATURE_NAMES from the exact release, not every historical Feature account.
// The explicitly enumerated retired IDs were confirmed absent from that source.
static RUNTIME_FEATURES: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("agave-4.4.1-features.json"))
        .expect("pinned Agave feature registry")
});

pub fn initialize_instruction(
    profile: &SharedProfile,
    identity: &NetworkIdentity,
    state: &CompactSigner,
    clearance: &CompactSigner,
) -> Result<Instruction> {
    let id = identity.resolve(profile)?;
    let s = state.public_key();
    let c = clearance.public_key();
    Ok(Instruction {
        program_id: Pubkey::new_from_array(profile.program_id()),
        accounts: vault::accounts::Initialize {
            vault: Pubkey::new_from_array(id.vault_state),
            authority: Pubkey::new_from_array(id.vault_authority),
            treasury: Pubkey::new_from_array(id.treasury),
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
        data: vault::instruction::Initialize {
            args: vault::InitializeArgs {
                genesis_hash: id.genesis_hash,
                note_ttl: profile.vault.note_ttl_seconds,
                challenge_period: profile.vault.challenge_period_seconds,
                request_charge_cap: profile.vault.request_charge_cap,
                state_signing_key_x: *s.x.as_bytes(),
                state_signing_key_y: *s.y.as_bytes(),
                clearance_signing_key_x: *c.x.as_bytes(),
                clearance_signing_key_y: *c.y.as_bytes(),
            },
        }
        .data(),
    })
}

pub struct Rpc {
    client: reqwest::Client,
    pub url: String,
}
pub struct Account {
    pub owner: String,
    pub executable: bool,
    pub data: Vec<u8>,
}
impl Rpc {
    pub fn new(url: String) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            url,
        })
    }
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let v: Value = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if let Some(e) = v.get("error") {
            bail!("{method}: {e}");
        }
        v.get("result")
            .cloned()
            .context("RPC response has no result")
    }
    async fn optional_account(&self, address: &str) -> Result<Option<Account>> {
        let v = self
            .call(
                "getAccountInfo",
                json!([address,{"encoding":"base64","commitment":"finalized"}]),
            )
            .await?;
        let a = v
            .get("value")
            .context("RPC account response has no value")?;
        if a.is_null() {
            return Ok(None);
        }
        Ok(Some(Account {
            owner: a["owner"].as_str().context("account owner")?.into(),
            executable: a["executable"].as_bool().context("account executable")?,
            data: base64::engine::general_purpose::STANDARD
                .decode(a["data"][0].as_str().context("account data")?)?,
        }))
    }
    pub async fn account(&self, address: &str) -> Result<Account> {
        self.optional_account(address)
            .await?
            .with_context(|| format!("account {address} is absent"))
    }
    pub async fn check_genesis(&self, identity: &NetworkIdentity) -> Result<()> {
        ensure!(
            self.call("getGenesisHash", json!([])).await? == identity.genesis_hash,
            "RPC genesis differs from identity"
        );
        Ok(())
    }
    pub async fn program(&self, address: &str) -> Result<Value> {
        let program = self.account(address).await?;
        self.program_account(address, program).await
    }
    async fn program_account(&self, address: &str, program: Account) -> Result<Value> {
        ensure!(
            program.executable && program.owner == UPGRADEABLE_LOADER,
            "{address}: not an upgradeable-loader executable"
        );
        ensure!(
            program.data.len() == 36 && program.data[..4] == 2u32.to_le_bytes(),
            "invalid loader Program account"
        );
        let data_address = Pubkey::new_from_array(program.data[4..36].try_into()?);
        let data = self.account(&data_address.to_string()).await?;
        ensure!(
            data.owner == UPGRADEABLE_LOADER && !data.executable,
            "invalid ProgramData owner/executable"
        );
        decode_program_data(&data.data)
    }
    pub async fn active_features(&self) -> Result<Vec<String>> {
        let result = self
            .call(
                "getProgramAccounts",
                json!([FEATURE_PROGRAM, {
                    "encoding":"base64", "commitment":"finalized", "withContext":true
                }]),
            )
            .await?;
        decode_active_features(&result)
    }
}

/// Compare IDs, not activation slots: the local genesis activates the same
/// runtime features at slot zero. A future scheduled activation is not active.
pub fn decode_active_features(result: &Value) -> Result<Vec<String>> {
    let slot = result["context"]["slot"]
        .as_u64()
        .context("feature observation slot")?;
    let accounts = result["value"].as_array().context("feature account list")?;
    let mut active = Vec::with_capacity(accounts.len());
    for entry in accounts {
        let account = &entry["account"];
        ensure!(
            account["owner"] == FEATURE_PROGRAM && account["executable"] == false,
            "invalid feature account owner/executable"
        );
        let data = base64::engine::general_purpose::STANDARD
            .decode(account["data"][0].as_str().context("feature data")?)?;
        match data.first() {
            Some(0) => {}
            Some(1) if data.len() == 9 => {
                if u64::from_le_bytes(data[1..9].try_into()?) <= slot {
                    let key = entry["pubkey"].as_str().context("feature pubkey")?;
                    Pubkey::from_str(key).context("invalid feature pubkey")?;
                    active.push(key.to_owned());
                }
            }
            _ => bail!("invalid feature activation encoding"),
        }
    }
    active.sort_unstable();
    ensure!(
        active.windows(2).all(|pair| pair[0] != pair[1]),
        "duplicate feature accounts"
    );
    Ok(active)
}

fn known_active_features(active: &[String]) -> Result<Vec<&str>> {
    let known = RUNTIME_FEATURES["feature_ids"].as_array().unwrap();
    let retired = RUNTIME_FEATURES["retired_in_software"].as_array().unwrap();
    let contains = |set: &[Value], key: &str| {
        set.binary_search_by(|v| v.as_str().unwrap().cmp(key))
            .is_ok()
    };
    let mut result = Vec::with_capacity(active.len());
    for key in active {
        if contains(known, key) {
            result.push(key.as_str());
        } else {
            ensure!(contains(retired, key), "unclassified active feature {key}: update the pinned software/registry; refusing parity");
        }
    }
    Ok(result)
}

async fn runtime_observation(rpc: &Rpc, expected: bool) -> Result<Value> {
    let local_version = rpc.call("getVersion", json!([])).await?;
    let mainnet_version = if expected {
        local_version.clone()
    } else {
        ensure!(
            local_version["solana-core"] == RUNTIME_FEATURES["version"],
            "local validator must be the pinned Agave release"
        );
        Rpc::new(
            std::env::var("MAINNET_RPC_URL")
                .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into()),
        )?
        .call("getVersion", json!([]))
        .await?
    };
    ensure!(
        mainnet_version["solana-core"]
            .as_str()
            .is_some_and(|v| v.starts_with("4.4.")),
        "mainnet software release changed; review the pinned runtime"
    );
    let active = rpc.active_features().await?;
    Ok(json!({
        "software_version":RUNTIME_FEATURES["version"],
        "mainnet_get_version":mainnet_version,
        "active_feature_ids":known_active_features(&active)?,
        "retired_in_software":RUNTIME_FEATURES["retired_in_software"],
        "feature_registry_git_blob":RUNTIME_FEATURES["source_git_blob"]
    }))
}

pub fn decode_program_data(data: &[u8]) -> Result<Value> {
    ensure!(
        data.len() > 45 && data[..4] == 3u32.to_le_bytes(),
        "invalid ProgramData account"
    );
    let authority = match data[12] {
        0 => Value::Null,
        1 => json!(Pubkey::new_from_array(data[13..45].try_into()?).to_string()),
        _ => bail!("invalid upgrade authority option"),
    };
    Ok(
        json!({"loader":UPGRADEABLE_LOADER,"executable":true,"upgrade_authority":authority,"executable_sha256":to_hex(&executable_sha256(&data[45..]))}),
    )
}

pub fn decode_price(account: &Account) -> Result<Value> {
    ensure!(
        account.data.len() == PriceUpdateV2::LEN,
        "invalid Pyth account length"
    );
    let price = PriceUpdateV2::try_deserialize(&mut account.data.as_slice())
        .context("invalid PriceUpdateV2")?;
    let verification = match price.verification_level {
        VerificationLevel::Full => json!("full"),
        VerificationLevel::Partial { num_signatures } => json!({"partial": num_signatures}),
    };
    Ok(
        json!({"owner":account.owner,"feed_id":format!("0x{}",to_hex(&price.price_message.feed_id)),"verification_level":verification}),
    )
}

pub fn decode_vault(data: &[u8], identity: &mut Map<String, Value>) -> Result<Value> {
    let v = vault::VaultState::try_deserialize(&mut &*data).context("invalid VaultState")?;
    identity.insert("vault_authority".into(), json!(v.authority.to_string()));
    identity.insert("treasury".into(), json!(v.treasury.to_string()));
    identity.insert(
        "genesis_hash".into(),
        json!(bs58::encode(v.genesis_hash).into_string()),
    );
    identity.insert("chain_id".into(), json!(v.chain_id));
    identity.insert(
        "deployment_binding".into(),
        json!(to_hex(&v.protocol_binding)),
    );
    identity.insert(
        "state_signing_key".into(),
        json!([
            to_hex(&v.state_signing_key_x),
            to_hex(&v.state_signing_key_y)
        ]),
    );
    identity.insert(
        "clearance_signing_key".into(),
        json!([
            to_hex(&v.clearance_signing_key_x),
            to_hex(&v.clearance_signing_key_y)
        ]),
    );
    Ok(
        json!({"version":v.version,"request_charge_cap":v.request_charge_cap,"note_ttl_seconds":v.note_ttl,"challenge_period_seconds":v.challenge_period,"paused":v.paused}),
    )
}

pub async fn oracle_observations(
    rpc: &Rpc,
    profile: &SharedProfile,
    price_address: &str,
) -> Result<Value> {
    let price = rpc.account(price_address).await?;
    let price_observation = decode_price(&price)?;
    ensure!(
        !price.executable
            && price.owner == profile.pyth.receiver_program
            && price_observation["feed_id"] == profile.pyth.feed_id
            && price_observation["verification_level"] == "full",
        "Pyth account must be the profile's fully verified SOL/USD feed"
    );
    let receiver = Pubkey::from_str(&profile.pyth.receiver_program)?;
    let config = Pubkey::find_program_address(&[b"config"], &receiver).0;
    let config_data = rpc.account(&config.to_string()).await?;
    ensure!(
        config_data.owner == receiver.to_string(),
        "receiver config owner mismatch"
    );
    // GuardianSet PDAs are indexed by the guardian set in the signed VAA. The
    // bridge account's first u32 is the current guardian-set index (Borsh).
    let wormhole = Pubkey::from_str(&profile.pyth.wormhole_program)?;
    let bridge = Pubkey::find_program_address(&[b"Bridge"], &wormhole).0;
    let bridge_data = rpc.account(&bridge.to_string()).await?;
    ensure!(
        bridge_data.owner == profile.pyth.wormhole_program && bridge_data.data.len() >= 4,
        "invalid Wormhole bridge"
    );
    let index = u32::from_le_bytes(bridge_data.data[..4].try_into()?);
    let guardian =
        Pubkey::find_program_address(&[b"GuardianSet", &index.to_be_bytes()], &wormhole).0;
    let guardian_data = rpc.account(&guardian.to_string()).await?;
    ensure!(
        guardian_data.owner == profile.pyth.wormhole_program,
        "guardian set owner mismatch"
    );
    Ok(
        json!({"price":price_observation,"receiver_program":rpc.program(&profile.pyth.receiver_program).await?,"push_oracle_program":rpc.program(&profile.pyth.push_oracle_program).await?,"wormhole_program":rpc.program(&profile.pyth.wormhole_program).await?,"receiver_config":{"address":config.to_string(),"sha256":to_hex(&Sha256::digest(&config_data.data))},"guardian_set":{"address":guardian.to_string(),"sha256":to_hex(&Sha256::digest(&guardian_data.data))}}),
    )
}

/// Validate a complete parity document independently of the other side.
/// Equality of two incomplete or identically misconfigured observations is
/// not evidence that either deployment implements the compiled profile.
pub fn validate_effective_profile(value: &Value) -> Result<()> {
    let p = SharedProfile::embedded();
    let object = value
        .as_object()
        .context("effective profile must be an object")?;
    ensure!(
        object.len() == 3 && object.contains_key("identity") && object.contains_key("observed"),
        "effective profile requires exactly profile, identity and observed"
    );
    ensure!(
        value["profile"] == p.to_value(),
        "shared profile differs from compiled profile"
    );
    let identity = value["identity"]
        .as_object()
        .context("identity must be an object")?;
    for (key, field) in identity {
        ensure!(
            dagon_zkapi_profile::IDENTITY_KEYS.contains(&key.as_str()),
            "unknown identity key {key}"
        );
        let valid = match key.as_str() {
            "chain_id" => field.as_u64().is_some(),
            "state_signing_key" | "clearance_signing_key" => field
                .as_array()
                .is_some_and(|parts| parts.len() == 2 && parts.iter().all(Value::is_string)),
            "vault_authority" | "vault_state" | "treasury" | "pyth_price_account" => {
                field.is_null() || field.is_string()
            }
            _ => field.is_string(),
        };
        ensure!(valid, "invalid identity value for {key}");
    }
    let mut declared = Map::new();
    declared.insert("schema".into(), json!(dagon_zkapi_profile::IDENTITY_SCHEMA));
    for key in [
        "network",
        "genesis_hash",
        "vault_authority",
        "vault_state",
        "treasury",
        "pyth_price_account",
    ] {
        declared.insert(
            key.into(),
            identity
                .get(key)
                .with_context(|| format!("missing identity {key}"))?
                .clone(),
        );
    }
    let declared = NetworkIdentity::parse(&Value::Object(declared).to_string())?;
    declared.pyth_price_account(p)?;
    if declared.vault_state.is_some() {
        declared.resolve(p)?;
    } else {
        ensure!(
            declared.network == dagon_zkapi_profile::MAINNET_BETA,
            "only the undeployed mainnet reference may omit vault accounts"
        );
    }
    ensure!(
        identity.get("rpc_url").is_some_and(Value::is_string),
        "missing identity RPC URL"
    );
    let observed = &value["observed"];
    ensure!(
        observed["program"]
            == json!({
                "loader": p.program.loader, "executable": true,
                "upgrade_authority": p.program.upgrade_authority,
                "executable_sha256": p.program.executable_sha256
            }),
        "observed program differs from compiled profile"
    );
    ensure!(
        observed["vault"]
            == json!({
                "version": p.vault.version, "request_charge_cap": p.vault.request_charge_cap,
                "note_ttl_seconds": p.vault.note_ttl_seconds,
                "challenge_period_seconds": p.vault.challenge_period_seconds, "paused": false
            }),
        "observed vault differs from compiled profile or is paused"
    );
    ensure!(
        observed["oracle"]["price"]
            == json!({
                "owner": p.pyth.receiver_program, "feed_id": p.pyth.feed_id, "verification_level": "full"
            }),
        "observed price is not the profile's fully verified feed"
    );
    for name in [
        "receiver_program",
        "push_oracle_program",
        "wormhole_program",
    ] {
        let program = &observed["oracle"][name];
        ensure!(
            program["loader"] == UPGRADEABLE_LOADER
                && program["executable"] == true
                && program
                    .get("upgrade_authority")
                    .is_some_and(|v| v.is_null() || v.is_string())
                && program["executable_sha256"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "missing or malformed oracle program {name}"
        );
    }
    for name in ["receiver_config", "guardian_set"] {
        let account = &observed["oracle"][name];
        ensure!(
            account["address"].is_string()
                && account["sha256"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "missing or malformed oracle account {name}"
        );
    }
    let runtime = &observed["runtime"];
    ensure!(
        runtime["software_version"] == RUNTIME_FEATURES["version"]
            && runtime["retired_in_software"] == RUNTIME_FEATURES["retired_in_software"]
            && runtime["feature_registry_git_blob"] == RUNTIME_FEATURES["source_git_blob"]
            && runtime["mainnet_get_version"]["solana-core"]
                .as_str()
                .is_some_and(|s| s.starts_with("4.4."))
            && runtime["mainnet_get_version"]["feature-set"]
                .as_u64()
                .is_some(),
        "missing or unsupported runtime observation"
    );
    let active: Vec<String> = serde_json::from_value(runtime["active_feature_ids"].clone())
        .context("missing or malformed active feature IDs")?;
    ensure!(
        !active.is_empty()
            && active.windows(2).all(|pair| pair[0] < pair[1])
            && known_active_features(&active)?.len() == active.len(),
        "active feature IDs must be nonempty, sorted, unique and known"
    );
    Ok(())
}

pub async fn observe(rpc: &Rpc, identity: &NetworkIdentity, expected: bool) -> Result<Value> {
    let p = SharedProfile::embedded();
    rpc.check_genesis(identity).await?;
    let mut id = serde_json::to_value(identity)?.as_object().unwrap().clone();
    id.remove("schema");
    id.insert("rpc_url".into(), json!(rpc.url));
    let program = if expected {
        match rpc.optional_account(&p.program.program_id).await? {
            Some(account) => rpc.program_account(&p.program.program_id, account).await?,
            None => {
                json!({"loader":p.program.loader,"executable":true,"upgrade_authority":p.program.upgrade_authority,"executable_sha256":p.program.executable_sha256})
            }
        }
    } else {
        rpc.program(&p.program.program_id).await?
    };
    let vault_observation = if expected && identity.vault_state.is_none() {
        json!({"version":p.vault.version,"request_charge_cap":p.vault.request_charge_cap,"note_ttl_seconds":p.vault.note_ttl_seconds,"challenge_period_seconds":p.vault.challenge_period_seconds,"paused":false})
    } else {
        let resolved = identity.resolve(p)?;
        let a = rpc
            .account(identity.vault_state.as_deref().unwrap())
            .await?;
        ensure!(
            a.owner == p.program.program_id && !a.executable,
            "vault owner/executable mismatch"
        );
        let observation = decode_vault(&a.data, &mut id)?;
        ensure!(
            id["vault_authority"] == identity.vault_authority.as_deref().unwrap()
                && id["treasury"] == identity.treasury.as_deref().unwrap()
                && id["genesis_hash"] == identity.genesis_hash,
            "vault identity differs from declared identity"
        );
        ensure!(resolved.genesis_hash != [0; 32], "missing genesis");
        observation
    };
    let price = identity
        .pyth_price_account
        .as_deref()
        .ok_or_else(|| anyhow!("identity has no price account"))?;
    let oracle = oracle_observations(rpc, p, price).await?;
    let observed = json!({"program":program,"vault":vault_observation,"oracle":oracle,"runtime":runtime_observation(rpc,expected).await?});
    let result = effective_profile(p, id, observed.as_object().unwrap().clone());
    validate_effective_profile(&result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::{Discriminator, Space};
    use dagon_zkapi_profile::parity_violations;
    #[test]
    fn runtime_registry_is_sorted_and_never_silently_ignores_unknown_features() {
        for name in ["feature_ids", "retired_in_software"] {
            let ids = RUNTIME_FEATURES[name].as_array().unwrap();
            assert!(ids.windows(2).all(|v| v[0].as_str() < v[1].as_str()));
            for id in ids {
                Pubkey::from_str(id.as_str().unwrap()).unwrap();
            }
        }
        let known = RUNTIME_FEATURES["feature_ids"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let retired = RUNTIME_FEATURES["retired_in_software"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let active = vec![known.clone(), retired];
        assert_eq!(
            known_active_features(&active).unwrap(),
            vec![known.as_str()]
        );
        assert!(known_active_features(&[Pubkey::default().to_string()]).is_err());
        assert_eq!(
            RUNTIME_FEATURES["feature_ids"].as_array().unwrap().len(),
            290
        );
    }
    #[test]
    fn feature_observations_sort_active_ids_and_reject_malformed_data() {
        let entry = |key: &str, activation: Option<u64>| {
            let mut data = vec![0; 9];
            if let Some(slot) = activation {
                data[0] = 1;
                data[1..].copy_from_slice(&slot.to_le_bytes());
            }
            json!({"pubkey":key,"account":{"owner":FEATURE_PROGRAM,"executable":false,"data":[base64::engine::general_purpose::STANDARD.encode(data),"base64"]}})
        };
        let a = Pubkey::new_from_array([1; 32]).to_string();
        let b = Pubkey::new_from_array([2; 32]).to_string();
        let mut response = json!({"context":{"slot":10},"value":[entry(&b,Some(10)),entry(&a,Some(0)),entry(FEATURE_PROGRAM,Some(11)),entry(&Pubkey::new_from_array([3; 32]).to_string(),None)]});
        let mut expected = vec![a, b];
        expected.sort_unstable();
        assert_eq!(decode_active_features(&response).unwrap(), expected);
        let local = json!({"observed":{"runtime":{"active_feature_ids":expected}}});
        let mut mainnet = local.clone();
        mainnet["observed"]["runtime"]["active_feature_ids"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(!parity_violations(&local, &mainnet).is_empty());
        response["value"][0]["account"]["data"][0] = json!("Ag==");
        assert!(decode_active_features(&response).is_err());
    }
    #[test]
    fn decoders_preserve_security_fields_and_separate_identity() {
        let mut price = vec![0; PriceUpdateV2::LEN];
        price[..8].copy_from_slice(PriceUpdateV2::DISCRIMINATOR);
        price[40] = 1; // Full, with no Partial.num_signatures byte.
        price[41..73].fill(0x42);
        let observation = decode_price(&Account {
            owner: "receiver".into(),
            executable: false,
            data: price,
        })
        .unwrap();
        assert_eq!(observation["verification_level"], "full");
        assert_eq!(observation["feed_id"], format!("0x{}", "42".repeat(32)));
        assert_eq!(observation["owner"], "receiver");
        let mut data = vec![0; 8 + vault::VaultState::INIT_SPACE];
        data[..8].copy_from_slice(vault::VaultState::DISCRIMINATOR);
        data[8] = 1;
        data[10] = 1;
        let mut identity = Map::new();
        let v = decode_vault(&data, &mut identity).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["paused"], true);
        assert_eq!(v["request_charge_cap"], 0);
        assert!(identity.contains_key("state_signing_key"));
        assert!(identity.contains_key("clearance_signing_key"));
        assert!(identity.contains_key("treasury"));
        assert!(!v.as_object().unwrap().contains_key("treasury"));
    }
    #[test]
    fn loader_decoding_is_strict_and_trims_padding() {
        let mut data = vec![0; 45];
        data[..4].copy_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 0, 0]);
        let v = decode_program_data(&data).unwrap();
        assert!(v["upgrade_authority"].is_null());
        assert_eq!(
            v["executable_sha256"],
            to_hex(&executable_sha256(&[1, 2, 3]))
        );
        data[12] = 2;
        assert!(decode_program_data(&data).is_err());
        assert!(decode_program_data(&[0; 44]).is_err());
    }
    #[test]
    fn diff_allows_only_identity_not_observed_security_fields() {
        let a = json!({"identity":{"network":"localnet"},"observed":{"vault":{"challenge_period_seconds":86400},"program":{"executable_sha256":"a"}}});
        let mut b = a.clone();
        b["identity"]["network"] = json!("mainnet-beta");
        assert!(parity_violations(&a, &b).is_empty());
        b["observed"]["vault"]["challenge_period_seconds"] = json!(40);
        assert_eq!(parity_violations(&a, &b).len(), 1);
        b["observed"]["program"]["executable_sha256"] = json!("b");
        assert_eq!(parity_violations(&a, &b).len(), 2);
    }
    #[test]
    fn malformed_price_and_vault_are_rejected() {
        assert!(decode_price(&Account {
            owner: String::new(),
            executable: false,
            data: vec![0; PriceUpdateV2::LEN]
        })
        .is_err());
        assert!(decode_vault(&[0; 400], &mut Map::new()).is_err());
    }

    fn valid_effective_profile() -> Value {
        let p = SharedProfile::embedded();
        let mut identity = serde_json::to_value(NetworkIdentity::mainnet()).unwrap();
        identity.as_object_mut().unwrap().remove("schema");
        identity["rpc_url"] = json!("https://api.mainnet-beta.solana.com");
        let program = json!({"loader":p.program.loader,"executable":true,"upgrade_authority":null,"executable_sha256":p.program.executable_sha256});
        json!({
            "profile": p.to_value(), "identity": identity,
            "observed": {
                "program": program,
                "vault": {"version":p.vault.version,"request_charge_cap":p.vault.request_charge_cap,"note_ttl_seconds":p.vault.note_ttl_seconds,"challenge_period_seconds":p.vault.challenge_period_seconds,"paused":false},
                "oracle": {
                    "price":{"owner":p.pyth.receiver_program,"feed_id":p.pyth.feed_id,"verification_level":"full"},
                    "receiver_program":program,"push_oracle_program":program,"wormhole_program":program,
                    "receiver_config":{"address":p.pyth.push_oracle_program,"sha256":"00".repeat(32)},
                    "guardian_set":{"address":p.pyth.wormhole_program,"sha256":"00".repeat(32)}
                },
                "runtime": {
                    "software_version":RUNTIME_FEATURES["version"],
                    "mainnet_get_version":{"solana-core":"4.4.1","feature-set":2681577653u64},
                    "active_feature_ids":[RUNTIME_FEATURES["feature_ids"][0]],
                    "retired_in_software":RUNTIME_FEATURES["retired_in_software"],
                    "feature_registry_git_blob":RUNTIME_FEATURES["source_git_blob"]
                }
            }
        })
    }

    #[test]
    fn parity_documents_fail_closed_even_when_both_sides_match() {
        let valid = valid_effective_profile();
        validate_effective_profile(&valid).unwrap();
        for malformed in [json!({}), json!(null), json!({"profile":{}})] {
            assert!(validate_effective_profile(&malformed).is_err());
        }
        for pointer in [
            "/observed/program/executable_sha256",
            "/observed/program/upgrade_authority",
            "/observed/vault/challenge_period_seconds",
            "/observed/oracle/price/verification_level",
            "/observed/oracle/guardian_set",
            "/observed/oracle/wormhole_program",
            "/observed/runtime/active_feature_ids",
            "/profile/server/lease_ttl_seconds",
            "/identity/rpc_url",
        ] {
            let mut bad = valid.clone();
            *bad.pointer_mut(pointer).unwrap() = json!({"challenge_period_seconds":40});
            assert!(validate_effective_profile(&bad).is_err(), "{pointer}");
        }
        let mut override_vault = valid;
        override_vault["observed"]["vault"]["challenge_period_seconds"] = json!(40);
        assert!(parity_violations(&override_vault, &override_vault).is_empty());
        assert!(validate_effective_profile(&override_vault).is_err());
        // Both sides pinning the same non-push-oracle price account is still refused.
        let mut foreign_price = valid_effective_profile();
        foreign_price["identity"]["pyth_price_account"] =
            json!(Pubkey::new_from_array([8; 32]).to_string());
        assert!(parity_violations(&foreign_price, &foreign_price).is_empty());
        assert!(validate_effective_profile(&foreign_price).is_err());
        let mut changed_tolerance = valid_effective_profile();
        changed_tolerance["profile"]["pyth"]["max_supersession_bps"] =
            json!(SharedProfile::embedded().pyth.max_supersession_bps + 1);
        assert!(parity_violations(&changed_tolerance, &changed_tolerance).is_empty());
        assert!(validate_effective_profile(&changed_tolerance).is_err());
    }
}
