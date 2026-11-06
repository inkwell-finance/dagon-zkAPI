//! Bridge between the arkworks circuits and a snarkjs Groth16 ceremony.
//!
//! * [`export_r1cs`] writes the three circuits as snarkjs binary `.r1cs` files
//!   (the input of `snarkjs zkey new`).
//! * [`import_zkeys`] turns the ceremony's final `.zkey` files back into the
//!   arkworks key/manifest artifacts, using
//!   [`KeyKind::Snarkjs`] key headers and the same artifact writers as
//!   [`crate::compact::setup`].
//!
//! The R1CS is taken from the same witness-independent template circuits that
//! `compact::setup` feeds to the arkworks generator, after the same
//! `finalize()` LC inlining. Wire order is snarkjs' (`1`, public inputs,
//! private wires) which equals arkworks' (instance variables, then witnesses).

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fr};
use sha2::{Digest, Sha256};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use rand::rngs::OsRng;
use serde::Serialize;

use crate::compact::{
    request_template, solana_transition_template, withdrawal_template, write_setup_artifacts,
    write_solana_transition_artifacts, KeyKind,
};
use crate::groth16::{
    REQUEST_PUBLIC_INPUTS, SOLANA_TRANSITION_PUBLIC_INPUTS, WITHDRAWAL_PUBLIC_INPUTS,
};
use crate::snarkjs_zkey::{check_zkey_consistency, read_zkey, ZkeyInfo};

/// Ceremony circuit identifiers, in the order the ceremony processes them.
pub const CIRCUIT_IDS: [&str; 3] = ["request", "withdrawal", "transition"];

/// Directory (below the import output directory) for request/withdrawal keys.
pub const IMPORT_V2_DIRECTORY: &str = "v2";
/// Directory (below the import output directory) for the transition keys.
pub const IMPORT_SOLANA_TRANSITION_DIRECTORY: &str = "solana-transition-v1";

/// Final snarkjs zkey file name for a circuit id.
pub fn final_zkey_file(id: &str) -> String {
    format!("{id}_final.zkey")
}

/// Constraint-system dimensions as the arkworks Groth16 setup sees them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitReport {
    pub id: String,
    /// R1CS constraints (without the `instance` constraints Groth16 adds).
    pub constraints: usize,
    /// Instance variables including the constant `1`.
    pub instance_variables: usize,
    /// Private witness variables.
    pub witness_variables: usize,
    /// Smallest Powers-of-Tau power accepted by `snarkjs zkey new`: the
    /// evaluation domain has `constraints + instanceVariables` points
    /// (snarkjs adds one `input * 0 = 0` constraint per public wire incl. the
    /// constant), rounded up to a power of two.
    pub ptau_power_needed: u32,
}

/// Finalized constraint matrices of one circuit plus their dimensions.
pub struct CircuitShape {
    pub id: &'static str,
    pub matrices: ConstraintMatrices<Fr>,
}

impl CircuitShape {
    pub fn report(&self) -> CircuitReport {
        let constraints = self.matrices.num_constraints;
        let instance_variables = self.matrices.num_instance_variables;
        CircuitReport {
            id: self.id.to_string(),
            constraints,
            instance_variables,
            witness_variables: self.matrices.num_witness_variables,
            ptau_power_needed: domain_power(constraints, instance_variables),
        }
    }
}

fn domain_power(constraints: usize, instance_variables: usize) -> u32 {
    (constraints + instance_variables)
        .next_power_of_two()
        .trailing_zeros()
}

pub(crate) fn matrices_of(
    circuit: impl ConstraintSynthesizer<Fr>,
) -> Result<ConstraintMatrices<Fr>> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .map_err(|error| anyhow!("constraint synthesis failed: {error}"))?;
    cs.finalize();
    cs.to_matrices()
        .ok_or_else(|| anyhow!("constraint matrices unavailable"))
}

/// Finalized shapes of `request`, `withdrawal` and `transition`.
pub fn circuit_shapes() -> Result<Vec<CircuitShape>> {
    Ok(vec![
        CircuitShape {
            id: "request",
            matrices: matrices_of(request_template()?)?,
        },
        CircuitShape {
            id: "withdrawal",
            matrices: matrices_of(withdrawal_template()?)?,
        },
        CircuitShape {
            id: "transition",
            matrices: matrices_of(solana_transition_template()?)?,
        },
    ])
}

fn push_u32(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).context("value exceeds the r1cs u32 range")?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_field(bytes: &mut Vec<u8>, value: &Fr) {
    let mut le = value.into_bigint().to_bytes_le();
    le.resize(32, 0);
    bytes.extend_from_slice(&le);
}

fn push_linear_combination(bytes: &mut Vec<u8>, terms: &[(Fr, usize)]) -> Result<()> {
    // Wire-sorted, duplicate-free and without zero coefficients, as circom writes it.
    let mut sorted: Vec<(usize, Fr)> = terms.iter().map(|(coeff, wire)| (*wire, *coeff)).collect();
    sorted.sort_by_key(|(wire, _)| *wire);
    let mut merged: Vec<(usize, Fr)> = Vec::with_capacity(sorted.len());
    for (wire, coeff) in sorted {
        match merged.last_mut() {
            Some((last, total)) if *last == wire => *total += coeff,
            _ => merged.push((wire, coeff)),
        }
    }
    merged.retain(|(_, coeff)| !ark_ff::Zero::is_zero(coeff));
    push_u32(bytes, merged.len())?;
    for (wire, coeff) in merged {
        push_u32(bytes, wire)?;
        push_field(bytes, &coeff);
    }
    Ok(())
}

/// Serialize constraint matrices in the snarkjs/circom binary `.r1cs` format
/// (version 1; header, constraints and wire-to-label sections).
pub fn r1cs_bytes(matrices: &ConstraintMatrices<Fr>) -> Result<Vec<u8>> {
    let n_wires = matrices.num_instance_variables + matrices.num_witness_variables;
    let n_public_inputs = matrices
        .num_instance_variables
        .checked_sub(1)
        .ok_or_else(|| anyhow!("circuit has no constant-one instance variable"))?;

    let mut constraints = Vec::new();
    for ((a, b), c) in matrices.a.iter().zip(&matrices.b).zip(&matrices.c) {
        push_linear_combination(&mut constraints, a)?;
        push_linear_combination(&mut constraints, b)?;
        push_linear_combination(&mut constraints, c)?;
    }

    let mut header = Vec::with_capacity(64);
    push_u32(&mut header, 32)?;
    header.extend_from_slice(&Fr::MODULUS.to_bytes_le());
    push_u32(&mut header, n_wires)?;
    push_u32(&mut header, 0)?; // nPubOut: every public wire is an input.
    push_u32(&mut header, n_public_inputs)?;
    push_u32(&mut header, matrices.num_witness_variables)?;
    header.extend_from_slice(&(n_wires as u64).to_le_bytes()); // nLabels
    push_u32(&mut header, matrices.num_constraints)?;

    let mut wire_to_label = Vec::with_capacity(n_wires * 8);
    for wire in 0..n_wires as u64 {
        wire_to_label.extend_from_slice(&wire.to_le_bytes());
    }

    let mut file =
        Vec::with_capacity(12 + 3 * 12 + header.len() + constraints.len() + wire_to_label.len());
    file.extend_from_slice(b"r1cs");
    file.extend_from_slice(&1u32.to_le_bytes());
    file.extend_from_slice(&3u32.to_le_bytes());
    for (kind, section) in [(1u32, &header), (2, &constraints), (3, &wire_to_label)] {
        file.extend_from_slice(&kind.to_le_bytes());
        file.extend_from_slice(&(section.len() as u64).to_le_bytes());
        file.extend_from_slice(section);
    }
    Ok(file)
}

/// Write `{request,withdrawal,transition}.r1cs` and `circuits.json` into
/// `directory` and return the per-circuit report.
pub fn export_r1cs(directory: impl AsRef<Path>) -> Result<Vec<CircuitReport>> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)
        .with_context(|| format!("create export directory {}", directory.display()))?;
    let mut reports = Vec::new();
    for shape in circuit_shapes()? {
        let path = directory.join(format!("{}.r1cs", shape.id));
        fs::write(&path, r1cs_bytes(&shape.matrices)?)
            .with_context(|| format!("write {}", path.display()))?;
        reports.push(shape.report());
    }
    let path = directory.join("circuits.json");
    let mut json = serde_json::to_vec_pretty(&reports).context("encode circuits.json")?;
    json.push(b'\n');
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(reports)
}

/// What [`import_zkeys`] learned about one circuit's final zkey.
#[derive(Clone, Debug)]
pub struct ImportedCircuit {
    pub id: &'static str,
    pub zkey: ZkeyInfo,
}

fn load_zkey(
    zkey_dir: &Path,
    shape: &CircuitShape,
    public_inputs: usize,
    expected_sha256: &str,
) -> Result<(ProvingKey<Bn254>, ZkeyInfo)> {
    let path = zkey_dir.join(final_zkey_file(shape.id));
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    ensure!(
        matches_sha256(&bytes, expected_sha256),
        "{}: final zkey SHA256 differs from the independently accepted manifest",
        shape.id
    );
    let (key, info) =
        read_zkey(&bytes, true).with_context(|| format!("decode {}", path.display()))?;
    let report = shape.report();
    ensure!(
        report.instance_variables == public_inputs + 1,
        "{}: circuit has {} instance variables, expected {} public inputs",
        shape.id,
        report.instance_variables,
        public_inputs
    );
    ensure!(
        info.n_vars == report.instance_variables + report.witness_variables,
        "{}: zkey has {} wires, the circuit has {}",
        shape.id,
        info.n_vars,
        report.instance_variables + report.witness_variables
    );
    ensure!(
        info.n_public == public_inputs,
        "{}: zkey has {} public wires, the circuit has {}",
        shape.id,
        info.n_public,
        public_inputs
    );
    ensure!(
        info.domain_size == 1usize << report.ptau_power_needed,
        "{}: zkey domain size {} does not match the circuit's 2^{}",
        shape.id,
        info.domain_size,
        report.ptau_power_needed
    );
    ensure!(
        key.vk.gamma_abc_g1.len() == public_inputs + 1,
        "{}: verifying key has {} IC points, expected {}",
        shape.id,
        key.vk.gamma_abc_g1.len(),
        public_inputs + 1
    );
    check_zkey_consistency(&key, &mut OsRng)
        .with_context(|| format!("{}: {}", shape.id, path.display()))?;
    Ok((key, info))
}

fn ensure_empty_directory(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            path.is_dir() && fs::read_dir(path)?.next().is_none(),
            "{} already exists and is not empty; refusing to overwrite",
            path.display()
        );
    }
    Ok(())
}

/// Convert the three final ceremony zkeys in `zkey_dir`
/// (`request_final.zkey`, `withdrawal_final.zkey`, `transition_final.zkey`)
/// into the repository's key layout below `out_dir`:
///
/// * `out_dir/v2/{request,withdrawal}.{pk,vk}`, `manifest.json`;
/// * `out_dir/solana-transition-v1/transition.{pk,vk}`, `manifest.json`.
///
/// Key files carry the `/snarkjs` headers, so provers use
/// [`crate::circom_reduction::CircomReduction`]. Existing non-empty output
/// directories are refused, so a committed setup directory cannot be
/// overwritten by accident.
pub fn import_zkeys(
    zkey_dir: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    manifest_file: impl AsRef<Path>,
    expected_manifest_sha256: &str,
) -> Result<Vec<ImportedCircuit>> {
    let (zkey_dir, out_dir) = (zkey_dir.as_ref(), out_dir.as_ref());
    let manifest_bytes = fs::read(manifest_file.as_ref()).context("read accepted ceremony manifest")?;
    let manifest = accepted_manifest(&manifest_bytes, expected_manifest_sha256)?;
    let v2_dir = out_dir.join(IMPORT_V2_DIRECTORY);
    let transition_dir = out_dir.join(IMPORT_SOLANA_TRANSITION_DIRECTORY);
    ensure_empty_directory(&v2_dir)?;
    ensure_empty_directory(&transition_dir)?;

    let shapes = circuit_shapes()?;
    let digest = |id: &str, field: &str| -> &str { manifest["keys"][id][field].as_str().unwrap() };
    for shape in &shapes {
        ensure!(
            matches_sha256(&r1cs_bytes(&shape.matrices)?, digest(shape.id, "r1csSha256")),
            "{}: the circuit compiled into this importer differs from the r1cs the ceremony verified",
            shape.id
        );
    }
    let [request, withdrawal, transition] = shapes.as_slice() else {
        bail!("expected exactly three circuits");
    };
    let (request_key, request_info) =
        load_zkey(zkey_dir, request, REQUEST_PUBLIC_INPUTS, digest("request", "zkeySha256"))?;
    let (withdrawal_key, withdrawal_info) =
        load_zkey(zkey_dir, withdrawal, WITHDRAWAL_PUBLIC_INPUTS, digest("withdrawal", "zkeySha256"))?;
    let (transition_key, transition_info) =
        load_zkey(zkey_dir, transition, SOLANA_TRANSITION_PUBLIC_INPUTS, digest("transition", "zkeySha256"))?;
    for info in [&request_info, &withdrawal_info, &transition_info] {
        ensure!(u64::from(info.contributions) == manifest["round"].as_u64().unwrap(),
            "zkey contribution count differs from accepted final manifest");
    }

    write_setup_artifacts(&v2_dir, KeyKind::Snarkjs, &request_key, &withdrawal_key)?;
    write_solana_transition_artifacts(&transition_dir, KeyKind::Snarkjs, &transition_key)?;
    fs::write(out_dir.join("ceremony-provenance.json"), &manifest_bytes)
        .context("write exact accepted ceremony provenance")?;
    fs::write(out_dir.join("ceremony-provenance.sha256"), format!("{expected_manifest_sha256}\n"))
        .context("write ceremony provenance digest")?;
    Ok(vec![
        ImportedCircuit {
            id: "request",
            zkey: request_info,
        },
        ImportedCircuit {
            id: "withdrawal",
            zkey: withdrawal_info,
        },
        ImportedCircuit {
            id: "transition",
            zkey: transition_info,
        },
    ])
}

fn matches_sha256(bytes: &[u8], expected: &str) -> bool {
    let mut expected_bytes = [0u8; 32];
    if hex::decode_to_slice(expected, &mut expected_bytes).is_err() {
        return false;
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    actual == expected_bytes
}

fn accepted_manifest(bytes: &[u8], expected_sha256: &str) -> Result<serde_json::Value> {
    ensure!(matches_sha256(bytes, expected_sha256),
        "adoption manifest SHA256 differs from independently accepted digest");
    let value: serde_json::Value = serde_json::from_slice(bytes).context("decode adoption manifest")?;
    ensure!(value["version"] == 1 && value["finalized"] == true && value["strict"] == true,
        "adoption requires a strict, finalized verification manifest");
    let round = value["round"].as_u64().context("missing final round")?;
    ensure!(round >= 2 && value["checkpoint"]["round"].as_u64() == Some(round - 1),
        "manifest lacks pre-beacon contribution checkpoint");
    let valid_digest = |v: &serde_json::Value| v.as_str().is_some_and(|s|
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    ensure!(valid_digest(&value["ceremonySha256"]), "manifest lacks ceremony identity");
    for id in CIRCUIT_IDS {
        ensure!(["zkeySha256", "verificationKeySha256", "r1csSha256"].iter().all(|field| valid_digest(&value["keys"][id][field])),
            "{id}: manifest lacks final artifact or r1cs digests");
    }
    Ok(value)
}

#[cfg(test)]
mod adoption_tests {
    use super::*;

    #[test]
    fn ceremony_adoption_rejects_manifest_substitution_and_nonfinal_inputs() {
        assert!(accepted_manifest(b"{}", &"0".repeat(64)).is_err());
        let bytes = br#"{"version":1,"finalized":false,"strict":true}"#;
        assert!(accepted_manifest(bytes, &hex::encode(Sha256::digest(bytes))).is_err());
    }

    #[test]
    fn ceremony_adoption_binds_circuits_and_input_bytes_before_decoding() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("ceremony-adoption-{}-{}",
            std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()));
        fs::create_dir(&dir)?;
        let result = (|| -> Result<()> {
            fs::write(dir.join("request_final.zkey"), b"substituted file")?;
            let r1cs: Vec<String> = circuit_shapes()?.iter()
                .map(|shape| Ok(hex::encode(Sha256::digest(r1cs_bytes(&shape.matrices)?))))
                .collect::<Result<_>>()?;
            let import = |r1cs_digest: &dyn Fn(usize) -> String| -> Result<anyhow::Error> {
                let keys: serde_json::Map<String, serde_json::Value> = CIRCUIT_IDS.iter().enumerate().map(|(i, id)|
                    ((*id).to_owned(), serde_json::json!({"zkeySha256": "0".repeat(64), "verificationKeySha256": "1".repeat(64), "r1csSha256": r1cs_digest(i)}))).collect();
                let manifest = serde_json::to_vec(&serde_json::json!({
                    "version": 1, "finalized": true, "strict": true, "round": 2,
                    "checkpoint": {"round": 1}, "ceremonySha256": "2".repeat(64), "keys": keys
                }))?;
                let path = dir.join("adoption.json");
                fs::write(&path, &manifest)?;
                Ok(import_zkeys(&dir, dir.join("out"), &path, &hex::encode(Sha256::digest(&manifest))).unwrap_err())
            };
            let drifted = import(&|i| if i == 2 { "3".repeat(64) } else { r1cs[i].clone() })?;
            assert!(drifted.to_string().contains("transition: the circuit compiled into this importer differs"), "{drifted:#}");
            let substituted = import(&|i| r1cs[i].clone())?;
            assert!(substituted.to_string().contains("final zkey SHA256 differs"), "{substituted:#}");
            assert!(!dir.join("out").exists());
            Ok(())
        })();
        fs::remove_dir_all(&dir)?;
        result
    }
}
