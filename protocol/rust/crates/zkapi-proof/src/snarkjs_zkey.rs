//! Reader for snarkjs Groth16 `.zkey` files, producing arkworks BN254 keys.
//!
//! The binary layout (iden3 `binfileutils` container, `zkey` type, Groth16
//! protocol) is implemented from snarkjs' `zkey_new.js`/`zkey_utils.js`. The
//! decoding of curve points and field elements follows arkworks-rs/circom-compat
//! (<https://github.com/arkworks-rs/circom-compat>, `src/zkey.rs`, MIT OR
//! Apache-2.0, the same terms as this repository): snarkjs writes every
//! coordinate as a little-endian 256-bit word in Montgomery form with
//! `R = 2^256`, which is exactly arkworks' internal representation.
//!
//! The `Coefs` section (section 4) is deliberately not read: arkworks derives
//! the constraint matrices from the circuit itself, and the proving key only
//! needs the A/B1/B2/C/H point sections, `IC` and the header points.
//!
//! Proofs made with a key read here MUST use [`crate::circom_reduction::CircomReduction`]
//! because snarkjs stores the `H` query over the doubled evaluation domain.

use std::collections::HashMap;

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, UniformRand, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_std::rand::{CryptoRng, RngCore};

const MAGIC: &[u8; 4] = b"zkey";
const GROTH16_PROTOCOL: u32 = 1;
const FIELD_BYTES: usize = 32;
const G1_BYTES: usize = 2 * FIELD_BYTES;
const G2_BYTES: usize = 4 * FIELD_BYTES;

const SECTION_PROTOCOL: u32 = 1;
const SECTION_HEADER: u32 = 2;
const SECTION_IC: u32 = 3;
const SECTION_A: u32 = 5;
const SECTION_B1: u32 = 6;
const SECTION_B2: u32 = 7;
const SECTION_C: u32 = 8;
const SECTION_H: u32 = 9;
const SECTION_CONTRIBUTIONS: u32 = 10;

/// Dimensions and ceremony bookkeeping read from a `.zkey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkeyInfo {
    /// Total number of wires, including the constant one.
    pub n_vars: usize,
    /// Public wires, not counting the constant one.
    pub n_public: usize,
    /// Evaluation-domain size (a power of two).
    pub domain_size: usize,
    /// `blake2b-512` hash of the circuit as written by `snarkjs zkey new`.
    pub circuit_hash: [u8; 64],
    /// Number of `zkey contribute`/`beacon` contributions recorded in the file.
    pub contributions: u32,
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| anyhow!("unexpected end of zkey data"))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.position == self.bytes.len(),
            "trailing bytes in zkey section"
        );
        Ok(())
    }
}

fn read_fq(bytes: &[u8]) -> Result<Fq> {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let value = BigInt::<4>::new(limbs);
    ensure!(
        value < Fq::MODULUS,
        "non-canonical base-field element in zkey"
    );
    Ok(Fq::new_unchecked(value))
}

fn read_g1(bytes: &[u8]) -> Result<G1Affine> {
    let x = read_fq(&bytes[..FIELD_BYTES])?;
    let y = read_fq(&bytes[FIELD_BYTES..G1_BYTES])?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::zero());
    }
    let point = G1Affine::new_unchecked(x, y);
    // BN254 G1 has cofactor 1, so being on the curve is the subgroup check.
    ensure!(point.is_on_curve(), "G1 point in zkey is not on the curve");
    Ok(point)
}

fn read_g2(bytes: &[u8], subgroup_check: bool) -> Result<G2Affine> {
    let coordinate = |offset: usize| -> Result<Fq2> {
        Ok(Fq2::new(
            read_fq(&bytes[offset..offset + FIELD_BYTES])?,
            read_fq(&bytes[offset + FIELD_BYTES..offset + 2 * FIELD_BYTES])?,
        ))
    };
    let x = coordinate(0)?;
    let y = coordinate(2 * FIELD_BYTES)?;
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::zero());
    }
    let point = G2Affine::new_unchecked(x, y);
    ensure!(point.is_on_curve(), "G2 point in zkey is not on the curve");
    if subgroup_check {
        ensure!(
            point.is_in_correct_subgroup_assuming_on_curve(),
            "G2 point in zkey is not in the prime-order subgroup"
        );
    }
    Ok(point)
}

fn read_g1_list(bytes: &[u8], count: usize, what: &str) -> Result<Vec<G1Affine>> {
    ensure!(
        bytes.len() == count * G1_BYTES,
        "zkey {what} section has {} bytes, expected {}",
        bytes.len(),
        count * G1_BYTES
    );
    bytes
        .chunks_exact(G1_BYTES)
        .map(read_g1)
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("decode zkey {what} section"))
}

fn read_g2_list(
    bytes: &[u8],
    count: usize,
    what: &str,
    subgroup_check: bool,
) -> Result<Vec<G2Affine>> {
    ensure!(
        bytes.len() == count * G2_BYTES,
        "zkey {what} section has {} bytes, expected {}",
        bytes.len(),
        count * G2_BYTES
    );
    bytes
        .chunks_exact(G2_BYTES)
        .map(|chunk| read_g2(chunk, subgroup_check))
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("decode zkey {what} section"))
}

fn modulus_bytes(modulus: BigInt<4>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(modulus.0) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

/// Parse a snarkjs Groth16 `.zkey` into an arkworks proving key.
///
/// Every point is checked to lie on the curve; all G2 points are additionally
/// checked for prime-order-subgroup membership when `full_subgroup_checks` is
/// set (the header/verifying-key G2 points are always checked).
///
/// The result is only meaningful together with [`crate::circom_reduction::CircomReduction`].
pub fn read_zkey(
    bytes: &[u8],
    full_subgroup_checks: bool,
) -> Result<(ProvingKey<Bn254>, ZkeyInfo)> {
    let mut reader = Reader::new(bytes);
    ensure!(
        reader.take(4)? == MAGIC,
        "not a snarkjs zkey file (bad magic)"
    );
    let version = reader.u32()?;
    ensure!(version == 1, "unsupported zkey container version {version}");
    let section_count = reader.u32()?;

    let mut sections: HashMap<u32, &[u8]> = HashMap::new();
    for _ in 0..section_count {
        let id = reader.u32()?;
        let size = usize::try_from(reader.u64()?).context("zkey section too large")?;
        let data = reader.take(size)?;
        ensure!(
            sections.insert(id, data).is_none(),
            "duplicate zkey section {id}"
        );
    }
    reader.finish().context("zkey container")?;
    let section = |id: u32| -> Result<&[u8]> {
        sections
            .get(&id)
            .copied()
            .ok_or_else(|| anyhow!("zkey section {id} is missing"))
    };

    let mut protocol = Reader::new(section(SECTION_PROTOCOL)?);
    let protocol_id = protocol.u32()?;
    protocol.finish()?;
    if protocol_id != GROTH16_PROTOCOL {
        bail!("zkey protocol {protocol_id} is not Groth16 (1)");
    }

    let mut header = Reader::new(section(SECTION_HEADER)?);
    ensure!(
        header.u32()? as usize == FIELD_BYTES,
        "unexpected base-field width"
    );
    ensure!(
        header.take(FIELD_BYTES)? == modulus_bytes(Fq::MODULUS),
        "zkey base field is not the BN254 base field"
    );
    ensure!(
        header.u32()? as usize == FIELD_BYTES,
        "unexpected scalar-field width"
    );
    ensure!(
        header.take(FIELD_BYTES)? == modulus_bytes(Fr::MODULUS),
        "zkey scalar field is not the BN254 scalar field"
    );
    let n_vars = header.u32()? as usize;
    let n_public = header.u32()? as usize;
    let domain_size = header.u32()? as usize;
    ensure!(n_public < n_vars, "zkey has more public wires than wires");
    ensure!(
        domain_size.is_power_of_two(),
        "zkey domain size is not a power of two"
    );
    let alpha_g1 = read_g1(header.take(G1_BYTES)?).context("alpha1")?;
    let beta_g1 = read_g1(header.take(G1_BYTES)?).context("beta1")?;
    let beta_g2 = read_g2(header.take(G2_BYTES)?, true).context("beta2")?;
    let gamma_g2 = read_g2(header.take(G2_BYTES)?, true).context("gamma2")?;
    let delta_g1 = read_g1(header.take(G1_BYTES)?).context("delta1")?;
    let delta_g2 = read_g2(header.take(G2_BYTES)?, true).context("delta2")?;
    header.finish().context("zkey header section")?;

    let gamma_abc_g1 = read_g1_list(section(SECTION_IC)?, n_public + 1, "IC")?;
    let a_query = read_g1_list(section(SECTION_A)?, n_vars, "A")?;
    let b_g1_query = read_g1_list(section(SECTION_B1)?, n_vars, "B1")?;
    let b_g2_query = read_g2_list(section(SECTION_B2)?, n_vars, "B2", full_subgroup_checks)?;
    let l_query = read_g1_list(section(SECTION_C)?, n_vars - n_public - 1, "C")?;
    let h_query = read_g1_list(section(SECTION_H)?, domain_size, "H")?;

    let mut contributions = Reader::new(section(SECTION_CONTRIBUTIONS)?);
    let circuit_hash: [u8; 64] = contributions.take(64)?.try_into().unwrap();
    let contribution_count = contributions.u32()?;

    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };
    let key = ProvingKey::<Bn254> {
        vk,
        beta_g1,
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    };
    Ok((
        key,
        ZkeyInfo {
            n_vars,
            n_public,
            domain_size,
            circuit_hash,
            contributions: contribution_count,
        },
    ))
}

/// Cross-check the redundant parts of a proving key decoded from a zkey.
///
/// A snarkjs zkey stores `beta`/`delta` in both groups and the `B` query in
/// both G1 and G2, so a mix-up or corruption shows up as a pairing mismatch:
///
/// * `e(beta_1, g2) == e(g1, beta_2)` and `e(delta_1, g2) == e(g1, delta_2)`;
/// * a random linear combination of the `B1` query pairs with `g2` exactly like
///   the same combination of the `B2` query pairs with `g1`.
///
/// Snarkjs fixes `gamma_2` to the group generator; that is checked too.
pub fn check_zkey_consistency(
    key: &ProvingKey<Bn254>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    ensure!(
        key.vk.gamma_g2 == g2,
        "zkey gamma_2 is not the G2 generator"
    );
    ensure!(
        Bn254::pairing(key.beta_g1, g2) == Bn254::pairing(g1, key.vk.beta_g2),
        "zkey beta_1 and beta_2 do not match"
    );
    ensure!(
        Bn254::pairing(key.delta_g1, g2) == Bn254::pairing(g1, key.vk.delta_g2),
        "zkey delta_1 and delta_2 do not match"
    );
    ensure!(
        key.b_g1_query.len() == key.b_g2_query.len(),
        "zkey B1 and B2 queries differ in length"
    );
    let scalars: Vec<Fr> = key.b_g1_query.iter().map(|_| Fr::rand(rng)).collect();
    let b1 = G1Projective::msm(&key.b_g1_query, &scalars)
        .map_err(|error| anyhow!("B1 combination: {error}"))?;
    let b2 = G2Projective::msm(&key.b_g2_query, &scalars)
        .map_err(|error| anyhow!("B2 combination: {error}"))?;
    ensure!(
        Bn254::pairing(b1.into_affine(), g2) == Bn254::pairing(g1, b2.into_affine()),
        "zkey B1 and B2 queries do not match"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::{matrices_of, r1cs_bytes};
    use crate::circom_reduction::CircomReduction;
    use crate::test_support::Product;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn product_r1cs() -> Vec<u8> {
        r1cs_bytes(
            &matrices_of(Product {
                x: None,
                y: None,
                z: None,
            })
            .unwrap(),
        )
        .unwrap()
    }

    /// `tests/fixtures/product.r1cs` is what `ceremony_export` would write for the
    /// tiny `Product` circuit; `product_final.zkey` is what snarkjs made from it
    /// (see `ceremony/README-rust.md`). Set `ZKAPI_UPDATE_FIXTURES=1` to rewrite
    /// the `.r1cs` after a deliberate exporter change.
    #[test]
    fn exporter_output_matches_the_committed_product_r1cs() {
        let path = fixture("product.r1cs");
        if std::env::var_os("ZKAPI_UPDATE_FIXTURES").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, product_r1cs()).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), product_r1cs());
    }

    #[test]
    fn snarkjs_zkey_fixture_proves_with_circom_reduction() {
        let bytes = std::fs::read(fixture("product_final.zkey")).unwrap();
        let (key, info) = read_zkey(&bytes, true).unwrap();
        assert_eq!(info.n_vars, 9);
        assert_eq!(info.n_public, 1);
        assert_eq!(info.domain_size, 8);
        assert!(info.contributions >= 2, "fixture is a multi-party zkey");
        let mut rng = StdRng::seed_from_u64(11);
        check_zkey_consistency(&key, &mut rng).unwrap();

        let (x, y) = (Fr::from(6u64), Fr::from(7u64));
        let z = x * y;
        let circuit = Product {
            x: Some(x),
            y: Some(y),
            z: Some(z),
        };
        let proof =
            Groth16::<Bn254, CircomReduction>::prove(&key, circuit.clone(), &mut rng).unwrap();
        assert!(Groth16::<Bn254, CircomReduction>::verify(&key.vk, &[z], &proof).unwrap());
        assert!(
            !Groth16::<Bn254, CircomReduction>::verify(&key.vk, &[z + Fr::from(1u64)], &proof)
                .unwrap()
        );
        // The same statement proved with the stock reduction must not verify.
        let stock = Groth16::<Bn254>::prove(&key, circuit, &mut rng).unwrap();
        assert!(!Groth16::<Bn254>::verify(&key.vk, &[z], &stock).unwrap());
    }

    #[test]
    fn malformed_zkeys_are_rejected() {
        let bytes = std::fs::read(fixture("product_final.zkey")).unwrap();
        for length in [0, 3, 11, 12, bytes.len() / 2, bytes.len() - 1] {
            assert!(
                read_zkey(&bytes[..length], true).is_err(),
                "length {length}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(read_zkey(&trailing, true).is_err());
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(read_zkey(&bad_magic, true).is_err());
        // The first section is `1`: protocol id. 2 is PLONK.
        let mut plonk = bytes.clone();
        plonk[12 + 4 + 8..12 + 4 + 8 + 4].copy_from_slice(&2u32.to_le_bytes());
        assert!(read_zkey(&plonk, true)
            .unwrap_err()
            .to_string()
            .contains("not Groth16"));
        // Corrupting a point coordinate must be noticed (off-curve or mismatch).
        let (key, _) = read_zkey(&bytes, true).unwrap();
        let mut broken = key.clone();
        broken.b_g1_query[3] = (broken.b_g1_query[3] + ark_bn254::G1Affine::generator()).into();
        assert!(check_zkey_consistency(&broken, &mut StdRng::seed_from_u64(1)).is_err());
    }
}
