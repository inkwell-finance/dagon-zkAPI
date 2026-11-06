//! snarkjs/circom-compatible R1CS-to-QAP witness map for arkworks Groth16.
//!
//! Keys that come out of a snarkjs/circom trusted-setup ceremony store the
//! quotient-polynomial query (`H`) over the odd powers of the `2n`-th root of
//! unity instead of the multiplicative-coset form that arkworks'
//! `LibsnarkReduction` uses. A proving key from such a ceremony therefore needs
//! this reduction when proofs are produced with `ark-groth16`.
//!
//! Adapted from `CircomReduction` in arkworks-rs/circom-compat
//! (<https://github.com/arkworks-rs/circom-compat>, `src/circom/qap.rs`),
//! licensed MIT OR Apache-2.0, the same terms as this repository. It is
//! vendored here against `ark-groth16 0.5` / `ark-poly 0.5` so the heavy
//! `ark-circom` dependency tree (wasmer, ethers, ...) is not needed. The code
//! is plain `core`/`ark` arithmetic and builds for `wasm32-unknown-unknown`.
//!
//! The instance map (used only by the arkworks generator, never by a snarkjs
//! ceremony) and the verifier are identical to the stock reduction: the
//! pairing equation does not depend on how `H` was produced.

use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{evaluate_constraint, LibsnarkReduction, R1CSToQAP};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystemRef, SynthesisError};

/// QAP witness map used by circom/snarkjs (`H` over the extended domain).
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];
        for (i, (at_i, bt_i)) in matrices.a.iter().zip(&matrices.b).enumerate() {
            a[i] = evaluate_constraint(at_i, full_assignment);
            b[i] = evaluate_constraint(bt_i, full_assignment);
        }

        // snarkjs appends one `input_i * 0 = 0` constraint per instance
        // variable (including the constant one); only the A side is non-zero.
        a[num_constraints..num_constraints + num_inputs]
            .clone_from_slice(&full_assignment[..num_inputs]);

        let mut c = vec![zero; domain_size];
        for (c_i, (a_i, b_i)) in c[..num_constraints].iter_mut().zip(a.iter().zip(&b)) {
            *c_i = *a_i * *b_i;
        }

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        // Primitive 2n-th root of unity: evaluating at its odd powers is the
        // coset FFT with offset `w_2n`.
        let root_of_unity = {
            let domain_double =
                D::new(2 * domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            domain_double.element(1)
        };
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        for (ab_i, c_i) in ab.iter_mut().zip(c) {
            *ab_i -= c_i;
        }

        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // The usual H query has `domain - 1` powers; `Z` has `domain` powers,
        // so `H * Z` has `2 * domain - 1` of them.
        Ok((0..=max_power)
            .map(|i| zt * delta_inverse * t.pow([i as u64]))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{snarkjs_layout_setup, Product};
    use ark_bn254::{Bn254, Fr};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn circom_reduction_matches_the_snarkjs_h_query_layout() {
        let mut rng = StdRng::seed_from_u64(7);
        let x = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        let z = x * y;
        let circuit = Product {
            x: Some(x),
            y: Some(y),
            z: Some(z),
        };
        let (pk, vk) = snarkjs_layout_setup(circuit.clone(), &mut rng);
        let proof =
            Groth16::<Bn254, CircomReduction>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        assert!(Groth16::<Bn254, CircomReduction>::verify(&vk, &[z], &proof).unwrap());
        assert!(
            !Groth16::<Bn254, CircomReduction>::verify(&vk, &[z + Fr::from(1u64)], &proof).unwrap()
        );
        // The stock reduction is a different QAP witness layout and must not verify.
        let stock = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        assert!(!Groth16::<Bn254>::verify(&vk, &[z], &stock).unwrap());
    }
}
