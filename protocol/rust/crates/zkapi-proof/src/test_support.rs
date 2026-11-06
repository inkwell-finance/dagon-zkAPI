//! Tiny circuit and snarkjs-layout setup shared by unit tests.

use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, UniformRand};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::lc;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
use ark_std::rand::rngs::StdRng;

/// `x * y = z` (`z` public) plus a chain of filler constraints so the domain
/// is non-trivial. Its R1CS shape does not depend on the assigned values.
#[derive(Clone)]
pub(crate) struct Product {
    pub x: Option<Fr>,
    pub y: Option<Fr>,
    pub z: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Product {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let z = cs.new_input_variable(|| self.z.ok_or(SynthesisError::AssignmentMissing))?;
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_witness_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        let mut previous = x;
        let mut value = self.x;
        for _ in 0..5 {
            value = value.zip(self.y).map(|(v, y)| v * y);
            let next =
                cs.new_witness_variable(|| value.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_constraint(lc!() + previous, lc!() + y, lc!() + next)?;
            previous = next;
        }
        cs.enforce_constraint(lc!() + x, lc!() + y, lc!() + z)?;
        Ok(())
    }
}

/// A snarkjs-layout Groth16 setup from explicit toxic waste: `gamma = 1` and
/// `H_i = [L^{2n}_{2i+1}(tau) / delta]_1` over the doubled domain, which is
/// what `snarkjs zkey new` writes.
pub(crate) fn snarkjs_layout_setup(
    circuit: Product,
    rng: &mut StdRng,
) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    type D = GeneralEvaluationDomain<Fr>;
    let (alpha, beta, delta, tau) = (Fr::rand(rng), Fr::rand(rng), Fr::rand(rng), Fr::rand(rng));
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let num_instance = cs.num_instance_variables();
    let (a, b, c, _zt, _vars, domain_size) =
        LibsnarkReduction::instance_map_with_evaluation::<Fr, D>(cs, &tau).unwrap();
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let delta_inv = delta.inverse().unwrap();
    let abc = |i: usize| beta * a[i] + alpha * b[i] + c[i];
    let doubled = D::new(2 * domain_size).unwrap();
    let lagrange = doubled.evaluate_all_lagrange_coefficients(tau);
    let vk = VerifyingKey::<Bn254> {
        alpha_g1: (g1 * alpha).into_affine(),
        beta_g2: (g2 * beta).into_affine(),
        gamma_g2: g2.into_affine(),
        delta_g2: (g2 * delta).into_affine(),
        gamma_abc_g1: (0..num_instance)
            .map(|i| (g1 * abc(i)).into_affine())
            .collect(),
    };
    let pk = ProvingKey::<Bn254> {
        vk: vk.clone(),
        beta_g1: (g1 * beta).into_affine(),
        delta_g1: (g1 * delta).into_affine(),
        a_query: a.iter().map(|v| (g1 * v).into_affine()).collect(),
        b_g1_query: b.iter().map(|v| (g1 * v).into_affine()).collect(),
        b_g2_query: b.iter().map(|v| (g2 * v).into_affine()).collect(),
        h_query: (0..domain_size)
            .map(|i| (g1 * (lagrange[2 * i + 1] * delta_inv)).into_affine())
            .collect(),
        l_query: (num_instance..a.len())
            .map(|i| (g1 * (abc(i) * delta_inv)).into_affine())
            .collect(),
    };
    (pk, vk)
}
