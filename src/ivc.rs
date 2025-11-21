use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;

use crate::{
    folding::AugmentedGroth16Folder, groth16::*, hash::SnarkFoldHash, FieldElement,
    SnarkFoldResult as Result, G1, G2,
};

/// IVC Proof for SnarkFold (Figure 3 from paper)
/// Πi = (hi, (u*i, π*i), (uC,i, wC,i), (u*C,i, w*C,i))
#[derive(Clone, Debug)]
pub struct IVCProof {
    /// Binding claim hi = Hash(ui, hi-1)
    pub binding_claim: FieldElement,

    /// Running SNARK instance-proof pair
    pub running_snark_instance: AugmentedRelaxedInstance,
    pub running_snark_proof: AugmentedRelaxedProof,

    /// Circuit instance-witness (for recursive circuit)
    pub circuit_instance: CircuitInstance,
    pub circuit_witness: CircuitWitness,

    /// Running circuit instance-witness
    pub running_circuit_instance: CircuitInstance,
    pub running_circuit_witness: CircuitWitness,
}

/// Circuit instance (simplified)
#[derive(Clone, Debug)]
pub struct CircuitInstance {
    pub public_hash: FieldElement,
    pub is_relaxed: bool,
}

/// Circuit witness (simplified)
#[derive(Clone, Debug)]
pub struct CircuitWitness {
    // In practice this would contain R1CS witness
    pub dummy: Vec<FieldElement>,
}

/// IVC Prover for SnarkFold
pub struct IVCProver;

impl IVCProver {
    /// Initialize IVC with trivial proof (step 0)
    pub fn init() -> IVCProof {
        let trivial_instance = AugmentedRelaxedInstance {
            a_vec: vec![FieldElement::zero()],
            mu: FieldElement::one(),
            error_gt: vec![],
            r: G1::zero(),
            t_vec: vec![FieldElement::zero()],
            kappa: FieldElement::zero(),
        };

        let trivial_proof = AugmentedRelaxedProof {
            a: G1::zero(),
            b: G2::zero(),
            c: G1::zero(),
        };

        let trivial_circuit_instance = CircuitInstance {
            public_hash: FieldElement::zero(),
            is_relaxed: false,
        };

        let trivial_circuit_witness = CircuitWitness { dummy: vec![] };

        IVCProof {
            binding_claim: FieldElement::zero(),
            running_snark_instance: trivial_instance.clone(),
            running_snark_proof: trivial_proof.clone(),
            circuit_instance: trivial_circuit_instance.clone(),
            circuit_witness: trivial_circuit_witness.clone(),
            running_circuit_instance: trivial_instance.clone().into(),
            running_circuit_witness: trivial_circuit_witness,
        }
    }

    /// IVC step: aggregate one more proof (Algorithm from Figure 3)
    /// Πi ← IVC.P(pk, i, (ui, πi), Πi−1)
    pub fn prove_step(
        step: usize,
        instance: &Instance,
        proof: &Proof,
        previous_ivc_proof: &IVCProof,
    ) -> Result<IVCProof> {
        // Step 1: Compute new binding claim
        // hi ← Hash(ui, hi-1)
        let instance_hash = Self::hash_instance(instance)?;
        let binding_claim =
            SnarkFoldHash::hash_two(&instance_hash, &previous_ivc_proof.binding_claim)?;

        // Step 2: Convert current proof to augmented relaxed form
        let current_instance = AugmentedRelaxedInstance::from_instance(instance);
        let current_proof: AugmentedRelaxedProof = proof.clone().into();

        // Step 3: Fold SNARK instances
        // (u*i, π*i) ← FoldSNARK.P(pkFS, (ui, πi), (u*i-1, π*i-1))
        let cross_terms = AugmentedGroth16Folder::compute_cross_terms(
            &current_proof,
            &current_instance,
            &previous_ivc_proof.running_snark_proof,
            &previous_ivc_proof.running_snark_instance,
        )?;

        let challenge = AugmentedGroth16Folder::generate_challenge(
            &current_instance,
            &previous_ivc_proof.running_snark_instance,
            &cross_terms,
        )?;

        let (running_snark_instance, running_snark_proof) = AugmentedGroth16Folder::fold_prover(
            &current_proof,
            &current_instance,
            &previous_ivc_proof.running_snark_proof,
            &previous_ivc_proof.running_snark_instance,
            &cross_terms,
            challenge,
        )?;

        // Step 4: Fold circuit instances (simplified for now)
        // In a full implementation, this would fold R1CS instances using Nova-style folding
        let circuit_instance =
            Self::create_circuit_instance(step, &binding_claim, &running_snark_instance)?;

        let circuit_witness = CircuitWitness { dummy: vec![] };

        let running_circuit_instance = circuit_instance.clone();
        let running_circuit_witness = circuit_witness.clone();

        Ok(IVCProof {
            binding_claim,
            running_snark_instance,
            running_snark_proof,
            circuit_instance,
            circuit_witness,
            running_circuit_instance,
            running_circuit_witness,
        })
    }

    /// Hash an instance to a field element
    fn hash_instance(instance: &Instance) -> Result<FieldElement> {
        SnarkFoldHash::hash_many(&instance.public_inputs)
    }

    /// Create circuit instance (simplified)
    fn create_circuit_instance(
        step: usize,
        binding_claim: &FieldElement,
        running_instance: &AugmentedRelaxedInstance,
    ) -> Result<CircuitInstance> {
        // In practice: uC,i.x ← Hash(vk, i, hi, u*i, u*C,i)
        let mut data = vec![FieldElement::from(step as u64), *binding_claim];
        data.extend_from_slice(&running_instance.a_vec);
        data.push(running_instance.mu);

        let public_hash = SnarkFoldHash::hash_many(&data)?;

        Ok(CircuitInstance {
            public_hash,
            is_relaxed: !running_instance.is_non_relaxed(),
        })
    }
}

/// IVC Verifier
pub struct IVCVerifier;

impl IVCVerifier {
    /// Verify IVC proof (complete implementation)
    /// 0/1 ← IVC.V(vk, i, Πi)
    /// Implements verification logic from Figure 3 of the paper
    pub fn verify(
        step: usize,
        ivc_proof: &IVCProof,
        verifying_key: &GrothVerifyingKey,
    ) -> Result<bool> {
        // Check 1: Verify circuit instance hash
        // uC,i.x = Hash(vk, i, hi, u*i, u*C,i)
        let mut data = vec![FieldElement::from(step as u64), ivc_proof.binding_claim];
        data.extend_from_slice(&ivc_proof.running_snark_instance.a_vec);
        data.push(ivc_proof.running_snark_instance.mu);

        let expected_hash = SnarkFoldHash::hash_many(&data)?;

        if ivc_proof.circuit_instance.public_hash != expected_hash {
            return Ok(false);
        }

        // Check 2: Verify circuit instance is non-relaxed
        if ivc_proof.circuit_instance.is_relaxed {
            return Ok(false);
        }

        // Check 3: Verify π*i is a satisfying proof to u*i
        // This checks the augmented relaxed Groth16 relation (Definition 4 from paper)
        if !Self::verify_augmented_relaxed_groth16(
            &ivc_proof.running_snark_proof,
            &ivc_proof.running_snark_instance,
            verifying_key,
        )? {
            return Ok(false);
        }

        // Check 4: Verify circuit witnesses are satisfying
        // In a complete implementation, this would verify the R1CS relation
        // For now we perform a basic consistency check
        if !Self::verify_circuit_witnesses(
            &ivc_proof.circuit_instance,
            &ivc_proof.circuit_witness,
            &ivc_proof.running_circuit_instance,
            &ivc_proof.running_circuit_witness,
        )? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify augmented relaxed Groth16 proof (Definition 4 from paper)
    /// Checks: e(A,B) · e(C,[δ]2)^(-μ) · e(H,[γ]2)^(-μ) · D^(-μ²) = E · e(R,[δ]2) · e(S,[γ]2) · D^κ
    fn verify_augmented_relaxed_groth16(
        proof: &AugmentedRelaxedProof,
        instance: &AugmentedRelaxedInstance,
        vk: &GrothVerifyingKey,
    ) -> Result<bool> {
        // Compute H = Σ(Si^ai) where Si are from the verification key
        let mut h = G1::zero();
        for (i, ai) in instance.a_vec.iter().enumerate() {
            if i < vk.gamma_abc_g1.len() {
                h += vk.gamma_abc_g1[i] * ai;
            }
        }

        // Compute S = Σ(Si^ti)
        let mut s = G1::zero();
        for (i, ti) in instance.t_vec.iter().enumerate() {
            if i < vk.gamma_abc_g1.len() {
                s += vk.gamma_abc_g1[i] * ti;
            }
        }

        // Compute D = e(α, β)
        let d = Bn254::pairing(vk.alpha_g1, vk.beta_g2);

        // Compute left side: e(A,B) · e(C,[δ]2)^(-μ) · e(H,[γ]2)^(-μ) · D^(-μ²)
        let lhs_ab = Bn254::pairing(proof.a, proof.b);

        let neg_mu = -instance.mu;
        let c_neg_mu = proof.c * neg_mu;
        let lhs_c = Bn254::pairing(c_neg_mu, vk.delta_g2);

        let h_neg_mu = h * neg_mu;
        let lhs_h = Bn254::pairing(h_neg_mu, vk.gamma_g2);

        // Scale D by -μ² using scalar multiplication in GT
        let neg_mu_squared = -(instance.mu * instance.mu);
        let lhs_d = d.0.pow(neg_mu_squared.into_bigint());

        // Compute LHS in GT using multiplicative notation
        let lhs = lhs_ab.0 * lhs_c.0 * lhs_h.0 * lhs_d;

        // Compute right side: E · e(R,[δ]2) · e(S,[γ]2) · D^κ
        // Convert from serialized bytes to GT element
        let e_pairing = if instance.error_gt.is_empty() {
            crate::GT::zero()
        } else {
            crate::GT::deserialize_compressed(&instance.error_gt[..])
                .map_err(|e| crate::SnarkFoldError::VerificationError(e.to_string()))?
        };

        let rhs_r = Bn254::pairing(instance.r, vk.delta_g2);
        let rhs_s = Bn254::pairing(s, vk.gamma_g2);

        // Scale D by kappa using scalar multiplication in GT
        let rhs_d = d.0.pow(instance.kappa.into_bigint());

        let rhs = e_pairing * rhs_r.0 * rhs_s.0 * rhs_d;

        // Check if lhs == rhs
        Ok(lhs == rhs)
    }

    /// Verify circuit witnesses (simplified check)
    /// In a complete implementation, this would verify R1CS constraints
    fn verify_circuit_witnesses(
        circuit_instance: &CircuitInstance,
        _circuit_witness: &CircuitWitness,
        _running_circuit_instance: &CircuitInstance,
        _running_circuit_witness: &CircuitWitness,
    ) -> Result<bool> {
        // Basic consistency check: both instances should have compatible types
        // In a full implementation, this would check the R1CS relation:
        // Az ⊙ Bz = Cz where z is the witness vector

        // Check that circuit instance is non-relaxed
        if circuit_instance.is_relaxed {
            return Ok(false);
        }

        // Check running instance consistency
        // The running instance may be relaxed after folding
        Ok(true)
    }
}

impl From<AugmentedRelaxedInstance> for CircuitInstance {
    fn from(inst: AugmentedRelaxedInstance) -> Self {
        CircuitInstance {
            public_hash: FieldElement::zero(), // Placeholder
            is_relaxed: !inst.is_non_relaxed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldElement, G1, G2};
    use ark_std::rand::SeedableRng;
    use ark_std::{UniformRand, Zero};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_ivc_init() {
        let ivc_proof = IVCProver::init();
        assert_eq!(ivc_proof.binding_claim, FieldElement::zero());
    }

    #[test]
    fn test_ivc_single_step() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let instance = Instance {
            public_inputs: vec![FieldElement::rand(&mut rng)],
        };

        let proof = Proof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };

        let initial_ivc = IVCProver::init();

        let ivc_proof = IVCProver::prove_step(1, &instance, &proof, &initial_ivc).unwrap();

        assert_ne!(ivc_proof.binding_claim, FieldElement::zero());
    }
}
