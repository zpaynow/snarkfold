use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;

use crate::{
    groth16::*,
    FieldElement, SnarkFoldResult as Result, SnarkFoldError,
};

/// Augmented Relaxed Groth16 Folding Scheme
/// Implements the protocol from Section 4.1 of the paper
pub struct AugmentedGroth16Folder;

impl AugmentedGroth16Folder {
    /// Compute cross terms (Equation 3 from paper)
    /// T = (T', R, ⃗t, κ) where:
    /// - T' = e(A1, B2) · e(A2, B1)
    /// - R = C1^(-μ2) · C2^(-μ1)
    /// - ⃗t = μ2⃗a1 + μ1⃗a2
    /// - κ = -2μ1μ2
    pub fn compute_cross_terms(
        proof1: &AugmentedRelaxedProof,
        inst1: &AugmentedRelaxedInstance,
        proof2: &AugmentedRelaxedProof,
        inst2: &AugmentedRelaxedInstance,
    ) -> Result<CrossTerms> {
        // Compute T' = e(A1, B2) · e(A2, B1)
        let pairing1 = Bn254::pairing(proof1.a, proof2.b);
        let pairing2 = Bn254::pairing(proof2.a, proof1.b);
        let t_prime_gt = pairing1 + pairing2;

        let mut t_prime_bytes = Vec::new();
        t_prime_gt.serialize_compressed(&mut t_prime_bytes)
            .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;

        // Compute R = C1^(-μ2) · C2^(-μ1)
        let neg_mu2 = -inst2.mu;
        let neg_mu1 = -inst1.mu;
        let r = (proof1.c * neg_mu2) + (proof2.c * neg_mu1);

        // Compute ⃗t = μ2⃗a1 + μ1⃗a2
        let len = inst1.a_vec.len();
        if len != inst2.a_vec.len() {
            return Err(SnarkFoldError::FoldingError(
                "Instance vectors must have same length".to_string()
            ));
        }

        let mut t_vec = Vec::with_capacity(len);
        for i in 0..len {
            let t_i = inst2.mu * inst1.a_vec[i] + inst1.mu * inst2.a_vec[i];
            t_vec.push(t_i);
        }

        // Compute κ = -2μ1μ2
        let kappa = -FieldElement::from(2u64) * inst1.mu * inst2.mu;

        Ok(CrossTerms {
            t_prime: t_prime_bytes,
            r,
            t_vec,
            kappa,
        })
    }

    /// Prover's folding operation (Equation 4 from paper)
    /// Folds two instance-proof pairs into one
    pub fn fold_prover(
        proof1: &AugmentedRelaxedProof,
        inst1: &AugmentedRelaxedInstance,
        proof2: &AugmentedRelaxedProof,
        inst2: &AugmentedRelaxedInstance,
        cross_terms: &CrossTerms,
        challenge: FieldElement,
    ) -> Result<(AugmentedRelaxedInstance, AugmentedRelaxedProof)> {
        let r = challenge;
        let r_squared = r * r;

        // Fold instance: (⃗a*, μ*, E*, R*, ⃗t*, κ*)

        // ⃗a* = ⃗a1 + r · ⃗a2
        let len = inst1.a_vec.len();
        let mut a_vec_star = Vec::with_capacity(len);
        for i in 0..len {
            a_vec_star.push(inst1.a_vec[i] + r * inst2.a_vec[i]);
        }

        // μ* = μ1 + r · μ2
        let mu_star = inst1.mu + r * inst2.mu;

        // E* = E1 · (T')^r · (E2)^(r²)
        // For now we'll handle this symbolically since GT operations are expensive
        let error_gt_star = Vec::new(); // TODO: Implement proper GT accumulation

        // R* = R1 · R^r · (R2)^(r²)
        let r_star = inst1.r + (cross_terms.r * r) + (inst2.r * r_squared);

        // ⃗t* = ⃗t1 + r·⃗t + r²·⃗t2
        let mut t_vec_star = Vec::with_capacity(len);
        for i in 0..len {
            t_vec_star.push(
                inst1.t_vec[i] + r * cross_terms.t_vec[i] + r_squared * inst2.t_vec[i]
            );
        }

        // κ* = κ1 + r·κ + r²·κ2
        let kappa_star = inst1.kappa + r * cross_terms.kappa + r_squared * inst2.kappa;

        let folded_instance = AugmentedRelaxedInstance {
            a_vec: a_vec_star,
            mu: mu_star,
            error_gt: error_gt_star,
            r: r_star,
            t_vec: t_vec_star,
            kappa: kappa_star,
        };

        // Fold proof: (A*, B*, C*)
        // A* = A1 · A2^r
        let a_star = proof1.a + (proof2.a * r);

        // B* = B1 · B2^r
        let b_star = proof1.b + (proof2.b * r);

        // C* = C1 · C2^r
        let c_star = proof1.c + (proof2.c * r);

        let folded_proof = AugmentedRelaxedProof {
            a: a_star,
            b: b_star,
            c: c_star,
        };

        Ok((folded_instance, folded_proof))
    }

    /// Verifier's folding operation
    /// Only computes the folded instance (verifier doesn't need the proof)
    pub fn fold_verifier(
        inst1: &AugmentedRelaxedInstance,
        inst2: &AugmentedRelaxedInstance,
        cross_terms: &CrossTerms,
        challenge: FieldElement,
    ) -> Result<AugmentedRelaxedInstance> {
        let r = challenge;
        let r_squared = r * r;

        let len = inst1.a_vec.len();
        let mut a_vec_star = Vec::with_capacity(len);
        for i in 0..len {
            a_vec_star.push(inst1.a_vec[i] + r * inst2.a_vec[i]);
        }

        let mu_star = inst1.mu + r * inst2.mu;
        let r_star = inst1.r + (cross_terms.r * r) + (inst2.r * r_squared);

        let mut t_vec_star = Vec::with_capacity(len);
        for i in 0..len {
            t_vec_star.push(
                inst1.t_vec[i] + r * cross_terms.t_vec[i] + r_squared * inst2.t_vec[i]
            );
        }

        let kappa_star = inst1.kappa + r * cross_terms.kappa + r_squared * inst2.kappa;

        Ok(AugmentedRelaxedInstance {
            a_vec: a_vec_star,
            mu: mu_star,
            error_gt: Vec::new(),
            r: r_star,
            t_vec: t_vec_star,
            kappa: kappa_star,
        })
    }

    /// Generate Fiat-Shamir challenge for non-interactive folding
    pub fn generate_challenge(
        inst1: &AugmentedRelaxedInstance,
        inst2: &AugmentedRelaxedInstance,
        cross_terms: &CrossTerms,
    ) -> Result<FieldElement> {
        // Hash all public data to generate challenge
        let mut data_to_hash = Vec::new();

        // Serialize instances
        inst1.serialize_compressed(&mut data_to_hash)
            .map_err(|e| SnarkFoldError::HashError(e.to_string()))?;
        inst2.serialize_compressed(&mut data_to_hash)
            .map_err(|e| SnarkFoldError::HashError(e.to_string()))?;

        // Serialize cross terms
        data_to_hash.extend_from_slice(&cross_terms.t_prime);
        cross_terms.r.serialize_compressed(&mut data_to_hash)
            .map_err(|e| SnarkFoldError::HashError(e.to_string()))?;

        for t in &cross_terms.t_vec {
            t.serialize_compressed(&mut data_to_hash)
                .map_err(|e| SnarkFoldError::HashError(e.to_string()))?;
        }

        cross_terms.kappa.serialize_compressed(&mut data_to_hash)
            .map_err(|e| SnarkFoldError::HashError(e.to_string()))?;

        // Hash to field element
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data_to_hash);
        let hash_result = hasher.finalize();

        Ok(FieldElement::from_le_bytes_mod_order(&hash_result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G1, G2, FieldElement};
    use rand_chacha::ChaCha20Rng;
    use ark_std::{rand::SeedableRng, UniformRand, Zero, One};

    #[test]
    fn test_cross_terms_computation() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let proof1 = AugmentedRelaxedProof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };

        let inst1 = AugmentedRelaxedInstance {
            a_vec: vec![FieldElement::rand(&mut rng), FieldElement::rand(&mut rng)],
            mu: FieldElement::one(),
            error_gt: vec![],
            r: G1::zero(),
            t_vec: vec![FieldElement::zero(), FieldElement::zero()],
            kappa: FieldElement::zero(),
        };

        let proof2 = AugmentedRelaxedProof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };

        let inst2 = AugmentedRelaxedInstance {
            a_vec: vec![FieldElement::rand(&mut rng), FieldElement::rand(&mut rng)],
            mu: FieldElement::one(),
            error_gt: vec![],
            r: G1::zero(),
            t_vec: vec![FieldElement::zero(), FieldElement::zero()],
            kappa: FieldElement::zero(),
        };

        let cross_terms = AugmentedGroth16Folder::compute_cross_terms(
            &proof1, &inst1, &proof2, &inst2
        ).unwrap();

        assert_eq!(cross_terms.t_vec.len(), 2);
    }

    #[test]
    fn test_folding() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let proof1 = AugmentedRelaxedProof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };

        let inst1 = AugmentedRelaxedInstance {
            a_vec: vec![FieldElement::rand(&mut rng)],
            mu: FieldElement::one(),
            error_gt: vec![],
            r: G1::zero(),
            t_vec: vec![FieldElement::zero()],
            kappa: FieldElement::zero(),
        };

        let proof2 = AugmentedRelaxedProof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };

        let inst2 = AugmentedRelaxedInstance {
            a_vec: vec![FieldElement::rand(&mut rng)],
            mu: FieldElement::one(),
            error_gt: vec![],
            r: G1::zero(),
            t_vec: vec![FieldElement::zero()],
            kappa: FieldElement::zero(),
        };

        let cross_terms = AugmentedGroth16Folder::compute_cross_terms(
            &proof1, &inst1, &proof2, &inst2
        ).unwrap();

        let challenge = FieldElement::rand(&mut rng);

        let (folded_inst, folded_proof) = AugmentedGroth16Folder::fold_prover(
            &proof1, &inst1, &proof2, &inst2, &cross_terms, challenge
        ).unwrap();

        assert!(!folded_proof.a.is_zero());
        assert_eq!(folded_inst.a_vec.len(), 1);
    }
}
