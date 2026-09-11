//! Folding scheme for augmented relaxed Groth16 (Section 4.1 of the paper).
//!
//! Given two satisfying pairs (u₁, π₁), (u₂, π₂) for the same verifying key, the prover
//! publishes cross terms T = (T', R, ⃗t, κ), both sides derive r = Hash(u₁, u₂, T), and the
//! folded pair
//!
//! ```text
//! ⃗a* = ⃗a₁ + r·⃗a₂        μ* = μ₁ + r·μ₂
//! E*  = E₁ · T'^r · E₂^(r²)    R* = R₁ + r·R + r²·R₂
//! ⃗t* = ⃗t₁ + r·⃗t + r²·⃗t₂    κ* = κ₁ + r·κ + r²·κ₂
//! A*  = A₁ + r·A₂    B* = B₁ + r·B₂    C* = C₁ + r·C₂
//! ```
//!
//! satisfies the relation again. The signs of the cross terms follow from expanding the
//! relation in `groth16.rs` with (⃗a*, μ*): R = −(μ₂C₁ + μ₁C₂), ⃗t = −(μ₂⃗a₁ + μ₁⃗a₂), κ = −2μ₁μ₂.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use sha3::{Digest, Keccak256};

use crate::{groth16::*, FieldElement, SnarkFoldError, SnarkFoldResult, G1};

pub struct AugmentedGroth16Folder;

impl AugmentedGroth16Folder {
    /// Cross terms (Equation 3).
    pub fn compute_cross_terms(
        proof1: &AugmentedRelaxedProof,
        inst1: &AugmentedRelaxedInstance,
        proof2: &AugmentedRelaxedProof,
        inst2: &AugmentedRelaxedInstance,
    ) -> SnarkFoldResult<CrossTerms> {
        let len = inst1.a_vec.len();
        if len != inst2.a_vec.len() || inst1.t_vec.len() != len || inst2.t_vec.len() != len {
            return Err(SnarkFoldError::FoldingError(
                "Instance vectors must have same length".to_string(),
            ));
        }

        // T' = e(A1, B2) · e(A2, B1)  (PairingOutput addition is GT multiplication)
        let t_prime = (Bn254::pairing(proof1.a, proof2.b) + Bn254::pairing(proof2.a, proof1.b)).0;

        // R = −(μ2·C1 + μ1·C2)
        let r = -(proof1.c * inst2.mu + proof2.c * inst1.mu);

        // ⃗t = −(μ2·⃗a1 + μ1·⃗a2)
        let t_vec = inst1
            .a_vec
            .iter()
            .zip(&inst2.a_vec)
            .map(|(a1, a2)| -(inst2.mu * a1 + inst1.mu * a2))
            .collect();

        // κ = −2·μ1·μ2
        let kappa = -(FieldElement::from(2u64) * inst1.mu * inst2.mu);

        Ok(CrossTerms { t_prime, r, t_vec, kappa })
    }

    /// Fold the two instances (what both prover and verifier compute).
    pub fn fold_instances(
        inst1: &AugmentedRelaxedInstance,
        inst2: &AugmentedRelaxedInstance,
        cross_terms: &CrossTerms,
        r: FieldElement,
    ) -> SnarkFoldResult<AugmentedRelaxedInstance> {
        let len = inst1.a_vec.len();
        if len != inst2.a_vec.len() || cross_terms.t_vec.len() != len {
            return Err(SnarkFoldError::FoldingError(
                "Instance vectors must have same length".to_string(),
            ));
        }
        let r2 = r * r;

        let a_vec = inst1.a_vec.iter().zip(&inst2.a_vec).map(|(x, y)| *x + r * y).collect();
        let mu = inst1.mu + r * inst2.mu;
        let error =
            inst1.error * cross_terms.t_prime.pow(r.into_bigint()) * inst2.error.pow(r2.into_bigint());
        let r_acc = inst1.r + cross_terms.r * r + inst2.r * r2;
        let t_vec = (0..len)
            .map(|i| inst1.t_vec[i] + r * cross_terms.t_vec[i] + r2 * inst2.t_vec[i])
            .collect();
        let kappa = inst1.kappa + r * cross_terms.kappa + r2 * inst2.kappa;

        Ok(AugmentedRelaxedInstance { a_vec, mu, error, r: r_acc, t_vec, kappa })
    }

    /// Fold the two proofs (prover only).
    pub fn fold_proofs(
        proof1: &AugmentedRelaxedProof,
        proof2: &AugmentedRelaxedProof,
        r: FieldElement,
    ) -> AugmentedRelaxedProof {
        AugmentedRelaxedProof {
            a: proof1.a + proof2.a * r,
            b: proof1.b + proof2.b * r,
            c: proof1.c + proof2.c * r,
        }
    }

    /// Prover's folding: instances and proofs.
    pub fn fold_prover(
        proof1: &AugmentedRelaxedProof,
        inst1: &AugmentedRelaxedInstance,
        proof2: &AugmentedRelaxedProof,
        inst2: &AugmentedRelaxedInstance,
        cross_terms: &CrossTerms,
        challenge: FieldElement,
    ) -> SnarkFoldResult<(AugmentedRelaxedInstance, AugmentedRelaxedProof)> {
        let inst = Self::fold_instances(inst1, inst2, cross_terms, challenge)?;
        Ok((inst, Self::fold_proofs(proof1, proof2, challenge)))
    }

    /// Verifier's folding (instances only).
    pub fn fold_verifier(
        inst1: &AugmentedRelaxedInstance,
        inst2: &AugmentedRelaxedInstance,
        cross_terms: &CrossTerms,
        challenge: FieldElement,
    ) -> SnarkFoldResult<AugmentedRelaxedInstance> {
        Self::fold_instances(inst1, inst2, cross_terms, challenge)
    }

    /// Fiat–Shamir challenge r = Hash(inst1, inst2, T).
    pub fn generate_challenge(
        inst1: &AugmentedRelaxedInstance,
        inst2: &AugmentedRelaxedInstance,
        cross_terms: &CrossTerms,
    ) -> SnarkFoldResult<FieldElement> {
        let mut data = Vec::new();
        let ser = |e: ark_serialize::SerializationError| SnarkFoldError::HashError(e.to_string());
        data.extend_from_slice(b"snarkfold-groth16-fold-v1");
        inst1.serialize_compressed(&mut data).map_err(ser)?;
        inst2.serialize_compressed(&mut data).map_err(ser)?;
        cross_terms.serialize_compressed(&mut data).map_err(ser)?;
        let digest = Keccak256::digest(&data);
        Ok(FieldElement::from_le_bytes_mod_order(&digest))
    }
}

/// Check the augmented relaxed relation for (u, π) against `vk` (3 pairings + 1 GT exponentiation).
pub fn verify_relaxed(
    proof: &AugmentedRelaxedProof,
    inst: &AugmentedRelaxedInstance,
    vk: &GrothVerifyingKey,
) -> SnarkFoldResult<bool> {
    vk.check_instance(inst)?;

    // H = Σ aᵢ·Sᵢ,  S = Σ tᵢ·Sᵢ
    let mut h = G1::default();
    let mut s = G1::default();
    for (i, base) in vk.gamma_abc_g1.iter().enumerate() {
        h += *base * inst.a_vec[i];
        s += *base * inst.t_vec[i];
    }

    // Move everything except E to the left:
    // e(A,B) · e(−μC − R, δ) · e(−μH − S, γ) · e(α,β)^(−μ² − κ) = E
    let neg_mu = -inst.mu;
    let lhs = Bn254::multi_pairing(
        [proof.a, proof.c * neg_mu - inst.r, h * neg_mu - s],
        [proof.b, vk.delta_g2, vk.gamma_g2],
    )
    .0;
    let d = Bn254::pairing(vk.alpha_g1, vk.beta_g2).0;
    let exp = -(inst.mu * inst.mu) - inst.kappa;
    Ok(lhs * d.pow(exp.into_bigint()) == inst.error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::G2;
    use ark_ff::One;
    use ark_std::{rand::SeedableRng, UniformRand};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_cross_terms_and_fold_shapes() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mk = |rng: &mut ChaCha20Rng| {
            (
                AugmentedRelaxedProof { a: G1::rand(rng), b: G2::rand(rng), c: G1::rand(rng) },
                AugmentedRelaxedInstance::from_instance(&Instance {
                    public_inputs: vec![FieldElement::rand(rng)],
                }),
            )
        };
        let (p1, u1) = mk(&mut rng);
        let (p2, u2) = mk(&mut rng);
        let ct = AugmentedGroth16Folder::compute_cross_terms(&p1, &u1, &p2, &u2).unwrap();
        assert_eq!(ct.t_vec.len(), 2);
        assert_eq!(ct.kappa, -FieldElement::from(2u64));
        let r = AugmentedGroth16Folder::generate_challenge(&u1, &u2, &ct).unwrap();
        let (fu, fp) = AugmentedGroth16Folder::fold_prover(&p1, &u1, &p2, &u2, &ct, r).unwrap();
        assert_eq!(fu.mu, FieldElement::one() + r);
        assert_eq!(fp.a, p1.a + p2.a * r);
        assert_eq!(AugmentedGroth16Folder::fold_verifier(&u1, &u2, &ct, r).unwrap(), fu);
    }

    #[test]
    fn test_length_mismatch_rejected() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let p = AugmentedRelaxedProof::zero();
        let u1 = AugmentedRelaxedInstance::from_instance(&Instance {
            public_inputs: vec![FieldElement::rand(&mut rng)],
        });
        let u2 = AugmentedRelaxedInstance::zero(5);
        assert!(AugmentedGroth16Folder::compute_cross_terms(&p, &u1, &p, &u2).is_err());
    }
}
