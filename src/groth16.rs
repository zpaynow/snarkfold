use ark_bn254::Bn254;
use ark_groth16::{Proof as Groth16Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::{vec::Vec, Zero};

use crate::{FieldElement, G1, G2, SnarkFoldResult as Result, SnarkFoldError};

/// Regular Groth16 proof wrapper
#[derive(Clone, Debug)]
pub struct Proof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

impl From<Groth16Proof<Bn254>> for Proof {
    fn from(proof: Groth16Proof<Bn254>) -> Self {
        Self {
            a: proof.a.into(),
            b: proof.b.into(),
            c: proof.c.into(),
        }
    }
}

/// Groth16 instance (public inputs)
#[derive(Clone, Debug)]
pub struct Instance {
    pub public_inputs: Vec<FieldElement>,
}

/// Augmented Relaxed Groth16 Instance (Definition 4 from the paper)
/// Represents: (a_vec, μ, E, R, t_vec, κ)
#[derive(Clone, Debug)]
pub struct AugmentedRelaxedInstance {
    /// Public inputs vector ⃗a
    pub a_vec: Vec<FieldElement>,
    /// Scalar factor μ
    pub mu: FieldElement,
    /// Error term E ∈ GT
    pub error_gt: Vec<u8>, // Serialized GT element
    /// Accumulated term R ∈ G1
    pub r: G1,
    /// Accumulated vector ⃗t
    pub t_vec: Vec<FieldElement>,
    /// Accumulated scalar κ
    pub kappa: FieldElement,
}

impl AugmentedRelaxedInstance {
    /// Create a new non-relaxed instance from regular Groth16 instance
    pub fn from_instance(instance: &Instance) -> Self {
        let len = instance.public_inputs.len();
        Self {
            a_vec: instance.public_inputs.clone(),
            mu: FieldElement::from(1u64),
            error_gt: vec![], // Represents [0]_T
            r: G1::zero(),    // [0]_1
            t_vec: vec![FieldElement::from(0u64); len],
            kappa: FieldElement::from(0u64),
        }
    }

    /// Check if this is a non-relaxed instance
    pub fn is_non_relaxed(&self) -> bool {
        self.mu == FieldElement::from(1u64)
            && self.error_gt.is_empty()
            && self.r.is_zero()
            && self.t_vec.iter().all(|&t| t == FieldElement::from(0u64))
            && self.kappa == FieldElement::from(0u64)
    }

    /// Serialize to bytes for hashing
    pub fn serialize_compressed(&self, mut writer: impl ark_std::io::Write) -> Result<()> {
        // Serialize a_vec
        (self.a_vec.len() as u32).serialize_compressed(&mut writer)
            .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;
        for a in &self.a_vec {
            a.serialize_compressed(&mut writer)
                .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;
        }

        // Serialize mu
        self.mu.serialize_compressed(&mut writer)
            .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;

        // Serialize error_gt
        writer.write_all(&self.error_gt)
            .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;

        // Serialize r
        self.r.serialize_compressed(&mut writer)
            .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;

        // Serialize t_vec
        (self.t_vec.len() as u32).serialize_compressed(&mut writer)
            .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;
        for t in &self.t_vec {
            t.serialize_compressed(&mut writer)
                .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;
        }

        // Serialize kappa
        self.kappa.serialize_compressed(&mut writer)
            .map_err(|e| SnarkFoldError::SerializationError(e.to_string()))?;

        Ok(())
    }
}

/// Augmented Relaxed Groth16 Proof
#[derive(Clone, Debug)]
pub struct AugmentedRelaxedProof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

impl From<Proof> for AugmentedRelaxedProof {
    fn from(proof: Proof) -> Self {
        Self {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        }
    }
}

/// Cross terms for folding (T', R, ⃗t, κ) from Equation (3)
#[derive(Clone, Debug)]
pub struct CrossTerms {
    /// T' = e(A1, B2) · e(A2, B1)
    pub t_prime: Vec<u8>, // Serialized GT element
    /// R = C1^(-μ2) · C2^(-μ1)
    pub r: G1,
    /// ⃗t = μ2⃗a1 + μ1⃗a2
    pub t_vec: Vec<FieldElement>,
    /// κ = -2μ1μ2
    pub kappa: FieldElement,
}

/// Groth16 verification key wrapper
#[derive(Clone, Debug)]
pub struct GrothVerifyingKey {
    pub alpha_g1: G1,
    pub beta_g2: G2,
    pub gamma_g2: G2,
    pub delta_g2: G2,
    pub gamma_abc_g1: Vec<G1>,
}

impl GrothVerifyingKey {
    pub fn from_ark_vk(vk: &VerifyingKey<Bn254>) -> Self {
        Self {
            alpha_g1: vk.alpha_g1.into(),
            beta_g2: vk.beta_g2.into(),
            gamma_g2: vk.gamma_g2.into(),
            delta_g2: vk.delta_g2.into(),
            gamma_abc_g1: vk.gamma_abc_g1.iter().map(|p| (*p).into()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G1, G2, FieldElement};
    use ark_std::{UniformRand, Zero};
    use rand_chacha::ChaCha20Rng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_instance_creation() {
        let instance = Instance {
            public_inputs: vec![FieldElement::from(1u64), FieldElement::from(2u64)],
        };

        let relaxed = AugmentedRelaxedInstance::from_instance(&instance);
        assert!(relaxed.is_non_relaxed());
        assert_eq!(relaxed.a_vec.len(), 2);
    }

    #[test]
    fn test_proof_conversion() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let proof = Proof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };

        let relaxed_proof: AugmentedRelaxedProof = proof.into();
        assert!(!relaxed_proof.a.is_zero());
    }
}
