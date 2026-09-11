//! Groth16 instances/proofs and their *augmented relaxed* form (Definition 4 of the SnarkFold paper).
//!
//! The relation checked for an augmented relaxed pair (u, π) against a verifying key is
//!
//! ```text
//! e(A,B) · e(C,δ)^(−μ) · e(Σ aᵢ·Sᵢ, γ)^(−μ) · e(α,β)^(−μ²)  =  E · e(R,δ) · e(Σ tᵢ·Sᵢ, γ) · e(α,β)^κ
//! ```
//!
//! where `Sᵢ = vk.gamma_abc_g1[i]` and `a₀ = 1`. A plain Groth16 proof is the special case
//! μ = 1, E = 1, R = 0, t = 0, κ = 0.

use ark_bn254::Bn254;
use ark_ff::{One, Zero};
use ark_groth16::{Proof as Groth16Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Valid, Validate};
use ark_std::{
    io::{Read, Write},
    vec::Vec,
};

use crate::{FieldElement, SnarkFoldError, SnarkFoldResult, G1, G2, GT};

/// Regular Groth16 proof wrapper
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
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

/// Groth16 instance: the public inputs **without** the leading constant 1
/// (exactly what `ark_groth16::Groth16::verify` takes).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance {
    pub public_inputs: Vec<FieldElement>,
}

/// Augmented Relaxed Groth16 Instance (⃗a, μ, E, R, ⃗t, κ)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AugmentedRelaxedInstance {
    /// Public inputs vector ⃗a, including the leading 1 (length = vk.gamma_abc_g1.len())
    pub a_vec: Vec<FieldElement>,
    /// Scalar factor μ
    pub mu: FieldElement,
    /// Error term E ∈ GT (multiplicative identity when unrelaxed)
    pub error: GT,
    /// Accumulated term R ∈ G1
    pub r: G1,
    /// Accumulated vector ⃗t (same length as ⃗a)
    pub t_vec: Vec<FieldElement>,
    /// Accumulated scalar κ
    pub kappa: FieldElement,
}

impl AugmentedRelaxedInstance {
    /// Non-relaxed instance for a fresh Groth16 proof.
    pub fn from_instance(instance: &Instance) -> Self {
        let mut a_vec = Vec::with_capacity(instance.public_inputs.len() + 1);
        a_vec.push(FieldElement::one());
        a_vec.extend_from_slice(&instance.public_inputs);
        let len = a_vec.len();
        Self {
            a_vec,
            mu: FieldElement::one(),
            error: GT::one(),
            r: G1::zero(),
            t_vec: vec![FieldElement::zero(); len],
            kappa: FieldElement::zero(),
        }
    }

    /// The trivially satisfied, fully relaxed instance (μ = 0). Paired with the zero proof
    /// (A = B = C = 0) it satisfies the relation, so it is the correct accumulator start.
    pub fn zero(len: usize) -> Self {
        Self {
            a_vec: vec![FieldElement::zero(); len],
            mu: FieldElement::zero(),
            error: GT::one(),
            r: G1::zero(),
            t_vec: vec![FieldElement::zero(); len],
            kappa: FieldElement::zero(),
        }
    }

    pub fn len(&self) -> usize {
        self.a_vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.a_vec.is_empty()
    }

    /// True for an instance that is exactly a plain Groth16 instance.
    pub fn is_non_relaxed(&self) -> bool {
        self.mu.is_one()
            && self.error.is_one()
            && self.r.is_zero()
            && self.t_vec.iter().all(|t| t.is_zero())
            && self.kappa.is_zero()
    }
}

/// Augmented Relaxed Groth16 Proof (A, B, C)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AugmentedRelaxedProof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

impl AugmentedRelaxedProof {
    /// The zero proof, satisfying together with `AugmentedRelaxedInstance::zero`.
    pub fn zero() -> Self {
        Self {
            a: G1::zero(),
            b: G2::zero(),
            c: G1::zero(),
        }
    }
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

/// Cross terms (T', R, ⃗t, κ) from Equation (3)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CrossTerms {
    /// T' = e(A₁, B₂) · e(A₂, B₁)
    pub t_prime: GT,
    /// R = −(μ₂·C₁ + μ₁·C₂)
    pub r: G1,
    /// ⃗t = −(μ₂·⃗a₁ + μ₁·⃗a₂)
    pub t_vec: Vec<FieldElement>,
    /// κ = −2·μ₁·μ₂
    pub kappa: FieldElement,
}

/// Groth16 verification key wrapper
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// Length of ⃗a for this key (public inputs + 1).
    pub fn instance_len(&self) -> usize {
        self.gamma_abc_g1.len()
    }

    pub fn check_instance(&self, inst: &AugmentedRelaxedInstance) -> SnarkFoldResult<()> {
        if inst.a_vec.len() != self.instance_len() || inst.t_vec.len() != self.instance_len() {
            return Err(SnarkFoldError::InvalidInstance);
        }
        Ok(())
    }
}

impl Valid for GrothVerifyingKey {
    fn check(&self) -> core::result::Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for GrothVerifyingKey {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> core::result::Result<(), ark_serialize::SerializationError> {
        self.alpha_g1.serialize_with_mode(&mut writer, compress)?;
        self.beta_g2.serialize_with_mode(&mut writer, compress)?;
        self.gamma_g2.serialize_with_mode(&mut writer, compress)?;
        self.delta_g2.serialize_with_mode(&mut writer, compress)?;
        self.gamma_abc_g1.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.alpha_g1.serialized_size(compress)
            + self.beta_g2.serialized_size(compress)
            + self.gamma_g2.serialized_size(compress)
            + self.delta_g2.serialized_size(compress)
            + self.gamma_abc_g1.serialized_size(compress)
    }
}

impl CanonicalDeserialize for GrothVerifyingKey {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> core::result::Result<Self, ark_serialize::SerializationError> {
        Ok(Self {
            alpha_g1: G1::deserialize_with_mode(&mut reader, compress, validate)?,
            beta_g2: G2::deserialize_with_mode(&mut reader, compress, validate)?,
            gamma_g2: G2::deserialize_with_mode(&mut reader, compress, validate)?,
            delta_g2: G2::deserialize_with_mode(&mut reader, compress, validate)?,
            gamma_abc_g1: Vec::<G1>::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_instance_creation() {
        let instance = Instance {
            public_inputs: vec![FieldElement::from(1u64), FieldElement::from(2u64)],
        };

        let relaxed = AugmentedRelaxedInstance::from_instance(&instance);
        assert!(relaxed.is_non_relaxed());
        assert_eq!(relaxed.a_vec.len(), 3);
        assert!(relaxed.a_vec[0].is_one());
        assert!(!AugmentedRelaxedInstance::zero(3).is_non_relaxed());
    }

    #[test]
    fn test_proof_conversion_and_serialization() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let proof = Proof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };
        let relaxed: AugmentedRelaxedProof = proof.clone().into();
        assert!(!relaxed.a.is_zero());

        let mut bytes = vec![];
        proof.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(Proof::deserialize_compressed(&bytes[..]).unwrap(), proof);

        let inst = AugmentedRelaxedInstance::from_instance(&Instance {
            public_inputs: vec![FieldElement::rand(&mut rng)],
        });
        let mut bytes = vec![];
        inst.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(AugmentedRelaxedInstance::deserialize_compressed(&bytes[..]).unwrap(), inst);
    }
}
