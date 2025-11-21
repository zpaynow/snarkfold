use crate::{FieldElement, SnarkFoldError, SnarkFoldResult as Result};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha3::{Digest, Keccak256};

/// Hash function for SnarkFold (collision-resistant hash)
pub struct SnarkFoldHash;

impl SnarkFoldHash {
    /// Hash a single field element
    pub fn hash_one(input: &FieldElement) -> Result<FieldElement> {
        let mut hasher = Keccak256::new();
        let mut bytes = Vec::new();
        input
            .serialize_compressed(&mut bytes)
            .map_err(|e| SnarkFoldError::HashError(format!("Serialization failed: {}", e)))?;
        hasher.update(&bytes);
        let result = hasher.finalize();

        // Convert hash output to field element
        Ok(FieldElement::from_le_bytes_mod_order(&result))
    }

    /// Hash two elements together
    pub fn hash_two(a: &FieldElement, b: &FieldElement) -> Result<FieldElement> {
        let mut hasher = Keccak256::new();
        let mut bytes = Vec::new();

        a.serialize_compressed(&mut bytes)
            .map_err(|e| SnarkFoldError::HashError(format!("Serialization failed: {}", e)))?;
        b.serialize_compressed(&mut bytes)
            .map_err(|e| SnarkFoldError::HashError(format!("Serialization failed: {}", e)))?;

        hasher.update(&bytes);
        let result = hasher.finalize();

        Ok(FieldElement::from_le_bytes_mod_order(&result))
    }

    /// Hash multiple field elements
    pub fn hash_many(inputs: &[FieldElement]) -> Result<FieldElement> {
        let mut hasher = Keccak256::new();
        let mut bytes = Vec::new();

        for input in inputs {
            input
                .serialize_compressed(&mut bytes)
                .map_err(|e| SnarkFoldError::HashError(format!("Serialization failed: {}", e)))?;
        }

        hasher.update(&bytes);
        let result = hasher.finalize();

        Ok(FieldElement::from_le_bytes_mod_order(&result))
    }

    /// Hash with arbitrary serializable data
    pub fn hash_arbitrary<T: CanonicalSerialize>(data: &T) -> Result<FieldElement> {
        let mut hasher = Keccak256::new();
        let mut bytes = Vec::new();

        data.serialize_compressed(&mut bytes)
            .map_err(|e| SnarkFoldError::HashError(format!("Serialization failed: {}", e)))?;

        hasher.update(&bytes);
        let result = hasher.finalize();

        Ok(FieldElement::from_le_bytes_mod_order(&result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldElement;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_hash_one() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let elem = FieldElement::rand(&mut rng);
        let hash = SnarkFoldHash::hash_one(&elem).unwrap();
        assert_ne!(hash, FieldElement::from(0u64));
    }

    #[test]
    fn test_hash_two() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let a = FieldElement::rand(&mut rng);
        let b = FieldElement::rand(&mut rng);
        let hash = SnarkFoldHash::hash_two(&a, &b).unwrap();
        assert_ne!(hash, FieldElement::from(0u64));
    }
}
