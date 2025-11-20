pub mod groth16;
pub mod ivc;
pub mod folding;
pub mod hash;
pub mod error;

pub use groth16::*;
pub use ivc::*;
pub use folding::*;
pub use hash::*;
pub use error::*;

// Re-export for convenience
pub use error::SnarkFoldResult as Result;

use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;

// Type aliases for BN254 curve
pub type FieldElement = Fr;
pub type G1 = G1Projective;
pub type G2 = G2Projective;
pub type GT = <Bn254 as Pairing>::TargetField;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
