//! SnarkFold-style aggregation of Groth16 proofs over BN254.
//!
//! See [`ivc`] for the aggregation API and its exact (non-)succinctness guarantees.

pub mod error;
pub mod folding;
pub mod groth16;
pub mod hash;
pub mod ivc;

pub use error::*;
pub use folding::*;
pub use groth16::*;
pub use hash::*;
pub use ivc::*;

// Re-export for convenience
pub use error::SnarkFoldResult as Result;

use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;

// Type aliases for BN254 curve
pub type FieldElement = Fr;
pub type G1 = G1Projective;
pub type G2 = G2Projective;
/// Target group element (Fq12); multiplicative, identity is `GT::one()`.
pub type GT = <Bn254 as Pairing>::TargetField;
