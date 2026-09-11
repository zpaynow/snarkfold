//! Aggregate real Groth16 proofs of a toy circuit (c = a·b) and verify the aggregate.
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::SeedableRng, UniformRand};
use rand_chacha::ChaCha20Rng;
use snarkfold::*;
use std::time::Instant;

#[derive(Clone)]
struct Mul {
    a: Fr,
    b: Fr,
}

impl ConstraintSynthesizer<Fr> for Mul {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> core::result::Result<(), SynthesisError> {
        let c = FpVar::new_input(cs.clone(), || Ok(self.a * self.b))?;
        let a = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
        (a * b).enforce_equal(&c)
    }
}

fn main() -> Result<()> {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(64);
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Mul { a: Fr::from(1u64), b: Fr::from(1u64) }, &mut rng).unwrap();
    let gvk = GrothVerifyingKey::from_ark_vk(&vk);

    println!("proving {n} Groth16 proofs…");
    let batch: Vec<(Instance, Proof)> = (0..n)
        .map(|_| {
            let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let proof = Groth16::<Bn254>::prove(&pk, Mul { a, b }, &mut rng).unwrap();
            (Instance { public_inputs: vec![a * b] }, Proof::from(proof))
        })
        .collect();

    let t = Instant::now();
    for (u, p) in &batch {
        assert!(Groth16::<Bn254>::verify(&vk, &u.public_inputs, &ark_groth16::Proof { a: p.a.into(), b: p.b.into(), c: p.c.into() }).unwrap());
    }
    println!("individual verification: {:?}", t.elapsed());

    let t = Instant::now();
    let agg = aggregate(&gvk, &batch)?;
    println!("aggregation (prover):    {:?}", t.elapsed());

    let mut bytes = vec![];
    agg.serialize_compressed(&mut bytes).unwrap();
    println!("aggregated proof size:   {} bytes ({} per proof)", bytes.len(), bytes.len() / n);

    let t = Instant::now();
    let ok = verify_aggregated(&gvk, &agg)?;
    println!("aggregated verification: {:?} -> {ok}", t.elapsed());
    assert!(ok);
    Ok(())
}
