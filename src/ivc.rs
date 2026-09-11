//! Incremental aggregation of Groth16 proofs for one verifying key.
//!
//! `Aggregator` folds proofs one by one into a single augmented relaxed pair. The resulting
//! [`AggregatedProof`] carries the per-step transcript (instance + cross terms), so a verifier
//! can re-derive every Fiat–Shamir challenge, re-fold the *instances* (no pairings, only GT
//! exponentiations and G1 scalar multiplications) and then check the final relaxed relation
//! with 3 pairings.
//!
//! What this is and is not:
//! - Verifying `n` aggregated proofs costs `n` instance folds + 3 pairings instead of `4n`
//!   pairings, and the pairing work no longer grows with `n`.
//! - The paper's O(1) verifier additionally needs the IVC circuit that proves the folding was
//!   done correctly. That circuit is **not** implemented here; the `binding_claim`
//!   (hᵢ = Hash(uᵢ, hᵢ₋₁)) is kept so the transcript commits to the instance sequence, but it
//!   provides no succinctness on its own.
//! - Everything folded must share one verifying key (⃗a is combined against `gamma_abc_g1`).

use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

use crate::{
    folding::{verify_relaxed, AugmentedGroth16Folder},
    groth16::*,
    hash::SnarkFoldHash,
    FieldElement, SnarkFoldError, SnarkFoldResult,
};

/// One folding step as seen by the verifier.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FoldStep {
    pub instance: Instance,
    pub cross_terms: CrossTerms,
}

/// Aggregated proof for `steps.len()` Groth16 proofs under one verifying key.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AggregatedProof {
    pub steps: Vec<FoldStep>,
    /// hₙ = Hash(uₙ, Hash(uₙ₋₁, … Hash(u₁, 0)))
    pub binding_claim: FieldElement,
    pub instance: AugmentedRelaxedInstance,
    pub proof: AugmentedRelaxedProof,
}

impl AggregatedProof {
    pub fn num_proofs(&self) -> usize {
        self.steps.len()
    }

    /// Public inputs of every folded proof, in order (what a contract needs to apply state).
    pub fn instances(&self) -> impl Iterator<Item = &Instance> {
        self.steps.iter().map(|s| &s.instance)
    }
}

/// Incremental prover state.
#[derive(Clone, Debug)]
pub struct Aggregator {
    len: usize,
    steps: Vec<FoldStep>,
    binding_claim: FieldElement,
    instance: AugmentedRelaxedInstance,
    proof: AugmentedRelaxedProof,
}

impl Aggregator {
    /// `vk` fixes the instance length; every pushed proof must be for this key.
    pub fn new(vk: &GrothVerifyingKey) -> Self {
        let len = vk.instance_len();
        Self {
            len,
            steps: Vec::new(),
            binding_claim: FieldElement::zero(),
            instance: AugmentedRelaxedInstance::zero(len),
            proof: AugmentedRelaxedProof::zero(),
        }
    }

    pub fn num_proofs(&self) -> usize {
        self.steps.len()
    }

    /// Fold one more (instance, proof). The caller is expected to have verified the Groth16
    /// proof already (an invalid proof makes the whole batch fail verification).
    pub fn push(&mut self, instance: &Instance, proof: &Proof) -> SnarkFoldResult<()> {
        if instance.public_inputs.len() + 1 != self.len {
            return Err(SnarkFoldError::InvalidInstance);
        }
        let fresh_inst = AugmentedRelaxedInstance::from_instance(instance);
        let fresh_proof: AugmentedRelaxedProof = proof.clone().into();

        let cross_terms = AugmentedGroth16Folder::compute_cross_terms(
            &fresh_proof,
            &fresh_inst,
            &self.proof,
            &self.instance,
        )?;
        let r = AugmentedGroth16Folder::generate_challenge(&fresh_inst, &self.instance, &cross_terms)?;
        let (inst, prf) = AugmentedGroth16Folder::fold_prover(
            &fresh_proof,
            &fresh_inst,
            &self.proof,
            &self.instance,
            &cross_terms,
            r,
        )?;

        let instance_hash = SnarkFoldHash::hash_many(&instance.public_inputs)?;
        self.binding_claim = SnarkFoldHash::hash_two(&instance_hash, &self.binding_claim)?;
        self.instance = inst;
        self.proof = prf;
        self.steps.push(FoldStep { instance: instance.clone(), cross_terms });
        Ok(())
    }

    pub fn finish(self) -> AggregatedProof {
        AggregatedProof {
            steps: self.steps,
            binding_claim: self.binding_claim,
            instance: self.instance,
            proof: self.proof,
        }
    }
}

/// Fold a whole batch at once.
pub fn aggregate(vk: &GrothVerifyingKey, batch: &[(Instance, Proof)]) -> SnarkFoldResult<AggregatedProof> {
    let mut agg = Aggregator::new(vk);
    for (u, p) in batch {
        agg.push(u, p)?;
    }
    Ok(agg.finish())
}

/// Verify an aggregated proof: replay the instance folding from the transcript, check it
/// reproduces the claimed final instance and binding claim, then check the relaxed relation.
pub fn verify_aggregated(vk: &GrothVerifyingKey, agg: &AggregatedProof) -> SnarkFoldResult<bool> {
    let len = vk.instance_len();
    if agg.steps.is_empty() {
        return Ok(false);
    }
    let mut inst = AugmentedRelaxedInstance::zero(len);
    let mut binding = FieldElement::zero();
    for step in &agg.steps {
        if step.instance.public_inputs.len() + 1 != len {
            return Ok(false);
        }
        let fresh = AugmentedRelaxedInstance::from_instance(&step.instance);
        let r = AugmentedGroth16Folder::generate_challenge(&fresh, &inst, &step.cross_terms)?;
        inst = AugmentedGroth16Folder::fold_verifier(&fresh, &inst, &step.cross_terms, r)?;
        let h = SnarkFoldHash::hash_many(&step.instance.public_inputs)?;
        binding = SnarkFoldHash::hash_two(&h, &binding)?;
    }
    if inst != agg.instance || binding != agg.binding_claim {
        return Ok(false);
    }
    verify_relaxed(&agg.proof, &agg.instance, vk)
}

#[cfg(test)]
mod tests {
    //! Real Groth16 proofs for a tiny circuit  c = a · b  (public: c).
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::Groth16;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{rand::SeedableRng, UniformRand};
    use rand_chacha::ChaCha20Rng;

    #[derive(Clone)]
    struct Mul {
        a: Fr,
        b: Fr,
    }
    impl ConstraintSynthesizer<Fr> for Mul {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Fr>,
        ) -> core::result::Result<(), SynthesisError> {
            let c = FpVar::new_input(cs.clone(), || Ok(self.a * self.b))?;
            let a = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
            let b = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
            (a * b).enforce_equal(&c)
        }
    }

    fn setup_and_prove(seed: u8, n: usize) -> (GrothVerifyingKey, Vec<(Instance, Proof)>) {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            Mul { a: Fr::from(1u64), b: Fr::from(1u64) },
            &mut rng,
        )
        .unwrap();
        let batch = (0..n)
            .map(|_| {
                let a = Fr::rand(&mut rng);
                let b = Fr::rand(&mut rng);
                let proof = Groth16::<Bn254>::prove(&pk, Mul { a, b }, &mut rng).unwrap();
                assert!(Groth16::<Bn254>::verify(&vk, &[a * b], &proof).unwrap());
                (Instance { public_inputs: vec![a * b] }, Proof::from(proof))
            })
            .collect();
        (GrothVerifyingKey::from_ark_vk(&vk), batch)
    }

    #[test]
    fn test_plain_and_zero_pairs_satisfy_relaxed_relation() {
        let (vk, batch) = setup_and_prove(7, 1);
        let inst = AugmentedRelaxedInstance::from_instance(&batch[0].0);
        assert!(verify_relaxed(&batch[0].1.clone().into(), &inst, &vk).unwrap());
        assert!(verify_relaxed(
            &AugmentedRelaxedProof::zero(),
            &AugmentedRelaxedInstance::zero(vk.instance_len()),
            &vk
        )
        .unwrap());
    }

    #[test]
    fn test_aggregate_real_proofs() {
        let (vk, batch) = setup_and_prove(7, 8);
        let agg = aggregate(&vk, &batch).unwrap();
        assert_eq!(agg.num_proofs(), 8);
        assert!(verify_aggregated(&vk, &agg).unwrap());
        assert_eq!(agg.instances().count(), 8);

        let mut bytes = vec![];
        agg.serialize_compressed(&mut bytes).unwrap();
        let back = AggregatedProof::deserialize_compressed(&bytes[..]).unwrap();
        assert!(verify_aggregated(&vk, &back).unwrap());
        println!("aggregated proof for 8: {} bytes ({} per proof)", bytes.len(), bytes.len() / 8);
    }

    #[test]
    fn test_incremental_matches_batch() {
        let (vk, batch) = setup_and_prove(7, 3);
        let mut agg = Aggregator::new(&vk);
        for (u, p) in &batch {
            agg.push(u, p).unwrap();
        }
        assert_eq!(agg.finish(), aggregate(&vk, &batch).unwrap());
    }

    #[test]
    fn test_tampered_transcript_rejected() {
        let (vk, batch) = setup_and_prove(7, 4);
        let agg = aggregate(&vk, &batch).unwrap();

        let mut t = agg.clone();
        t.steps[1].instance.public_inputs[0] += Fr::from(1u64);
        assert!(!verify_aggregated(&vk, &t).unwrap());

        let mut t = agg.clone();
        t.instance.mu += Fr::from(1u64);
        assert!(!verify_aggregated(&vk, &t).unwrap());

        let mut t = agg;
        t.binding_claim += Fr::from(1u64);
        assert!(!verify_aggregated(&vk, &t).unwrap());
    }

    #[test]
    fn test_forged_statement_rejected() {
        let (vk, mut batch) = setup_and_prove(7, 4);
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        // a valid proof presented for a different public input
        batch[2].0.public_inputs[0] = Fr::rand(&mut rng);
        let agg = aggregate(&vk, &batch).unwrap();
        assert!(!verify_aggregated(&vk, &agg).unwrap());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (vk, batch) = setup_and_prove(7, 2);
        let (other_vk, _) = setup_and_prove(8, 0);
        assert_ne!(vk, other_vk);
        let agg = aggregate(&vk, &batch).unwrap();
        assert!(!verify_aggregated(&other_vk, &agg).unwrap());
    }

    #[test]
    fn test_empty_rejected_and_length_checked() {
        let (vk, _) = setup_and_prove(7, 0);
        assert!(!verify_aggregated(&vk, &Aggregator::new(&vk).finish()).unwrap());
        let mut a = Aggregator::new(&vk);
        assert!(a
            .push(
                &Instance { public_inputs: vec![Fr::from(1u64), Fr::from(2u64)] },
                &Proof::from(ark_groth16::Proof::<Bn254>::default())
            )
            .is_err());
    }
}
