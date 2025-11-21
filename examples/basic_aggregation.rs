use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use rand_chacha::ChaCha20Rng;
use snarkfold::*;

fn main() -> Result<()> {
    println!("SnarkFold: Groth16 Proof Aggregation Example");
    println!("=============================================\n");

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    // Number of proofs to aggregate
    let num_proofs = 10;

    println!("Aggregating {} Groth16 proofs...\n", num_proofs);

    // Step 1: Generate mock Groth16 proofs and instances
    println!("Step 1: Generating {} mock Groth16 proofs...", num_proofs);
    let mut proofs = Vec::new();
    let mut instances = Vec::new();

    for i in 0..num_proofs {
        // In practice, these would be actual Groth16 proofs from your payment circuits
        let proof = Proof {
            a: G1::rand(&mut rng),
            b: G2::rand(&mut rng),
            c: G1::rand(&mut rng),
        };

        let instance = Instance {
            public_inputs: vec![FieldElement::rand(&mut rng), FieldElement::rand(&mut rng)],
        };

        proofs.push(proof);
        instances.push(instance);

        if (i + 1) % 10 == 0 {
            println!("  Generated {}/{} proofs", i + 1, num_proofs);
        }
    }

    println!("✓ Generated all proofs\n");

    // Step 2: Initialize IVC
    println!("Step 2: Initializing IVC...");
    let mut ivc_proof = IVCProver::init();
    println!("✓ IVC initialized\n");

    // Step 3: Incrementally aggregate proofs
    println!("Step 3: Folding proofs incrementally...");
    for (i, (instance, proof)) in instances.iter().zip(proofs.iter()).enumerate() {
        ivc_proof = IVCProver::prove_step(i + 1, instance, proof, &ivc_proof)?;

        if (i + 1) % 10 == 0 || i + 1 == num_proofs {
            println!("  Folded {}/{} proofs", i + 1, num_proofs);
        }
    }

    println!("✓ All proofs aggregated\n");

    // Step 4: Verifier preprocessing (offline)
    println!("Step 4: Verifier preprocessing (can be done offline)...");
    let mut binding_claim = FieldElement::from(0u64);
    for instance in &instances {
        let mut instance_data = Vec::new();
        for input in &instance.public_inputs {
            instance_data.push(*input);
        }
        let instance_hash = SnarkFoldHash::hash_many(&instance_data)?;
        binding_claim = SnarkFoldHash::hash_two(&instance_hash, &binding_claim)?;
    }
    println!("✓ Preprocessing complete\n");

    // Step 5: Verify binding claim matches
    println!("Step 5: Verifying binding claim...");
    if ivc_proof.binding_claim == binding_claim {
        println!("✓ Binding claim verified\n");
    } else {
        println!("✗ Binding claim mismatch!\n");
        return Err(SnarkFoldError::VerificationError(
            "Binding claim mismatch".to_string(),
        ));
    }

    // Step 6: Online verification (constant time!)
    println!("Step 6: Online verification (O(1) time)...");
    let mock_vk = create_mock_verifying_key();
    let verified = IVCVerifier::verify(num_proofs, &ivc_proof, &mock_vk)?;

    if verified {
        println!("✓ Aggregated proof VERIFIED!\n");
    } else {
        println!("✗ Aggregated proof REJECTED!\n");
        return Err(SnarkFoldError::VerificationError(
            "Proof verification failed".to_string(),
        ));
    }

    // Print statistics
    println!("Statistics:");
    println!("===========");
    println!("Number of proofs aggregated: {}", num_proofs);
    println!("Proof size: Constant (independent of n)");
    println!("Verification time: O(1) (constant)");
    println!("Preprocessing time: O(n) hashes");
    println!("Prover time: O(n) (2n pairings)");
    println!("\nComparison with alternatives:");
    println!("  TIPP/SnarkPack: O(log n) proof size, O(log n) verification");
    println!("  SnarkFold: O(1) proof size, O(1) verification ✓");

    Ok(())
}

fn create_mock_verifying_key() -> GrothVerifyingKey {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    GrothVerifyingKey {
        alpha_g1: G1::rand(&mut rng),
        beta_g2: G2::rand(&mut rng),
        gamma_g2: G2::rand(&mut rng),
        delta_g2: G2::rand(&mut rng),
        gamma_abc_g1: vec![G1::rand(&mut rng), G1::rand(&mut rng)],
    }
}
