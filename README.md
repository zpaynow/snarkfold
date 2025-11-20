# SnarkFold: Groth16 Proof Aggregation

This crate implements the SnarkFold proof aggregation scheme for Groth16 proofs as described in the paper ["SnarkFold: Efficient Proof Aggregation from Incrementally Verifiable Computation and Applications"](https://eprint.iacr.org/2023/1946).

## Overview

SnarkFold achieves **constant-size proofs** and **constant verification time** for aggregating multiple Groth16 proofs, making it ideal for blockchain applications like auditable payment systems.

### Key Features

- ✅ **Constant proof size**: Aggregated proof size doesn't grow with the number of proofs
- ✅ **Constant verification time**: O(1) online verification
- ✅ **No trusted setup**: Unlike TIPP and SnarkPack
- ✅ **Instance delegation**: Verifier can preprocess instance aggregation
- ✅ **Efficient prover**: Only 2n pairings for n proofs (vs 17n for TIPP, 21n for SnarkPack)

## Architecture

The implementation consists of several key components:

1. **Augmented Relaxed Groth16**: Extended Groth16 relation that supports folding (Definition 4)
2. **Folding Scheme**: Efficiently folds two proofs into one using randomized linear combinations
3. **IVC (Incrementally Verifiable Computation)**: Recursive proof composition
4. **SnarkFold Aggregation**: Main aggregation scheme combining IVC with folding

## Usage Example

```rust
use snarkfold::*;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() -> Result<()> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    // Step 1: Collect Groth16 proofs to aggregate
    let proofs: Vec<Proof> = vec![/* your Groth16 proofs */];
    let instances: Vec<Instance> = vec![/* corresponding instances */];

    // Step 2: Initialize IVC
    let mut ivc_proof = IVCProver::init();

    // Step 3: Incrementally aggregate proofs
    for (i, (instance, proof)) in instances.iter().zip(proofs.iter()).enumerate() {
        ivc_proof = IVCProver::prove_step(
            i + 1,
            instance,
            proof,
            &ivc_proof
        )?;
    }

    // Step 4: Verifier preprocessing (can be done offline)
    // Compute binding claim from instances
    let mut binding_claim = FieldElement::from(0u64);
    for instance in &instances {
        let instance_hash = hash_instance(instance)?;
        binding_claim = SnarkFoldHash::hash_two(&instance_hash, &binding_claim)?;
    }

    // Step 5: Online verification (constant time!)
    let verified = IVCVerifier::verify(
        instances.len(),
        &ivc_proof,
        &verifying_key
    )?;

    assert!(verified);

    Ok(())
}
```

## Technical Details

### Augmented Relaxed Groth16 Relation

The augmented relaxed relation (Definition 4) consists of:
- Instance: `(⃗a, μ, E, R, ⃗t, κ)`
- Proof: `(A, B, C)`

Verification relation:
```
e(A, B) · e(C, [δ]₂)^(-μ) · e(∏Sᵢ^(aᵢ), [γ]₂)^(-μ) · D^(-μ²) = E · e(R, [δ]₂) · e(∏Sᵢ^(tᵢ), [γ]₂) · D^κ
```

### Folding Protocol

The folding protocol (Equation 3-4) works as follows:

1. **Prover computes cross terms**:
   - `T' = e(A₁, B₂) · e(A₂, B₁)`
   - `R = C₁^(-μ₂) · C₂^(-μ₁)`
   - `⃗t = μ₂⃗a₁ + μ₁⃗a₂`
   - `κ = -2μ₁μ₂`

2. **Generate challenge** (Fiat-Shamir):
   - `r ← Hash(inst₁, inst₂, T)`

3. **Fold instances and proofs**:
   - `⃗a* = ⃗a₁ + r·⃗a₂`
   - `μ* = μ₁ + r·μ₂`
   - `E* = E₁ · (T')^r · E₂^(r²)`
   - `R* = R₁ · R^r · R₂^(r²)`
   - `⃗t* = ⃗t₁ + r·⃗t + r²·⃗t₂`
   - `κ* = κ₁ + r·κ + r²·κ₂`
   - `A* = A₁ · A₂^r`, `B* = B₁ · B₂^r`, `C* = C₁ · C₂^r`

## Performance

Based on the paper's evaluation (aggregating 4096 Plonk proofs):

| Scheme | Proof Size | Proving Time | Verification Time |
|--------|-----------|--------------|-------------------|
| aPlonk | 13 KB | ~800s | 38 ms |
| **SnarkFold** | **0.5 KB** | ~700s | **4.5 ms** |

For Groth16 aggregation, SnarkFold requires:
- **Prover**: 2n pairings + O(n) group operations
- **Verifier**: O(1) online verification + O(n) hashes (preprocessing)
- **Proof size**: Constant (7 G₁ elements + 1 G₂ element + 1 GT element)

## Integration with Auditable Payment System

This SnarkFold implementation can aggregate all payment circuit proofs:

```rust
// Aggregate deposit, transfer, and withdrawal proofs
let deposit_proofs: Vec<Proof> = /* ... */;
let transfer_proofs: Vec<Proof> = /* ... */;
let withdrawal_proofs: Vec<Proof> = /* ... */;

let all_proofs: Vec<Proof> = [
    deposit_proofs,
    transfer_proofs,
    withdrawal_proofs
].concat();

// Aggregate all proofs
let aggregated_proof = aggregate_proofs(&all_proofs)?;

// Verifier only checks one constant-size proof!
verify_aggregated(&aggregated_proof)?;
```

## References

- [SnarkFold Paper](https://eprint.iacr.org/2023/1946)
- [Nova: Recursive Zero-Knowledge Arguments](https://eprint.iacr.org/2021/370)
- [Groth16: On the Size of Pairing-based Non-interactive Arguments](https://eprint.iacr.org/2016/260)

## License

MIT
