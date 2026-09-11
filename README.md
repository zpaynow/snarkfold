# snarkfold

Folding-based aggregation of **Groth16 proofs over BN254**, after
[SnarkFold (ePrint 2023/1946)](https://eprint.iacr.org/2023/1946), Section 4.1.

## What it does

`aggregate(vk, &[(Instance, Proof)])` folds `n` Groth16 proofs for **one verifying key** into a
single *augmented relaxed* Groth16 pair plus a transcript (per step: the instance and the cross
terms `T' ∈ GT, R ∈ G1, ⃗t, κ`). `verify_aggregated(vk, &agg)`:

1. replays the Fiat–Shamir challenges and re-folds the instances from the transcript
   (per step: 2 GT exponentiations + a few G1 scalar multiplications, no pairings),
2. checks the result equals the claimed final instance and binding claim,
3. checks the relaxed relation with **3 pairings + 1 GT exponentiation**:

```
e(A,B) · e(−μC − R, δ) · e(−μ·Σaᵢ·Sᵢ − Σtᵢ·Sᵢ, γ) · e(α,β)^(−μ² − κ) = E
```

Everything is tested against real Groth16 proofs (`src/ivc.rs` tests, `examples/basic_aggregation.rs`).

## What it does not do (yet)

- **No O(1) verification.** The paper achieves that with an IVC circuit proving each folding step;
  that circuit is not implemented, so the verifier is O(n) in GT exponentiations. Pairing work is
  constant. Proof size is ~570 bytes per folded proof (the `T'` elements dominate).
- **No on-chain verifier.** The relation compares a pairing product with an arbitrary GT element `E`;
  the EVM pairing precompile can only test a product against 1, so this cannot be checked on-chain
  without Fq12 arithmetic in Solidity. Use random-linear-combination batch verification on-chain
  and this crate for native / off-chain verification.
- One verifying key per aggregate; aggregate per circuit.

## Usage

```rust
use snarkfold::*;

let gvk = GrothVerifyingKey::from_ark_vk(&vk);
let mut agg = Aggregator::new(&gvk);
for (public_inputs, proof) in proofs {          // public inputs WITHOUT the leading 1
    agg.push(&Instance { public_inputs }, &Proof::from(proof))?;
}
let aggregated = agg.finish();                  // CanonicalSerialize / Deserialize
assert!(verify_aggregated(&gvk, &aggregated)?);
for inst in aggregated.instances() { /* apply state per proof */ }
```

```sh
cargo test --release
cargo run --release --example basic_aggregation -- 64
```

## Layout

| file | content |
| --- | --- |
| `src/groth16.rs` | `Proof`, `Instance`, augmented relaxed instance/proof, cross terms, vk wrapper |
| `src/folding.rs` | cross terms, folding, Fiat–Shamir challenge, `verify_relaxed` |
| `src/ivc.rs` | `Aggregator`, `AggregatedProof`, `aggregate`, `verify_aggregated` |
| `src/hash.rs` | keccak-based field hashing for the binding claim |
