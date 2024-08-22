# Cyclic Hash Computation with Plonky2

Have you ever been sitting behind your desk one evening and thought to yourself, "Gee whiz, I sure wish I could cryptographically prove in quantum-resistant zero knowledge that I computed a gigantic chain of hashes correctly"? Well _good news_ because this repo will fill that burning hole in your heart with a plonky2-based implementation of a prover and verifier pair for a recursive computation chain that argues the computational integrity of a series of hashes a la IVC style and outputs a compressed proof of constant size. The recursive nature of this circuit allows it to scale to potentially unlimited computation size.

## Quick start:

You can download the repo and run the main brain successfully with:
```bash
cargo test
```

Which is run in release mode by default. This repo requires the nightly toolchain. If you are seeing errors related to:

```bash
6 | #![feature(specialization)]
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0554]: `#![feature]` may not be used on the stable release channel
  |
7 | #![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]
  |                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0554]: `#![feature]` may not be used on the stable release channel
  |
7 | #![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]
  |                                             ^^^^^^^^^^^^^^^^^^
```

Then please double check your toolchain. Otherwise, this repo should work out of the box.

This branch performs cyclic poseidon hashes, while [this branch](https://github.com/drcapybara/hash-chain/tree/feat/keccak) (currently broken), performs cyclic keccak hashes. 


# Strategy

Our approach is to insert the following gates into the circuit with the requisite connections. It is not enough to create a circuit that simply connects each hash output the next input, the prover must argue the hash computation _and_ verify the preceeding hash in a single step, taking into account the recursive structure of the chain:

```
+------------------+    +------------------+    +-----------------+
| Initial Hash     |    | Current Hash     |    | Verifier Data   |
| Target Gate      |──▶| Input Target     |──▶| Target Gate     |
+------------------+    | (Updateable)     |    +-----------------+
         │              +------------------+            │
         │                   │    ▲                     │
         │                   │    │                     │
         │                   │    └───────┐             │
         │                   │            │             │
         │             +-----------+      │             │
         └───────────▶| Condition |      │             │
                       | Check Gate|      │             │
                       +-----------+      │             │
                                │         │             │
                                │   +------------------------+
                                └───┤ Recursive Proof        |
                                    | Integration & Loop     |
                                    +------------------------+
                                            │           ▲
                                            │           │
                                            │           │
                                            │           │
                                    +---------------+   │
                                    | Step Counter  |───┘
                                    | & Loop Check  |
                                    +---------------+
                                            │
                                            │
                                    +---------------+
                                    | Finalize Hash |
                                    | & Verification|
                                    +---------------+
```

### Initial Setup
- **Counter Initialization**: A counter gate is initialized to track the depth of recursion.
- **Hash Initialization**: A virtual hash target gate is inserted and registered as a public input, marking the starting point of the hash chain.
- **Keccak Hash Gate**: An updateable hash gate is added to enable hash updates as the recursion progresses.

### Recursive Hashing
- **Verifier Data Setup**: Circuit common data is prepared, including configuration and partial witnesses required for recursion.
- **Base Case Identification**: A condition is set to identify whether the current computation is the base case or a recursive case.
- **Hash Chain Connection**: The current hash is connected to the previous hash output or set as the initial hash based on whether it's a base or recursive step.

### Recursive Proof Verification
- **Circuit Building**: The circuit for the current step is built.
- **Proof Generation**: A proof of the correctness of the current hash computation is generated using the circuit data.
- **Proof Verification**: The generated proof is verified to ensure that the hash was computed correctly.

### Final Verification
- **Final Hash Check**: After all recursive steps, the final hash is compared against the expected result to confirm the integrity of the entire hash chain.

## Usage:

```rust
use hash_chain::HashChain;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

let config = CircuitConfig::standard_recursion_config();
let mut builder = CircuitBuilder::<F, D>::new(config.clone());
let (p, c) =
    <CircuitBuilder<GoldilocksField, 2> as HashChain<GoldilocksField, 2, C>>::hash_chain(
        &mut builder,
        10,
    )
    .unwrap();

let result =
    <CircuitBuilder<GoldilocksField, 2> as HashChain<GoldilocksField, 2, C>>::verify(p, c);
assert!(result.is_ok())

```

We observe a total uncomressed proof size of 133440 bytes, regardless of number of steps in the chain.

TODO
- [ ] Compress the proof at the end
- [ ] support keccak
- [ ] add benches
