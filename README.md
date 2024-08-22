# Cyclic Hash Computation with Plonky2

Have you ever been sitting behind your desk one evening and thought to yourself, "Gee whiz, I sure wish I could cryptographically prove in quantum-resistant zero knowledge that I computed a gigantic chain of hashes correctly"? Well _good news_ because this repo will fill that burning hole in your heart with a plonky2-based implementation of a recursive computation chain that proves a series of hashes a la IVC style and outputs a compressed proof of constant size, arguing the integrity of a potentially unlimited size computation.

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

// setup the parameters for the circuit
const D: usize = 2;
type C = PoseidonGoldilocksConfig; // this is the hasher for FRI, not for the circuit
type F = <C as GenericConfig<D>>::F;

let config = CircuitConfig::standard_recursion_config(); // Non-ZK standard recursion config
let mut hash_chain_circuit = CircuitBuilder::<F, D>::new(config.clone());

<CircuitBuilder<GoldilocksField, 2> as HashChain<GoldilocksField, 2, C>>::hash_chain(
    &mut hash_chain_circuit,
    10,  // compute a hash chain of size 10
)
.unwrap();
```

We observe a total uncomressed proof size of 133440 bytes, regardless of number of steps in the chain.

TODO
- [ ] Compress the proof at the end
- [ ] support keccak
- [ ] add benches