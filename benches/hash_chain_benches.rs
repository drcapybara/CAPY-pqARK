use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hash_chain::HashChain;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

fn hash_chain_proving_benchmark(c: &mut Criterion) {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();

    // Power of two recursive step sizes
    let step_sizes = [2, 4, 8, 16, 32, 64];

    let mut group = c.benchmark_group("HashChain Prover");

    // Configure the group
    group.sample_size(10);
    for &steps in &step_sizes {
        group.bench_function(format!("hash_chain_{}_steps", steps), |b| {
            b.iter(|| {
                let mut circuit = black_box(CircuitBuilder::<F, D>::new(config.clone()));
                let (_, _) = <CircuitBuilder<GoldilocksField, D> as HashChain<
                    GoldilocksField,
                    D,
                    C,
                >>::build_hash_chain_circuit(&mut circuit, steps)
                .unwrap();
            });
        });
    }
}

fn hash_chain_verification_benchmark(c: &mut Criterion) {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();

    let mut group = c.benchmark_group("HashChain Verifier");

    // Configure the group
    group.sample_size(10);

    // Power of two recursive step sizes
    let step_sizes = [2, 4, 8, 16, 32, 64];

    for &steps in &step_sizes {
        group.bench_function(format!("hash_chain_verify_{}_steps", steps), |b| {
            // Move the circuit and proof generation out of the iterated benchmark block
            let mut circuit = CircuitBuilder::<F, D>::new(config.clone());
            let (proof, circuit_map) = <CircuitBuilder<GoldilocksField, D> as HashChain<
                GoldilocksField,
                D,
                C,
            >>::build_hash_chain_circuit(&mut circuit, steps)
            .unwrap();

            b.iter(|| {
                // Only verification is timed
                let verification_result =
                    black_box(<CircuitBuilder<GoldilocksField, D> as HashChain<
                        GoldilocksField,
                        D,
                        C,
                    >>::verify(proof.clone(), &circuit_map));

                verification_result.unwrap();
                black_box(());
            });
        });
    }
}

criterion_group!(
    benches,
    hash_chain_proving_benchmark,
    hash_chain_verification_benchmark
);
criterion_main!(benches);
