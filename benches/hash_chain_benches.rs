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

fn hash_chain_benchmark(c: &mut Criterion) {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();

    let step_sizes = [2, 4, 8, 16, 32, 64]; // Example step sizes

    for &steps in &step_sizes {
        c.bench_function(&format!("hash_chain_{}_steps", steps), |b| {
            b.iter(|| {
                // Create the circuit inside the black_box to ensure it is evaluated
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

criterion_group!(benches, hash_chain_benchmark);
criterion_main!(benches);
