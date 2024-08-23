use hash_chain::HashChain;
use log::info;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use std::{env, time::Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    let verbose = args.contains(&"-vv".to_string());
    if env::args().any(|arg| arg == "-vv") {
        std::env::set_var("RUST_LOG", "info");
    }

    env_logger::init();

    // Default steps if not specified
    let mut steps = 2;
    if let Some(pos) = args.iter().position(|x| x == "--steps") {
        if let Some(steps_arg) = args.get(pos + 1) {
            steps = steps_arg.parse().expect("Invalid number for steps");
        }
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut circuit = CircuitBuilder::<F, D>::new(config.clone());
    // Timing verification
    let start_time = Instant::now();
    let (proof, circuit_map) = <CircuitBuilder<GoldilocksField, D> as HashChain<
        GoldilocksField,
        D,
        C,
    >>::build_hash_chain_circuit(&mut circuit, steps)
    .expect("Failed to build hash chain circuit");
    let proof_time = start_time.elapsed();

    // Timing verification
    let start_time = Instant::now();
    let verification_result = <CircuitBuilder<GoldilocksField, D> as HashChain<
        GoldilocksField,
        D,
        C,
    >>::verify(proof, &circuit_map);
    let verify_time = start_time.elapsed();

    // Ensure the verification is successful before considering timing
    assert!(verification_result.is_ok(), "Verification failed");

    if verbose {
        info!("Proof time: {:?}", proof_time);
        info!("Verification time: {:?}", verify_time);
        info!("Circuit depth: {}", steps);
    }
}
