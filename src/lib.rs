use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
    },
};
use std::error::Error;
pub const KECCAK256_R: usize = 1088;

pub trait HashChain<F: RichField + Extendable<D>, const D: usize, C: GenericConfig<D, F = F>> {
    fn check_cyclic_proof_layer(
        condition: BoolTarget,
        inner_cyclic_proof_with_pub_inputs: ProofWithPublicInputsTarget<D>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data_target: VerifierCircuitTarget,
        cyclic_circuit_data: &CircuitData<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, Box<dyn Error>>;
    fn hash_chain(&mut self, steps: usize) -> Result<(), Box<dyn std::error::Error>>;
    fn common_data_for_recursion() -> CommonCircuitData<F, D>;
}

impl<F: RichField + Extendable<D>, const D: usize, C: GenericConfig<D, F = F> + 'static>
    HashChain<F, D, C> for CircuitBuilder<F, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn hash_chain(&mut self, steps: usize) -> Result<(), Box<dyn std::error::Error>> {
        let config = CircuitConfig::standard_recursion_config();

        // Setup the builder for the cyclic circuit. We will proceed to add the necessary
        // gates into this first builder, then proceed to construct additional builders
        // and configs for each layer of recursion.
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Set a counter to be incremented and track recursion depth
        let one = builder.one();

        let initial_hash_target: HashOutTarget = builder.add_virtual_hash();

        // Next register the initial hash as a public input.
        builder.register_public_inputs(&initial_hash_target.elements);

        // Insert an updateable hash gate into the circuit, so that we can
        // update it as we recurse.
        let current_hash_in: HashOutTarget = builder.add_virtual_hash();
        let current_hash_out: HashOutTarget =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(current_hash_in.elements.to_vec());

        builder.register_public_inputs(&current_hash_out.elements);
        let counter = builder.add_virtual_public_input();

        // Get the `CircuitCommonData` for this circuit, which defines the configuration
        // and partial witnesses for the recursion layers.
        let mut common_data =
            <CircuitBuilder<F, D> as HashChain<F, D, C>>::common_data_for_recursion();

        // Define the verifier data target for the circuit.
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();

        // Set a condition flag to determine if we are in the base case or not.
        let condition = builder.add_virtual_bool_target_safe();

        let inner_cyclic_proof_with_pub_inputs = builder.add_virtual_proof_with_pis(&common_data);
        let inner_cyclic_pub_inputs = &inner_cyclic_proof_with_pub_inputs.public_inputs;
        let inner_cyclic_initial_hash =
            HashOutTarget::try_from(&inner_cyclic_pub_inputs[0..4]).unwrap();
        let inner_cyclic_latest_hash =
            HashOutTarget::try_from(&inner_cyclic_pub_inputs[4..8]).unwrap();
        let inner_cyclic_counter = inner_cyclic_pub_inputs[8];

        builder.connect_hashes(initial_hash_target, inner_cyclic_initial_hash);

        let actual_hash_in =
            builder.select_hash(condition, inner_cyclic_latest_hash, initial_hash_target);
        builder.connect_hashes(current_hash_in, actual_hash_in);

        let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
        builder.connect(counter, new_counter);

        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_cyclic_proof_with_pub_inputs,
            &common_data,
        )?;

        let cyclic_circuit_data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let initial_hash = [F::ZERO, F::ONE, F::TWO, F::from_canonical_usize(3)];
        let initial_hash_pub_inputs = initial_hash.into_iter().enumerate().collect();
        pw.set_bool_target(condition, false);
        pw.set_proof_with_pis_target::<C, D>(
            &inner_cyclic_proof_with_pub_inputs,
            &cyclic_base_proof(
                &common_data,
                &cyclic_circuit_data.verifier_only,
                initial_hash_pub_inputs,
            ),
        );
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
        let proof = cyclic_circuit_data.prove(pw)?;
        check_cyclic_proof_verifier_data(
            &proof,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )?;
        cyclic_circuit_data.verify(proof.clone())?;

        // Base case of the recursion
        let mut proof = Self::check_cyclic_proof_layer(
            condition,
            inner_cyclic_proof_with_pub_inputs.clone(),
            proof,
            verifier_data_target.clone(),
            &cyclic_circuit_data,
        )?;
        cyclic_circuit_data.verify(proof.clone())?;

        // Subsequent recursive steps
        for _ in 0..steps {
            proof = Self::check_cyclic_proof_layer(
                condition,
                inner_cyclic_proof_with_pub_inputs.clone(),
                proof,
                verifier_data_target.clone(),
                &cyclic_circuit_data,
            )?;
        }

        // Use the given hash permutation from plonky2 to verify
        // that the repeated hash is computed correctly.
        let initial_hash = &proof.public_inputs[..4];
        let hash = &proof.public_inputs[4..8];
        let counter = proof.public_inputs[8];
        let expected_hash: [F; 4] = iterate_hash(
            initial_hash.try_into().unwrap(),
            counter.to_canonical_u64() as usize,
        );
        assert_eq!(hash, expected_hash);
        let proof_bytes = proof.to_bytes();
        println!("Total Proof length: {} bytes", proof_bytes.len());
        Ok(cyclic_circuit_data.verify(proof)?)
    }

    // Generates the common circuit data config for recursion, starting with the base case,
    // the generating the configs for the recursive cases.
    fn common_data_for_recursion() -> CommonCircuitData<F, D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let data = builder.build::<C>();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        let data = builder.build::<C>();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);

        // Im not entiirely sure why we do this, but my best guess is that FRI requires AIR traces that are powers of 2
        while builder.num_gates() < 1 << ((12 - 1) + 1) {
            builder.add_gate(NoopGate, vec![]);
        }
        builder.build::<C>().common
    }

    fn check_cyclic_proof_layer(
        condition: BoolTarget,
        inner_cyclic_proof_with_pub_inputs: ProofWithPublicInputsTarget<D>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data_target: VerifierCircuitTarget,
        cyclic_circuit_data: &CircuitData<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, Box<dyn Error>> {
        let mut pw = PartialWitness::new();
        pw.set_bool_target(condition, true);
        pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pub_inputs, &proof);
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
        let proof = cyclic_circuit_data.prove(pw)?;
        check_cyclic_proof_verifier_data(
            &proof,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )?;
        Ok(proof)
    }
}

fn iterate_hash<F: RichField>(initial_state: [F; 4], n: usize) -> [F; 4] {
    let mut current = initial_state;
    for _ in 0..n {
        current = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&current).elements;
    }
    current
}

#[cfg(test)]
mod tests {

    use crate::HashChain;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    #[test]
    fn test_hash_chain() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let _ =
            <CircuitBuilder<GoldilocksField, 2> as HashChain<GoldilocksField, 2, C>>::hash_chain(
                &mut builder,
                100,
            );
    }
}
