#![cfg(all(feature = "midnight", feature = "loader_evm", feature = "revm"))]

use ff::Field;
use midnight_circuits::{
    ecc::{
        curves::CircuitCurve,
        foreign::{nb_foreign_ecc_chip_columns, ForeignEccChip, ForeignEccConfig},
    },
    field::{
        decomposition::{
            chip::{P2RDecompositionChip, P2RDecompositionConfig},
            pow2range::Pow2RangeChip,
        },
        foreign::FieldChip,
        native::NB_ARITH_COLS,
        NativeChip, NativeConfig, NativeGadget,
    },
    hash::poseidon::{
        PoseidonChip, PoseidonConfig, PoseidonState, NB_POSEIDON_ADVICE_COLS,
        NB_POSEIDON_FIXED_COLS,
    },
    instructions::*,
    types::{AssignedNative, ComposableChip, Instantiable},
    verifier::{
        self, Accumulator, AssignedAccumulator, AssignedVk, BlstrsEmulation, Msm, SelfEmulation,
        VerifierGadget,
    },
};
use midnight_curves::Bls12;
use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk_with_k, prepare, Circuit, ConstraintSystem, Error},
    poly::{
        kzg::{params::ParamsKZG, KZGCommitmentScheme},
        EvaluationDomain,
    },
    transcript::{CircuitTranscript, Transcript},
};
use rand::{rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use snark_verifier_sdk::{
    midnight_adapter::{MidnightBundleOptions, MidnightProofBundle},
    snark_verifier::loader::evm::deploy_unrolled_sharded_and_call,
};
use std::collections::BTreeMap;

#[path = "../examples/support/midnight_evm_transcript.rs"]
mod midnight_evm_transcript;
use midnight_evm_transcript::MidnightEvmHash;

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
type E = <S as SelfEmulation>::Engine;
type CBase = <C as CircuitCurve>::Base;
type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;

const K: u32 = 19;

#[derive(Clone, Debug)]
struct IvcCircuit {
    self_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>),
    prev_state: Value<F>,
    prev_proof: Value<Vec<u8>>,
    prev_acc: Value<Accumulator<S>>,
}

fn collapsed_accumulator_as_public_input(acc: &Accumulator<S>) -> Vec<F> {
    let mut collapsed = acc.clone();
    collapsed.collapse();
    AssignedAccumulator::as_public_input(&collapsed)
}

fn configure_ivc_circuit(
    meta: &mut ConstraintSystem<F>,
) -> (NativeConfig, P2RDecompositionConfig, ForeignEccConfig<C>, PoseidonConfig<F>) {
    let nb_advice_cols = nb_foreign_ecc_chip_columns::<F, C, C, NG>();
    let nb_fixed_cols = NB_ARITH_COLS + 4;

    let advice_columns: Vec<_> = (0..nb_advice_cols).map(|_| meta.advice_column()).collect();
    let fixed_columns: Vec<_> = (0..nb_fixed_cols).map(|_| meta.fixed_column()).collect();
    let committed_instance_column = meta.instance_column();
    let instance_column = meta.instance_column();

    let native_config = NativeChip::configure(
        meta,
        &(
            advice_columns[..NB_ARITH_COLS].try_into().unwrap(),
            fixed_columns[..NB_ARITH_COLS + 4].try_into().unwrap(),
            [committed_instance_column, instance_column],
        ),
    );

    let core_decomp_config = {
        let pow2_config = Pow2RangeChip::configure(meta, &advice_columns[1..NB_ARITH_COLS]);
        P2RDecompositionChip::configure(meta, &(native_config.clone(), pow2_config))
    };

    let base_config = FieldChip::<F, CBase, C, NG>::configure(meta, &advice_columns);
    let curve_config =
        ForeignEccChip::<F, C, C, NG, NG>::configure(meta, &base_config, &advice_columns);

    let poseidon_config = PoseidonChip::configure(
        meta,
        &(
            advice_columns[..NB_POSEIDON_ADVICE_COLS].try_into().unwrap(),
            fixed_columns[..NB_POSEIDON_FIXED_COLS].try_into().unwrap(),
        ),
    );

    (native_config, core_decomp_config, curve_config, poseidon_config)
}

impl Circuit<F> for IvcCircuit {
    type Config = (NativeConfig, P2RDecompositionConfig, ForeignEccConfig<C>, PoseidonConfig<F>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unreachable!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        configure_ivc_circuit(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let native_chip = <NativeChip<F> as ComposableChip<F>>::new(&config.0, &());
        let core_decomp_chip = P2RDecompositionChip::new(&config.1, &(K as usize - 1));
        let scalar_chip = NativeGadget::new(core_decomp_chip.clone(), native_chip.clone());
        let curve_chip = ForeignEccChip::new(&config.2, &scalar_chip, &scalar_chip);
        let poseidon_chip = PoseidonChip::new(&config.3, &native_chip);

        let verifier_chip = VerifierGadget::new(&curve_chip, &scalar_chip, &poseidon_chip);

        let self_vk_name = "self_vk";
        let (self_domain, self_cs, self_vk_value) = &self.self_vk;
        let assigned_self_vk: AssignedVk<S> = verifier_chip.assign_vk_as_public_input(
            &mut layouter,
            self_vk_name,
            self_domain,
            self_cs,
            *self_vk_value,
        )?;

        let prev_state = scalar_chip.assign(&mut layouter, self.prev_state)?;
        let next_state = scalar_chip.add_constant(&mut layouter, &prev_state, F::ONE)?;
        scalar_chip.constrain_as_public_input(&mut layouter, &next_state)?;

        let prev_acc = {
            let mut fixed_base_names = vec![String::from("com_instance")];
            fixed_base_names.extend(verifier::fixed_base_names::<S>(
                self_vk_name,
                self_cs.num_fixed_columns() + self_cs.num_selectors(),
                self_cs.permutation().columns.len(),
            ));
            AssignedAccumulator::assign(
                &mut layouter,
                &curve_chip,
                &scalar_chip,
                1,
                1,
                &[],
                &fixed_base_names,
                self.prev_acc.clone(),
            )?
        };

        let id_point = curve_chip.assign_fixed(&mut layouter, C::default())?;

        let assigned_pi = [
            verifier_chip.as_public_input(&mut layouter, &assigned_self_vk)?,
            vec![prev_state.clone()],
            verifier_chip.as_public_input(&mut layouter, &prev_acc)?,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        let mut proof_acc = verifier_chip.prepare(
            &mut layouter,
            &assigned_self_vk,
            &[("com_instance", id_point)],
            &[&assigned_pi],
            self.prev_proof.clone(),
        )?;

        let is_genesis = scalar_chip.is_zero(&mut layouter, &prev_state)?;
        let is_not_genesis = scalar_chip.not(&mut layouter, &is_genesis)?;

        AssignedAccumulator::scale_by_bit(
            &mut layouter,
            &scalar_chip,
            &is_not_genesis,
            &mut proof_acc,
        )?;

        proof_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        let mut next_acc = AssignedAccumulator::<S>::accumulate(
            &mut layouter,
            &verifier_chip,
            &scalar_chip,
            &poseidon_chip,
            &[proof_acc, prev_acc],
        )?;

        next_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;
        verifier_chip.constrain_as_public_input(&mut layouter, &next_acc)?;

        core_decomp_chip.load(&mut layouter)
    }
}

fn build_ivc_bundle() -> MidnightProofBundle {
    let mut self_cs = ConstraintSystem::default();
    configure_ivc_circuit(&mut self_cs);
    let self_domain = EvaluationDomain::new(self_cs.degree() as u32, K);

    let default_ivc_circuit = IvcCircuit {
        self_vk: (self_domain.clone(), self_cs.clone(), Value::unknown()),
        prev_state: Value::unknown(),
        prev_proof: Value::unknown(),
        prev_acc: Value::unknown(),
    };

    let srs = ParamsKZG::<Bls12>::unsafe_setup(K, OsRng);
    let vk = keygen_vk_with_k(&srs, &default_ivc_circuit, K).expect("vk generation failed");
    let pk = keygen_pk(vk.clone(), &default_ivc_circuit).expect("pk generation failed");

    let mut fixed_bases = BTreeMap::new();
    fixed_bases.insert(String::from("com_instance"), C::default());
    fixed_bases.extend(midnight_circuits::verifier::fixed_bases::<S>("self_vk", &vk));
    let fixed_base_names = fixed_bases.keys().cloned().collect::<Vec<_>>();

    let trivial_acc = Accumulator::<S>::new(
        Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
        Msm::new(
            &[C::default()],
            &[F::ONE],
            &fixed_base_names.iter().map(|name| (name.clone(), F::ZERO)).collect(),
        ),
    );

    let state0 = F::ONE;
    let acc0 = trivial_acc.clone();
    let circuit0 = IvcCircuit {
        self_vk: (self_domain.clone(), self_cs.clone(), Value::known(vk.transcript_repr())),
        prev_state: Value::known(F::ZERO),
        prev_proof: Value::known(vec![]),
        prev_acc: Value::known(trivial_acc),
    };

    let mut public_inputs0 = AssignedVk::<S>::as_public_input(&vk);
    public_inputs0.extend(AssignedNative::<F>::as_public_input(&state0));
    public_inputs0.extend(collapsed_accumulator_as_public_input(&acc0));

    let proof0 = {
        let mut transcript = CircuitTranscript::<PoseidonState<F>>::init();
        create_proof::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>, IvcCircuit>(
            &srs,
            &pk,
            &[circuit0],
            1,
            &[&[&[], &public_inputs0]],
            OsRng,
            &mut transcript,
        )
        .expect("failed to create step-0 IVC proof");
        transcript.finalize()
    };

    let proof_acc0: Accumulator<S> = {
        let mut transcript = CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&proof0);
        let dual_msm = prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
            &vk,
            &[&[C::default()]],
            &[&[&public_inputs0]],
            &mut transcript,
        )
        .expect("native step-0 prepare/verification failed");
        assert!(
            dual_msm.clone().check(&srs.verifier_params()),
            "step-0 proof pairing check failed"
        );
        let mut proof_acc: Accumulator<S> = dual_msm.into();
        proof_acc.extract_fixed_bases(&fixed_bases);
        proof_acc.collapse();
        proof_acc
    };

    let mut acc1 = Accumulator::accumulate(&[proof_acc0, acc0]);
    acc1.collapse();

    let state1 = state0 + F::ONE;
    let circuit1 = IvcCircuit {
        self_vk: (self_domain.clone(), self_cs.clone(), Value::known(vk.transcript_repr())),
        prev_state: Value::known(state0),
        prev_proof: Value::known(proof0),
        prev_acc: Value::known(Accumulator::<S>::new(
            Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
            Msm::new(
                &[C::default()],
                &[F::ONE],
                &fixed_base_names.iter().map(|name| (name.clone(), F::ZERO)).collect(),
            ),
        )),
    };
    let mut public_inputs1 = AssignedVk::<S>::as_public_input(&vk);
    public_inputs1.extend(AssignedNative::<F>::as_public_input(&state1));
    public_inputs1.extend(collapsed_accumulator_as_public_input(&acc1));

    let proof = {
        let mut transcript = CircuitTranscript::<MidnightEvmHash>::init();
        create_proof::<F, KZGCommitmentScheme<E>, CircuitTranscript<MidnightEvmHash>, IvcCircuit>(
            &srs,
            &pk,
            &[circuit1],
            1,
            &[&[&[], &public_inputs1]],
            OsRng,
            &mut transcript,
        )
        .expect("failed to create step-1 EVM IVC proof");
        transcript.finalize()
    };

    MidnightProofBundle::from_vk(
        srs.verifier_params(),
        vk,
        proof,
        vec![public_inputs1],
        MidnightBundleOptions::default(),
    )
    .expect("bundle creation should succeed")
}

#[test]
#[ignore = "slow: generates a full IVC proof and deploys sharded artifacts multiple times"]
fn ivc_sharded_artifacts_reject_fuzzed_calldata() {
    let bundle = build_ivc_bundle();
    let artifacts = bundle
        .generate_evm_verifier_unrolled_sharded_artifacts()
        .expect("failed to generate IVC unrolled-sharded verifier artifacts");
    let calldata = bundle.encode_evm_calldata().expect("failed to encode IVC calldata");

    deploy_unrolled_sharded_and_call(
        artifacts.shard_deployment_codes.clone(),
        artifacts.dispatcher_deployment_code.clone(),
        calldata.clone(),
    )
    .expect("valid IVC calldata should pass against generated sharded artifacts");

    let mut rng = ChaCha8Rng::seed_from_u64(7);
    const FUZZ_MUTATIONS: usize = 12;
    for case_idx in 0..FUZZ_MUTATIONS {
        let mut mutated = calldata.clone();
        let byte_idx = rng.gen_range(0..mutated.len());
        let bit_mask = 1u8 << rng.gen_range(0..8);
        mutated[byte_idx] ^= bit_mask;

        let result = deploy_unrolled_sharded_and_call(
            artifacts.shard_deployment_codes.clone(),
            artifacts.dispatcher_deployment_code.clone(),
            mutated,
        );
        assert!(
            result.is_err(),
            "mutated calldata unexpectedly verified (case={case_idx}, byte={byte_idx}, bit_mask=0x{bit_mask:02x})"
        );
    }
}
