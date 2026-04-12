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
    snark_verifier::loader::evm::{deploy_and_call, deploy_unrolled_sharded_and_call},
};
use std::{collections::BTreeMap, sync::OnceLock};

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

#[derive(Clone)]
struct IvcGeneratedArtifacts {
    unrolled_bytecode: Vec<u8>,
    sharded_deployments: Vec<Vec<u8>>,
    sharded_dispatcher_deployment: Vec<u8>,
    calldata: Vec<u8>,
}

fn ivc_generated_artifacts() -> &'static IvcGeneratedArtifacts {
    static ARTIFACTS: OnceLock<IvcGeneratedArtifacts> = OnceLock::new();
    ARTIFACTS.get_or_init(|| {
        let bundle = build_ivc_bundle();
        let sharded = bundle
            .generate_evm_verifier_unrolled_sharded_artifacts()
            .expect("failed to generate IVC unrolled-sharded verifier artifacts");
        IvcGeneratedArtifacts {
            unrolled_bytecode: bundle
                .generate_evm_verifier_bytecode()
                .expect("failed to generate IVC unrolled verifier bytecode"),
            sharded_deployments: sharded.shard_deployment_codes,
            sharded_dispatcher_deployment: sharded.dispatcher_deployment_code,
            calldata: bundle.encode_evm_calldata().expect("failed to encode IVC calldata"),
        }
    })
}

fn sharded_accepts(artifacts: &IvcGeneratedArtifacts, calldata: Vec<u8>) -> bool {
    deploy_unrolled_sharded_and_call(
        artifacts.sharded_deployments.clone(),
        artifacts.sharded_dispatcher_deployment.clone(),
        calldata,
    )
    .is_ok()
}

fn unrolled_accepts(artifacts: &IvcGeneratedArtifacts, calldata: Vec<u8>) -> bool {
    deploy_and_call(artifacts.unrolled_bytecode.clone(), calldata).is_ok()
}

fn fuzz_bitflip_cases(base: &[u8], seed: u64, count: usize) -> Vec<(String, Vec<u8>)> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut out = Vec::with_capacity(count);
    for case_idx in 0..count {
        let mut mutated = base.to_vec();
        let byte_idx = rng.gen_range(0..mutated.len());
        let bit_mask = 1u8 << rng.gen_range(0..8);
        mutated[byte_idx] ^= bit_mask;
        out.push((format!("bitflip-{case_idx}-byte-{byte_idx}-mask-{bit_mask:#04x}"), mutated));
    }
    out
}

fn structured_rejection_cases(base: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut cases = Vec::new();

    let mut zeroed = base.to_vec();
    zeroed.fill(0);
    cases.push(("all-zero".to_string(), zeroed));

    let mut first_word_zeroed = base.to_vec();
    let first_word_len = first_word_zeroed.len().min(32);
    first_word_zeroed[..first_word_len].fill(0);
    cases.push(("zero-first-word".to_string(), first_word_zeroed));

    let mut last_word_zeroed = base.to_vec();
    let start = last_word_zeroed.len().saturating_sub(32);
    last_word_zeroed[start..].fill(0);
    cases.push(("zero-last-word".to_string(), last_word_zeroed));

    if base.len() >= 64 {
        let mut swapped = base.to_vec();
        let (lhs, rhs) = swapped.split_at_mut(32);
        lhs.swap_with_slice(&mut rhs[..32]);
        cases.push(("swap-first-two-words".to_string(), swapped));
    }

    if base.len() > 1 {
        cases.push(("truncate-by-1".to_string(), base[..base.len() - 1].to_vec()));
    }
    if base.len() > 64 {
        cases.push(("truncate-half".to_string(), base[..base.len() / 2].to_vec()));
    }

    cases
}

fn structured_parity_only_cases(base: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut cases = Vec::new();

    let mut append_one = base.to_vec();
    append_one.push(0u8);
    cases.push(("append-one-byte".to_string(), append_one));

    let mut append_word = base.to_vec();
    append_word.extend([0u8; 32]);
    cases.push(("append-32-bytes".to_string(), append_word));

    cases
}

#[test]
#[ignore = "slow: generates full IVC artifacts and performs mutation checks via revm deployments"]
fn ivc_sharded_artifacts_reject_fuzzed_and_structured_calldata() {
    let artifacts = ivc_generated_artifacts();

    assert!(
        sharded_accepts(artifacts, artifacts.calldata.clone()),
        "valid IVC calldata should pass against generated sharded artifacts"
    );

    let mut cases = fuzz_bitflip_cases(&artifacts.calldata, 7, 16);
    cases.extend(structured_rejection_cases(&artifacts.calldata));

    for (name, payload) in cases {
        let accepted = sharded_accepts(artifacts, payload);
        assert!(!accepted, "mutated calldata unexpectedly verified for case={name}");
    }
}

#[test]
#[ignore = "slow: generates full IVC artifacts and checks unrolled vs sharded verdict parity"]
fn ivc_unrolled_and_sharded_verdicts_match_on_mutation_corpus() {
    let artifacts = ivc_generated_artifacts();

    assert!(
        unrolled_accepts(artifacts, artifacts.calldata.clone()),
        "valid IVC calldata should pass against generated unrolled artifacts"
    );
    assert!(
        sharded_accepts(artifacts, artifacts.calldata.clone()),
        "valid IVC calldata should pass against generated sharded artifacts"
    );

    let mut cases = vec![("valid".to_string(), artifacts.calldata.clone())];
    cases.extend(fuzz_bitflip_cases(&artifacts.calldata, 11, 8));
    cases.extend(structured_rejection_cases(&artifacts.calldata));
    cases.extend(structured_parity_only_cases(&artifacts.calldata));

    for (name, payload) in cases {
        let unrolled_ok = unrolled_accepts(artifacts, payload.clone());
        let sharded_ok = sharded_accepts(artifacts, payload);
        assert_eq!(unrolled_ok, sharded_ok, "unrolled/sharded verdict mismatch for case={name}");
    }
}

#[test]
#[ignore = "slow: generates full IVC artifacts and validates bytecode tampering fails"]
fn ivc_sharded_artifacts_fail_when_bytecode_is_tampered() {
    let artifacts = ivc_generated_artifacts();

    let mut mutated_shard_deployments = artifacts.sharded_deployments.clone();
    let first =
        mutated_shard_deployments.first_mut().expect("at least one shard deployment must exist");
    assert!(first.len() > 2, "first shard deployment should be non-trivial");
    first.truncate(first.len() / 2);
    assert!(
        deploy_unrolled_sharded_and_call(
            mutated_shard_deployments,
            artifacts.sharded_dispatcher_deployment.clone(),
            artifacts.calldata.clone(),
        )
        .is_err(),
        "mutated shard deployment should not verify valid IVC calldata"
    );

    let mut mutated_dispatcher = artifacts.sharded_dispatcher_deployment.clone();
    assert!(mutated_dispatcher.len() > 2, "dispatcher deployment bytecode should be non-trivial");
    mutated_dispatcher.truncate(mutated_dispatcher.len() / 2);
    assert!(
        deploy_unrolled_sharded_and_call(
            artifacts.sharded_deployments.clone(),
            mutated_dispatcher,
            artifacts.calldata.clone(),
        )
        .is_err(),
        "mutated dispatcher deployment should not verify valid IVC calldata"
    );
}
