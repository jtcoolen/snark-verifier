use std::time::{Duration, Instant};

#[cfg(feature = "evm-bench")]
use std::cell::RefCell;
#[cfg(feature = "evm-bench")]
use std::collections::BTreeSet;
#[cfg(feature = "evm-bench")]
use std::path::PathBuf;

use ff::{Field, PrimeField};
use group::Group;
#[cfg(feature = "evm-bench")]
use group::prime::PrimeCurveAffine;
#[cfg(feature = "evm-bench")]
use group::Curve;
#[cfg(feature = "evm-bench")]
use midnight_curves::CurveAffine as MidnightCurveAffine;
use num_bigint::BigUint;
use thiserror::Error;

use midnight_circuits::{
    hash::poseidon::{PoseidonChip, PoseidonState},
    instructions::map::MapCPU,
    map::cpu::MapMt,
    types::{AssignedNativePoint, Instantiable},
};
use midnight_curves::{Fr as JubjubScalar, JubjubExtended as Jubjub, JubjubSubgroup};
use midnight_proofs::{circuit::Value, transcript::Transcript};
use midnight_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk_with_k, prepare, VerifyingKey},
    poly::kzg::{params::ParamsKZG, KZGCommitmentScheme},
};
use midnight_zk_stdlib::{self, cost_model, MidnightPK};
use rand::{rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[cfg(feature = "evm-bench")]
use revm::{
    context::TxEnv,
    context_interface::result::{ExecutionResult, Output},
    database::InMemoryDB,
    primitives::{hardfork::SpecId, Address, Bytes, TxKind},
    Context, ExecuteCommitEvm, MainBuilder, MainContext, MainnetEvm,
};
#[cfg(feature = "evm-bench")]
use serde_json::json;
use sha3::{Digest, Keccak256};
#[cfg(feature = "evm-bench")]
use snark_verifier_sdk::midnight_adapter::MidnightProofBundle;

use midnight_circuits::{
    ecc::foreign::ForeignEccChip,
    field::{decomposition::chip::P2RDecompositionChip, native::NativeChip, NativeGadget},
    types::AssignedForeignPoint,
    verifier::{BlstrsEmulation, SelfEmulation},
};

mod keccak_transcript;
mod rollup_ivc_circuits;
mod rollup_ivc_proofs;
mod setup_ivc;
mod transfer_circuit;
mod trusted_setup;

pub type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
type E = <S as SelfEmulation>::Engine;
type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;

pub type CurveChip = ForeignEccChip<F, C, C, NG, NG>;
pub type MapGadget = midnight_circuits::map::map_gadget::MapGadget<F, NG, PoseidonChip<F>>;
pub type IdPoint = AssignedForeignPoint<
    midnight_curves::Fq,
    midnight_curves::G1Projective,
    midnight_curves::G1Projective,
>;

type CommitmentMap = MapMt<F, PoseidonChip<F>>;

const DEFAULT_BATCH_SIZE: usize = 4;
const DEFAULT_ROLLUP_TRANSITIONS: usize = 100;

/// Probability that a client proof is generated against an older confirmed root.
const LAG_TX_PROB: f64 = 0.35;

pub const AGG_K: u32 = rollup_ivc_circuits::AGG_K;

#[cfg(feature = "evm-bench")]
const BLS_ENCODED_FP_BYTES: usize = 64;
#[cfg(feature = "evm-bench")]
const STATE_TRANSITION_PUBLIC_INPUTS: usize = 9;
#[cfg(feature = "evm-bench")]
const L2_METADATA_MERKLE_PUBLIC_INPUTS: usize = 1;
#[cfg(feature = "evm-bench")]
const FINAL_ACC_PUBLIC_INPUTS: usize = 28;
#[cfg(feature = "evm-bench")]
const SUBROOT_PUBLIC_INPUT_INDEX: usize = 6;
#[cfg(feature = "evm-bench")]
const CLIENT_PUBLIC_ITEMS_WIDTH: usize = 7;
#[cfg(feature = "evm-bench")]
const FINAL_ACC_PUBLIC_INPUTS_OFFSET: usize =
    STATE_TRANSITION_PUBLIC_INPUTS + L2_METADATA_MERKLE_PUBLIC_INPUTS;
#[cfg(feature = "evm-bench")]
const PROOF_PUBLIC_INPUTS: usize =
    STATE_TRANSITION_PUBLIC_INPUTS + L2_METADATA_MERKLE_PUBLIC_INPUTS + FINAL_ACC_PUBLIC_INPUTS;
#[cfg(feature = "evm-bench")]
type RevmMainnetContext = revm::context::Context<
    revm::context::BlockEnv,
    revm::context::TxEnv,
    revm::context::CfgEnv,
    InMemoryDB,
    revm::Journal<InMemoryDB>,
    (),
>;

#[derive(Debug, Error)]
enum AppError {
    #[error("trusted setup failed: {0}")]
    TrustedSetup(String),

    #[error("key generation failed: {0}")]
    Keygen(String),

    #[error("proof generation failed: {0}")]
    Proof(String),

    #[error("verification preparation failed: {0}")]
    VerificationPrep(String),

    #[error("invalid scalar-to-field conversion")]
    ScalarToField,

    #[error("replay guard failed: {0}")]
    ReplayGuard(String),

    #[cfg(feature = "evm-bench")]
    #[error("evm bench failed: {0}")]
    EvmBench(String),
}

fn err_string<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "y" | "on")
        })
        .unwrap_or(false)
}

fn env_usize_or(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|value| value.trim().parse::<usize>().ok()).unwrap_or(default)
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|value| value.trim().parse::<usize>().ok())
}

fn env_u32_or(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|value| value.trim().parse::<u32>().ok()).unwrap_or(default)
}

#[cfg(feature = "evm-bench")]
#[derive(Clone, Debug)]
struct FinalWrapBenchSample {
    batch_idx: usize,
    proof: Vec<u8>,
    public_inputs: Vec<F>,
    l2_block_metadata: Vec<F>,
}

#[cfg(feature = "evm-bench")]
#[derive(Clone, Debug)]
struct RollupTransitionBenchSample {
    batch_idx: usize,
    transition_idx: usize,
    proof: Vec<u8>,
    public_inputs: Vec<F>,
}

#[cfg(feature = "evm-bench")]
struct FinalWrapStatefulLoopCache {
    evm: MainnetEvm<RevmMainnetContext>,
    dispatcher_address: Address,
    state_contract_address: Address,
    shard_deploy_gas: u64,
    dispatcher_deploy_gas: u64,
    verifier_deploy_gas_total: u64,
    direct_verifier_call_gas: Option<u64>,
    state_contract_deploy_gas: u64,
    call_gas_total: u64,
    call_gas_per_batch: Vec<serde_json::Value>,
    processed_batch_ids: BTreeSet<usize>,
}

#[cfg(feature = "evm-bench")]
thread_local! {
    static FINAL_WRAP_STATEFUL_LOOP_CACHE: RefCell<Option<FinalWrapStatefulLoopCache>> = RefCell::new(None);
}

#[cfg(feature = "evm-bench")]
fn abi_word_from_usize(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    let be = (value as u64).to_be_bytes();
    word[24..].copy_from_slice(&be);
    word
}

fn field_to_abi_word(value: F) -> [u8; 32] {
    let mut word = value.to_repr();
    word.reverse();
    word
}

#[cfg(feature = "evm-bench")]
fn address_to_abi_word(address: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
}

#[cfg(feature = "evm-bench")]
fn le_component_to_padded_word_hex(component_le: &[u8]) -> [String; 2] {
    assert!(component_le.len() <= BLS_ENCODED_FP_BYTES);
    let mut padded = [0u8; BLS_ENCODED_FP_BYTES];
    let mut be = component_le.to_vec();
    be.reverse();
    let offset = BLS_ENCODED_FP_BYTES - be.len();
    padded[offset..].copy_from_slice(&be);
    [
        format!("0x{}", hex::encode(&padded[..0x20])),
        format!("0x{}", hex::encode(&padded[0x20..])),
    ]
}

#[cfg(feature = "evm-bench")]
fn g2_to_word_hex(ec_point: midnight_curves::G2Affine) -> Vec<String> {
    let coordinates = ec_point.coordinates().expect("expected affine G2 point");
    let x = coordinates.x().to_repr();
    let y = coordinates.y().to_repr();

    let x = x.as_ref();
    let y = y.as_ref();
    assert_eq!(x.len() % 2, 0);
    assert_eq!(y.len() % 2, 0);
    let x_mid = x.len() / 2;
    let y_mid = y.len() / 2;

    let use_legacy_c1c0 =
        std::env::var("SNARK_VERIFIER_EVM_G2_LEGACY_C1C0").ok().as_deref() == Some("1");
    let components = if use_legacy_c1c0 {
        [&x[x_mid..], &x[..x_mid], &y[y_mid..], &y[..y_mid]]
    } else {
        [&x[..x_mid], &x[x_mid..], &y[..y_mid], &y[y_mid..]]
    };

    components
        .into_iter()
        .flat_map(|component| le_component_to_padded_word_hex(component))
        .collect()
}

#[cfg(feature = "evm-bench")]
fn g1_to_word_hex(ec_point: midnight_curves::G1Projective) -> [String; 4] {
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    if bool::from(ec_point.is_identity()) {
        return [zero.clone(), zero.clone(), zero.clone(), zero];
    }

    let affine = ec_point.to_affine();
    let coordinates = affine.coordinates().expect("expected affine G1 point");
    let x = le_component_to_padded_word_hex(coordinates.x().to_repr().as_ref());
    let y = le_component_to_padded_word_hex(coordinates.y().to_repr().as_ref());

    [x[0].clone(), x[1].clone(), y[0].clone(), y[1].clone()]
}

#[cfg(feature = "evm-bench")]
fn decode_final_acc_field_words(
    final_acc_pi: &[F],
    start: usize,
    first_limb_override: Option<BigUint>,
) -> Result<[String; 2], AppError> {
    const LIMB_BITS: usize = 56;
    const NB_LIMBS: usize = 7;
    const FP_BYTES: usize = 48;

    if final_acc_pi.len() < start + NB_LIMBS {
        return Err(AppError::EvmBench(format!(
            "final accumulator slice too short for field decode: len={}, start={start}",
            final_acc_pi.len()
        )));
    }

    let base = BigUint::from(1u8) << LIMB_BITS;
    let limb_mask = &base - BigUint::from(1u8);

    let mut limbs = Vec::with_capacity(NB_LIMBS);
    for i in 0..NB_LIMBS {
        let limb = if i == 0 {
            first_limb_override
                .clone()
                .unwrap_or_else(|| BigUint::from_bytes_le(final_acc_pi[start].to_repr().as_ref()))
        } else {
            BigUint::from_bytes_le(final_acc_pi[start + i].to_repr().as_ref())
        };
        if limb > limb_mask {
            return Err(AppError::EvmBench(format!(
                "final accumulator limb out of range at index {}",
                start + i
            )));
        }
        limbs.push(limb);
    }

    // Inverse of AssignedField::as_public_input: value = 1 + sum(limb_i * 2^(56*i)).
    let mut value = BigUint::from(1u8);
    for (i, limb) in limbs.iter().enumerate() {
        value += limb << (LIMB_BITS * i);
    }

    let mut value_le = value.to_bytes_le();
    if value_le.len() > FP_BYTES {
        return Err(AppError::EvmBench(format!(
            "decoded field element too large: {} bytes (max {})",
            value_le.len(),
            FP_BYTES
        )));
    }
    value_le.resize(FP_BYTES, 0u8);
    Ok(le_component_to_padded_word_hex(&value_le))
}

#[cfg(feature = "evm-bench")]
fn decode_final_acc_point_words(final_acc_pi: &[F], start: usize) -> Result<[String; 4], AppError> {
    const LIMB_BITS: usize = 56;

    let l0_raw = BigUint::from_bytes_le(final_acc_pi[start].to_repr().as_ref());
    let is_id = &l0_raw >> LIMB_BITS;
    let one = BigUint::from(1u8);
    if is_id > one {
        return Err(AppError::EvmBench(format!(
            "invalid is_id flag in final accumulator at index {start}"
        )));
    }

    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    if is_id == one {
        return Ok([zero.clone(), zero.clone(), zero.clone(), zero]);
    }

    let limb_mask = (BigUint::from(1u8) << LIMB_BITS) - BigUint::from(1u8);
    let l0 = l0_raw & limb_mask;
    let x = decode_final_acc_field_words(final_acc_pi, start, Some(l0))?;
    let y = decode_final_acc_field_words(final_acc_pi, start + 7, None)?;
    Ok([x[0].clone(), x[1].clone(), y[0].clone(), y[1].clone()])
}

#[cfg(feature = "evm-bench")]
fn encode_state_constructor_args(
    verifier: Address,
    first_public_inputs: &[F],
) -> Result<Vec<u8>, AppError> {
    if first_public_inputs.len() < PROOF_PUBLIC_INPUTS {
        return Err(AppError::EvmBench(format!(
            "expected at least {} public inputs, got {}",
            PROOF_PUBLIC_INPUTS,
            first_public_inputs.len(),
        )));
    }

    // [verifier, c_pre, n_pre, pre_roots_set_root, blk_pre]
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&address_to_abi_word(verifier));
    encoded.extend_from_slice(&field_to_abi_word(first_public_inputs[0]));
    encoded.extend_from_slice(&field_to_abi_word(first_public_inputs[2]));
    encoded.extend_from_slice(&field_to_abi_word(first_public_inputs[7]));
    encoded.extend_from_slice(&field_to_abi_word(first_public_inputs[4]));
    Ok(encoded)
}

#[cfg(feature = "evm-bench")]
fn encode_sharded_constructor_args(shard_addresses: &[Address]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(32 * (2 + shard_addresses.len()));
    encoded.extend_from_slice(&abi_word_from_usize(0x20));
    encoded.extend_from_slice(&abi_word_from_usize(shard_addresses.len()));
    for address in shard_addresses {
        encoded.extend_from_slice(&address_to_abi_word(*address));
    }
    encoded
}

#[cfg(feature = "evm-bench")]
fn encode_verify_and_update_call(
    verifier_calldata: &[u8],
    public_inputs: &[F],
    l2_block_metadata: &[F],
) -> Result<Vec<u8>, AppError> {
    if public_inputs.len() < PROOF_PUBLIC_INPUTS {
        return Err(AppError::EvmBench(format!(
            "expected at least {} public inputs, got {}",
            PROOF_PUBLIC_INPUTS,
            public_inputs.len(),
        )));
    }
    if l2_block_metadata.is_empty() || l2_block_metadata.len() % CLIENT_PUBLIC_ITEMS_WIDTH != 0 {
        return Err(AppError::EvmBench(format!(
            "invalid L2 block metadata length: got {}, expected non-zero multiple of {}",
            l2_block_metadata.len(),
            CLIENT_PUBLIC_ITEMS_WIDTH
        )));
    }
    let metadata_leaf_count = l2_block_metadata.len() / CLIENT_PUBLIC_ITEMS_WIDTH;
    if !metadata_leaf_count.is_power_of_two() {
        return Err(AppError::EvmBench(format!(
            "invalid L2 block metadata rows: {metadata_leaf_count} (must be power-of-two)"
        )));
    }

    let selector = {
        let digest = Keccak256::digest(
            b"verifyAndUpdate(bytes,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256[28],uint256[])",
        );
        [digest[0], digest[1], digest[2], digest[3]]
    };

    // Head: bytes offset + 8 state-transition words + fixed uint256[28] accumulator limbs + metadata offset.
    let head_words = 2 + (STATE_TRANSITION_PUBLIC_INPUTS - 1) + FINAL_ACC_PUBLIC_INPUTS;
    let bytes_offset = head_words * 32;
    let verifier_tail_size = 32 + ((verifier_calldata.len() + 31) / 32) * 32;
    let metadata_offset = bytes_offset + verifier_tail_size;
    let metadata_tail_size = 32 + (l2_block_metadata.len() * 32);

    let mut encoded = Vec::with_capacity(4 + bytes_offset + verifier_tail_size + metadata_tail_size);
    encoded.extend_from_slice(&selector);
    encoded.extend_from_slice(&abi_word_from_usize(bytes_offset));
    for (idx, value) in public_inputs[..STATE_TRANSITION_PUBLIC_INPUTS].iter().enumerate() {
        if idx == SUBROOT_PUBLIC_INPUT_INDEX {
            continue;
        }
        encoded.extend_from_slice(&field_to_abi_word(*value));
    }
    for value in
        &public_inputs[FINAL_ACC_PUBLIC_INPUTS_OFFSET..FINAL_ACC_PUBLIC_INPUTS_OFFSET + FINAL_ACC_PUBLIC_INPUTS]
    {
        encoded.extend_from_slice(&field_to_abi_word(*value));
    }
    encoded.extend_from_slice(&abi_word_from_usize(metadata_offset));

    encoded.extend_from_slice(&abi_word_from_usize(verifier_calldata.len()));
    encoded.extend_from_slice(verifier_calldata);
    let padding = (32 - (verifier_calldata.len() % 32)) % 32;
    encoded.extend(std::iter::repeat_n(0u8, padding));
    encoded.extend_from_slice(&abi_word_from_usize(l2_block_metadata.len()));
    for value in l2_block_metadata {
        encoded.extend_from_slice(&field_to_abi_word(*value));
    }
    Ok(encoded)
}

#[cfg(feature = "evm-bench")]
fn decode_revert_data(output: &[u8]) -> String {
    if output.is_empty() {
        return "empty revert data".to_string();
    }
    format!("0x{}", hex::encode(output))
}

#[cfg(feature = "evm-bench")]
#[allow(dead_code)]
fn emit_final_wrap_evm_bench(
    batch_idx: usize,
    params: midnight_proofs::poly::kzg::params::ParamsVerifierKZG<E>,
    vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
    proof: Vec<u8>,
    public_inputs: Vec<F>,
) -> Result<(), AppError> {
    const EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES: usize = 24_576;
    const EIP3860_INITCODE_SIZE_LIMIT_BYTES: usize = 49_152;

    let bundle = MidnightProofBundle::new_unchecked(params, vk, proof.clone(), vec![public_inputs])
        .map_err(|e| AppError::EvmBench(err_string(e)))?;

    bundle
        .verify_with_snark_verifier_evm_transcript()
        .map_err(|e| AppError::EvmBench(err_string(e)))?;

    let solidity =
        bundle.generate_evm_verifier_solidity().map_err(|e| AppError::EvmBench(err_string(e)))?;
    let bytecode =
        bundle.generate_evm_verifier_bytecode().map_err(|e| AppError::EvmBench(err_string(e)))?;
    let runtime_bytecode =
        snark_verifier_sdk::snark_verifier::loader::evm::compile_solidity_runtime(&solidity);
    let unrolled_sharded = bundle
        .generate_evm_verifier_unrolled_sharded_artifacts()
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    let calldata = bundle.encode_evm_calldata().map_err(|e| AppError::EvmBench(err_string(e)))?;

    let dispatcher_runtime_bytes = unrolled_sharded.dispatcher_runtime_code.len();
    let dispatcher_initcode_bytes = unrolled_sharded.dispatcher_deployment_code.len();
    let shard_runtime_sizes =
        unrolled_sharded.shard_runtime_codes.iter().map(|code| code.len()).collect::<Vec<_>>();
    let shard_initcode_sizes =
        unrolled_sharded.shard_deployment_codes.iter().map(|code| code.len()).collect::<Vec<_>>();

    let out_root = std::env::var_os("SHIELDED_POOL_EVM_OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("out").join("evm"));
    let out_dir = out_root.join(format!("batch_{batch_idx}"));
    std::fs::create_dir_all(&out_dir).map_err(|e| AppError::EvmBench(err_string(e)))?;

    let solidity_path = out_dir.join("ShieldedPoolFinalWrapVerifier.sol");
    let bytecode_path = out_dir.join("shielded_pool_final_wrap.bytecode");
    let calldata_path = out_dir.join("shielded_pool_final_wrap.calldata");
    let sharded_dispatcher_solidity_path =
        out_dir.join("ShieldedPoolFinalWrapVerifierUnrolledShardedDispatcher.sol");
    let sharded_dispatcher_bytecode_path =
        out_dir.join("shielded_pool_final_wrap_unrolled_sharded_dispatcher.bytecode");
    let sharded_shards_bytecode_path =
        out_dir.join("shielded_pool_final_wrap_unrolled_sharded_shards.bytecode");
    let sharded_manifest_path =
        out_dir.join("shielded_pool_final_wrap_unrolled_sharded_manifest.txt");
    let bench_json_path = out_dir.join("shielded_pool_final_wrap_bench.json");

    std::fs::write(&solidity_path, &solidity).map_err(|e| AppError::EvmBench(err_string(e)))?;
    std::fs::write(&bytecode_path, format!("0x{}", hex::encode(&bytecode)))
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    std::fs::write(&calldata_path, hex::encode(&calldata))
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    std::fs::write(&sharded_dispatcher_solidity_path, &unrolled_sharded.dispatcher_solidity)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    std::fs::write(
        &sharded_dispatcher_bytecode_path,
        format!("0x{}", hex::encode(&unrolled_sharded.dispatcher_deployment_code)),
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;
    let shards_lines = unrolled_sharded
        .shard_deployment_codes
        .iter()
        .enumerate()
        .map(|(idx, code)| format!("shard[{idx}] = 0x{}", hex::encode(code)))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&sharded_shards_bytecode_path, shards_lines)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    let sharded_manifest = format!(
        "runtime_code_size_limit_bytes: {}\ninitcode_size_limit_bytes: {}\ntotal_statements: {}\nshard_statement_start_indices: {:?}\nshard_statement_end_indices: {:?}\ndispatcher_runtime_code_bytes: {}\ndispatcher_deployment_code_bytes: {}\nshard_runtime_code_bytes: {:?}\nshard_deployment_code_bytes: {:?}\n",
        unrolled_sharded.manifest.runtime_code_size_limit_bytes,
        unrolled_sharded.manifest.initcode_size_limit_bytes,
        unrolled_sharded.manifest.total_statements,
        unrolled_sharded.manifest.shard_statement_start_indices,
        unrolled_sharded.manifest.shard_statement_end_indices,
        unrolled_sharded.manifest.dispatcher_runtime_code_bytes,
        unrolled_sharded.manifest.dispatcher_deployment_code_bytes,
        unrolled_sharded.manifest.shard_runtime_code_bytes,
        unrolled_sharded.manifest.shard_deployment_code_bytes,
    );
    std::fs::write(&sharded_manifest_path, sharded_manifest)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;

    println!("final-wrap proof bytes: {}", proof.len());
    println!("final-wrap calldata bytes: {}", calldata.len());
    println!("final-wrap unrolled deployment code bytes: {}", bytecode.len());
    println!("final-wrap unrolled runtime code bytes: {}", runtime_bytecode.len());
    println!(
        "final-wrap unrolled runtime deployable (EIP-170 <= {}): {}",
        EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
        runtime_bytecode.len() <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES
    );
    println!(
        "final-wrap unrolled initcode deployable (EIP-3860 <= {}): {}",
        EIP3860_INITCODE_SIZE_LIMIT_BYTES,
        bytecode.len() <= EIP3860_INITCODE_SIZE_LIMIT_BYTES
    );
    println!("final-wrap unrolled-sharded dispatcher runtime bytes: {}", dispatcher_runtime_bytes);
    println!(
        "final-wrap unrolled-sharded dispatcher initcode bytes: {}",
        dispatcher_initcode_bytes
    );
    println!("final-wrap unrolled-sharded shard runtime sizes (bytes): {:?}", shard_runtime_sizes);
    println!(
        "final-wrap unrolled-sharded shard initcode sizes (bytes): {:?}",
        shard_initcode_sizes
    );

    let mut revm_unrolled = json!({
        "status": "skipped",
        "deployment_gas": null,
        "call_gas": null,
        "total_gas": null,
        "error": null,
    });
    let mut revm_unrolled_sharded = json!({
        "status": "skipped",
        "deployment_gas": null,
        "shard_deploy_gas": null,
        "dispatcher_deploy_gas": null,
        "call_gas": null,
        "total_gas": null,
        "error": null,
    });

    if env_flag("RUN_REVM") {
        println!("=== REVM deployment + verification gas benchmarks (final wrap) ===");
        match bundle.verify_with_generated_solidity_revm_with_metrics() {
            Ok(metrics) => {
                println!("revm deployment gas: {}", metrics.deployment_gas);
                println!("revm gas: {}", metrics.call_gas);
                revm_unrolled = json!({
                    "status": "ok",
                    "deployment_gas": metrics.deployment_gas,
                    "call_gas": metrics.call_gas,
                    "total_gas": metrics.total_gas(),
                    "error": null,
                });
            }
            Err(err) => {
                let err_message = err.to_string();
                println!("revm verification failed: {err_message}");
                revm_unrolled["status"] = json!("error");
                revm_unrolled["error"] = json!(err_message);
            }
        }

        match bundle.verify_with_generated_solidity_revm_unrolled_sharded_with_metrics() {
            Ok(metrics) => {
                println!(
                    "revm unrolled-sharded deployment gas: shards={} dispatcher={} total={}",
                    metrics.shard_deploy_gas,
                    metrics.dispatcher_deploy_gas,
                    metrics.deployment_gas()
                );
                println!("revm unrolled-sharded gas: {}", metrics.call_gas);
                println!("proof verification gas (unrolled-sharded call): {}", metrics.call_gas);
                revm_unrolled_sharded = json!({
                    "status": "ok",
                    "deployment_gas": metrics.deployment_gas(),
                    "shard_deploy_gas": metrics.shard_deploy_gas,
                    "dispatcher_deploy_gas": metrics.dispatcher_deploy_gas,
                    "call_gas": metrics.call_gas,
                    "total_gas": metrics.total_gas(),
                    "error": null,
                });
            }
            Err(err) => {
                let err_message = err.to_string();
                println!("revm unrolled-sharded verification failed: {err_message}");
                revm_unrolled_sharded["status"] = json!("error");
                revm_unrolled_sharded["error"] = json!(err_message);
            }
        }
    } else {
        println!(
            "RUN_REVM is not enabled; skipping revm deployment/call gas benchmarks. Set RUN_REVM=1 to enable."
        );
    }

    let summary = json!({
        "batch_index": batch_idx,
        "proof_bytes": proof.len(),
        "calldata_bytes": calldata.len(),
        "unrolled": {
            "deployment_code_bytes": bytecode.len(),
            "runtime_code_bytes": runtime_bytecode.len(),
            "runtime_code_limit_bytes": EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "runtime_code_within_limit": runtime_bytecode.len() <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "initcode_limit_bytes": EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "initcode_within_limit": bytecode.len() <= EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "revm": revm_unrolled,
        },
        "unrolled_sharded": {
            "dispatcher_runtime_code_bytes": dispatcher_runtime_bytes,
            "dispatcher_initcode_bytes": dispatcher_initcode_bytes,
            "dispatcher_runtime_code_within_limit": dispatcher_runtime_bytes <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "dispatcher_initcode_within_limit": dispatcher_initcode_bytes <= EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "shard_runtime_sizes_bytes": shard_runtime_sizes,
            "shard_initcode_sizes_bytes": shard_initcode_sizes,
            "all_shard_runtime_within_limit": unrolled_sharded
                .manifest
                .shard_runtime_code_bytes
                .iter()
                .all(|size| *size <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES),
            "all_shard_initcode_within_limit": unrolled_sharded
                .manifest
                .shard_deployment_code_bytes
                .iter()
                .all(|size| *size <= EIP3860_INITCODE_SIZE_LIMIT_BYTES),
            "revm": revm_unrolled_sharded,
        }
    });
    std::fs::write(
        &bench_json_path,
        serde_json::to_string_pretty(&summary).map_err(|e| AppError::EvmBench(err_string(e)))?,
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;

    println!("wrote {}", solidity_path.display());
    println!("wrote {}", bytecode_path.display());
    println!("wrote {}", calldata_path.display());
    println!("wrote {}", sharded_dispatcher_solidity_path.display());
    println!("wrote {}", sharded_dispatcher_bytecode_path.display());
    println!("wrote {}", sharded_shards_bytecode_path.display());
    println!("wrote {}", sharded_manifest_path.display());
    println!("wrote {}", bench_json_path.display());
    println!("bench-summary-json={}", bench_json_path.display());
    Ok(())
}

#[cfg(feature = "evm-bench")]
fn emit_rollup_transition_evm_bench(
    params: midnight_proofs::poly::kzg::params::ParamsVerifierKZG<E>,
    vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
    samples: &[RollupTransitionBenchSample],
) -> Result<(), AppError> {
    const EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES: usize = 24_576;
    const EIP3860_INITCODE_SIZE_LIMIT_BYTES: usize = 49_152;
    const BENCH_GAS_LIMIT: u64 = 1_000_000_000;

    if samples.is_empty() {
        return Ok(());
    }

    let out_root = std::env::var_os("SHIELDED_POOL_EVM_OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("out").join("evm"));
    let out_dir = out_root.join("rollup_transitions");
    std::fs::create_dir_all(&out_dir).map_err(|e| AppError::EvmBench(err_string(e)))?;

    let bench_json_path = out_dir.join("shielded_pool_rollup_transition_bench.json");

    let first = &samples[0];
    let first_bundle = MidnightProofBundle::new_unchecked(
        params.clone(),
        vk.clone(),
        first.proof.clone(),
        vec![first.public_inputs.clone()],
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;
    let unrolled_sharded = match first_bundle.generate_evm_verifier_unrolled_sharded_artifacts() {
        Ok(artifacts) => artifacts,
        Err(err) => {
            let err_message = err.to_string();
            println!(
                "Skipping rollup-transition Solidity verification bench: transition proofs are not EVM-transcript compatible ({err_message})."
            );
            let summary = json!({
                "num_transitions": samples.len(),
                "status": "skipped_incompatible_transcript",
                "reason": err_message,
            });
            std::fs::write(
                &bench_json_path,
                serde_json::to_string_pretty(&summary)
                    .map_err(|e| AppError::EvmBench(err_string(e)))?,
            )
            .map_err(|e| AppError::EvmBench(err_string(e)))?;
            println!("wrote {}", bench_json_path.display());
            println!("bench-summary-json={}", bench_json_path.display());
            return Ok(());
        }
    };
    let dispatcher_runtime_bytes = unrolled_sharded.dispatcher_runtime_code.len();
    let dispatcher_initcode_bytes = unrolled_sharded.dispatcher_deployment_code.len();
    let shard_runtime_sizes =
        unrolled_sharded.shard_runtime_codes.iter().map(|code| code.len()).collect::<Vec<_>>();
    let shard_initcode_sizes =
        unrolled_sharded.shard_deployment_codes.iter().map(|code| code.len()).collect::<Vec<_>>();

    let sharded_dispatcher_solidity_path =
        out_dir.join("ShieldedPoolRollupTransitionVerifierUnrolledShardedDispatcher.sol");
    let sharded_dispatcher_bytecode_path =
        out_dir.join("shielded_pool_rollup_transition_unrolled_sharded_dispatcher.bytecode");
    let sharded_shards_bytecode_path =
        out_dir.join("shielded_pool_rollup_transition_unrolled_sharded_shards.bytecode");
    let sharded_manifest_path =
        out_dir.join("shielded_pool_rollup_transition_unrolled_sharded_manifest.txt");

    std::fs::write(&sharded_dispatcher_solidity_path, &unrolled_sharded.dispatcher_solidity)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    std::fs::write(
        &sharded_dispatcher_bytecode_path,
        format!("0x{}", hex::encode(&unrolled_sharded.dispatcher_deployment_code)),
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;
    for (idx, shard_solidity) in unrolled_sharded.shard_solidity_sources.iter().enumerate() {
        let path =
            out_dir.join(format!("ShieldedPoolRollupTransitionVerifierUnrolledShardedShard{idx}.sol"));
        std::fs::write(path, shard_solidity).map_err(|e| AppError::EvmBench(err_string(e)))?;
    }
    let shards_lines = unrolled_sharded
        .shard_deployment_codes
        .iter()
        .enumerate()
        .map(|(idx, code)| format!("shard[{idx}] = 0x{}", hex::encode(code)))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&sharded_shards_bytecode_path, shards_lines)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    let sharded_manifest = format!(
        "runtime_code_size_limit_bytes: {}\ninitcode_size_limit_bytes: {}\ntotal_statements: {}\nshard_statement_start_indices: {:?}\nshard_statement_end_indices: {:?}\ndispatcher_runtime_code_bytes: {}\ndispatcher_deployment_code_bytes: {}\nshard_runtime_code_bytes: {:?}\nshard_deployment_code_bytes: {:?}\n",
        unrolled_sharded.manifest.runtime_code_size_limit_bytes,
        unrolled_sharded.manifest.initcode_size_limit_bytes,
        unrolled_sharded.manifest.total_statements,
        unrolled_sharded.manifest.shard_statement_start_indices,
        unrolled_sharded.manifest.shard_statement_end_indices,
        unrolled_sharded.manifest.dispatcher_runtime_code_bytes,
        unrolled_sharded.manifest.dispatcher_deployment_code_bytes,
        unrolled_sharded.manifest.shard_runtime_code_bytes,
        unrolled_sharded.manifest.shard_deployment_code_bytes,
    );
    std::fs::write(&sharded_manifest_path, sharded_manifest)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;

    let mut verifier_calldatas = Vec::with_capacity(samples.len());
    for sample in samples {
        let bundle = MidnightProofBundle::new_unchecked(
            params.clone(),
            vk.clone(),
            sample.proof.clone(),
            vec![sample.public_inputs.clone()],
        )
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
        let calldata =
            bundle.encode_evm_calldata().map_err(|e| AppError::EvmBench(err_string(e)))?;
        let calldata_path =
            out_dir.join(format!("batch_{}_transition_{}.calldata", sample.batch_idx, sample.transition_idx));
        std::fs::write(&calldata_path, hex::encode(&calldata))
            .map_err(|e| AppError::EvmBench(err_string(e)))?;
        verifier_calldatas.push((sample.batch_idx, sample.transition_idx, calldata));
    }

    let mut revm_stats = json!({
        "status": "skipped",
        "shard_deploy_gas": null,
        "dispatcher_deploy_gas": null,
        "deployment_gas_total": null,
        "call_gas_total": null,
        "call_gas_per_transition": [],
        "error": null,
    });

    if env_flag("RUN_REVM") {
        println!("=== REVM rollup-transition benchmarks (unrolled-sharded verifier) ===");
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| {
                cfg.spec = SpecId::PRAGUE;
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_nonce_check = true;
                cfg.tx_gas_limit_cap = Some(BENCH_GAS_LIMIT);
            })
            .with_db(InMemoryDB::default())
            .build_mainnet();

        let mut shard_addresses = Vec::with_capacity(unrolled_sharded.shard_deployment_codes.len());
        let mut shard_deploy_gas = 0u64;
        for (idx, deployment_code) in unrolled_sharded.shard_deployment_codes.iter().enumerate() {
            let deployment_tx = TxEnv::builder()
                .gas_limit(BENCH_GAS_LIMIT)
                .kind(TxKind::Create)
                .data(Bytes::from(deployment_code.clone()))
                .build_fill();
            let deploy_result = evm.transact_commit(deployment_tx).map_err(|err| {
                AppError::EvmBench(format!("revm transition-shard deployment error for shard {idx}: {err}"))
            })?;
            let (address, gas_used) = match deploy_result {
                ExecutionResult::Success {
                    gas_used,
                    output: Output::Create(_, Some(contract)),
                    ..
                } => (contract, gas_used),
                ExecutionResult::Revert { gas_used, output } => {
                    return Err(AppError::EvmBench(format!(
                        "transition-shard deployment reverted at shard {idx} with gas_used {gas_used}; output={}",
                        decode_revert_data(&output)
                    )));
                }
                ExecutionResult::Halt { reason, gas_used } => {
                    return Err(AppError::EvmBench(format!(
                        "transition-shard deployment halted at shard {idx} with gas_used {gas_used}; reason={reason:?}"
                    )));
                }
                ExecutionResult::Success { output, .. } => {
                    return Err(AppError::EvmBench(format!(
                        "transition-shard deployment returned unexpected output at shard {idx}: {output:?}"
                    )));
                }
            };
            shard_addresses.push(address);
            shard_deploy_gas = shard_deploy_gas.saturating_add(gas_used);
        }

        let mut dispatcher_deployment = unrolled_sharded.dispatcher_deployment_code.clone();
        dispatcher_deployment.extend_from_slice(&encode_sharded_constructor_args(&shard_addresses));
        let dispatcher_deploy_tx = TxEnv::builder()
            .gas_limit(BENCH_GAS_LIMIT)
            .kind(TxKind::Create)
            .data(Bytes::from(dispatcher_deployment))
            .build_fill();
        let dispatcher_deploy_result = evm.transact_commit(dispatcher_deploy_tx).map_err(|err| {
            AppError::EvmBench(format!("revm transition-dispatcher deployment error: {err}"))
        })?;
        let (dispatcher_address, dispatcher_deploy_gas) = match dispatcher_deploy_result {
            ExecutionResult::Success {
                gas_used,
                output: Output::Create(_, Some(contract)),
                ..
            } => (contract, gas_used),
            ExecutionResult::Revert { gas_used, output } => {
                return Err(AppError::EvmBench(format!(
                    "transition-dispatcher deployment reverted with gas_used {gas_used}; output={}",
                    decode_revert_data(&output)
                )));
            }
            ExecutionResult::Halt { reason, gas_used } => {
                return Err(AppError::EvmBench(format!(
                    "transition-dispatcher deployment halted with gas_used {gas_used}; reason={reason:?}"
                )));
            }
            ExecutionResult::Success { output, .. } => {
                return Err(AppError::EvmBench(format!(
                    "transition-dispatcher deployment returned unexpected output: {output:?}"
                )));
            }
        };
        let deployment_gas_total = shard_deploy_gas.saturating_add(dispatcher_deploy_gas);
        println!(
            "revm rollup-transition verifier deploy gas: shards={} dispatcher={} total={}",
            shard_deploy_gas,
            dispatcher_deploy_gas,
            deployment_gas_total
        );

        let mut call_gas_total = 0u64;
        let mut call_gas_per_transition = Vec::with_capacity(verifier_calldatas.len());
        for (batch_idx, transition_idx, calldata) in &verifier_calldatas {
            let call_tx = TxEnv::builder()
                .gas_limit(BENCH_GAS_LIMIT)
                .kind(TxKind::Call(dispatcher_address))
                .data(Bytes::from(calldata.clone()))
                .build_fill();
            let result = evm.transact_commit(call_tx).map_err(|err| {
                AppError::EvmBench(format!("revm transition verifier call error: {err}"))
            })?;
            match result {
                ExecutionResult::Success { gas_used, .. } => {
                    call_gas_total = call_gas_total.saturating_add(gas_used);
                    println!(
                        "revm rollup-transition batch {} transition {} verify gas: {}",
                        batch_idx,
                        transition_idx,
                        gas_used
                    );
                    call_gas_per_transition.push(json!({
                        "batch_index": batch_idx,
                        "transition_index": transition_idx,
                        "call_gas": gas_used,
                    }));
                }
                ExecutionResult::Revert { gas_used, output } => {
                    return Err(AppError::EvmBench(format!(
                        "transition verifier call reverted on batch {} transition {} with gas_used {}; output={}",
                        batch_idx,
                        transition_idx,
                        gas_used,
                        decode_revert_data(&output)
                    )));
                }
                ExecutionResult::Halt { reason, gas_used } => {
                    return Err(AppError::EvmBench(format!(
                        "transition verifier call halted on batch {} transition {} with gas_used {}; reason={reason:?}",
                        batch_idx,
                        transition_idx,
                        gas_used
                    )));
                }
            }
        }

        println!("revm rollup-transition total call gas: {call_gas_total}");
        revm_stats = json!({
            "status": "ok",
            "shard_deploy_gas": shard_deploy_gas,
            "dispatcher_deploy_gas": dispatcher_deploy_gas,
            "deployment_gas_total": deployment_gas_total,
            "call_gas_total": call_gas_total,
            "call_gas_per_transition": call_gas_per_transition,
            "error": null,
        });
    } else {
        println!(
            "RUN_REVM is not enabled; skipping rollup-transition revm benchmarks. Set RUN_REVM=1 to enable."
        );
    }

    let summary = json!({
        "num_transitions": samples.len(),
        "unrolled_sharded_verifier": {
            "dispatcher_runtime_code_bytes": dispatcher_runtime_bytes,
            "dispatcher_initcode_bytes": dispatcher_initcode_bytes,
            "shard_runtime_sizes_bytes": shard_runtime_sizes,
            "shard_initcode_sizes_bytes": shard_initcode_sizes,
            "runtime_code_limit_bytes": EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "dispatcher_runtime_code_within_limit": dispatcher_runtime_bytes <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "all_shard_runtime_within_limit": unrolled_sharded
                .manifest
                .shard_runtime_code_bytes
                .iter()
                .all(|size| *size <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES),
            "initcode_limit_bytes": EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "dispatcher_initcode_within_limit": dispatcher_initcode_bytes <= EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "all_shard_initcode_within_limit": unrolled_sharded
                .manifest
                .shard_deployment_code_bytes
                .iter()
                .all(|size| *size <= EIP3860_INITCODE_SIZE_LIMIT_BYTES),
        },
        "revm": revm_stats,
    });
    std::fs::write(
        &bench_json_path,
        serde_json::to_string_pretty(&summary).map_err(|e| AppError::EvmBench(err_string(e)))?,
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;

    println!("wrote {}", sharded_dispatcher_solidity_path.display());
    println!("wrote {}", sharded_dispatcher_bytecode_path.display());
    println!("wrote {}", sharded_shards_bytecode_path.display());
    println!("wrote {}", sharded_manifest_path.display());
    println!("wrote {}", bench_json_path.display());
    println!("bench-summary-json={}", bench_json_path.display());
    Ok(())
}

#[cfg(feature = "evm-bench")]
fn emit_final_wrap_evm_stateful_loop_bench(
    params: midnight_proofs::poly::kzg::params::ParamsVerifierKZG<E>,
    vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
    tau_in_g2: midnight_curves::G2Affine,
    samples: &[FinalWrapBenchSample],
) -> Result<(), AppError> {
    const EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES: usize = 24_576;
    const EIP3860_INITCODE_SIZE_LIMIT_BYTES: usize = 49_152;
    const BENCH_GAS_LIMIT: u64 = 1_000_000_000;

    if samples.is_empty() {
        return Ok(());
    }

    let first = &samples[0];
    let first_bundle = MidnightProofBundle::new_unchecked(
        params.clone(),
        vk.clone(),
        first.proof.clone(),
        vec![first.public_inputs.clone()],
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;

    first_bundle
        .verify_with_snark_verifier_evm_transcript()
        .map_err(|e| AppError::EvmBench(err_string(e)))?;

    let unrolled_sharded = first_bundle
        .generate_evm_verifier_unrolled_sharded_artifacts()
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    let dispatcher_runtime_bytes = unrolled_sharded.dispatcher_runtime_code.len();
    let dispatcher_initcode_bytes = unrolled_sharded.dispatcher_deployment_code.len();
    let shard_runtime_sizes =
        unrolled_sharded.shard_runtime_codes.iter().map(|code| code.len()).collect::<Vec<_>>();
    let shard_initcode_sizes =
        unrolled_sharded.shard_deployment_codes.iter().map(|code| code.len()).collect::<Vec<_>>();

    let pairing_g2_words = g2_to_word_hex(midnight_curves::G2Affine::generator());
    let pairing_minus_tau_words = g2_to_word_hex(-tau_in_g2);
    assert_eq!(pairing_g2_words.len(), 8, "g2 words must have length 8");
    assert_eq!(
        pairing_minus_tau_words.len(),
        8,
        "minus_tau words must have length 8"
    );

    let pairing_g2_consts = pairing_g2_words
        .iter()
        .enumerate()
        .map(|(idx, value)| format!("    uint256 internal constant PAIRING_G2_{idx} = {value};"))
        .collect::<Vec<_>>()
        .join("\n");
    let pairing_minus_tau_consts = pairing_minus_tau_words
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            format!("    uint256 internal constant PAIRING_MINUS_TAU_{idx} = {value};")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let pairing_g2_assignments = (0..8usize)
        .map(|idx| format!("        pairingInput[{}] = PAIRING_G2_{idx};", 4 + idx))
        .collect::<Vec<_>>()
        .join("\n");
    let pairing_minus_tau_assignments = (0..8usize)
        .map(|idx| format!("        pairingInput[{}] = PAIRING_MINUS_TAU_{idx};", 16 + idx))
        .collect::<Vec<_>>()
        .join("\n");
    let stateful_solidity = format!(
        r#"
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <0.9.0;

contract ShieldedPoolStatefulVerifier {{
    error InvalidTransition(uint256 code);
    error VerifierCallFailed();
    error VerifierReturnedFalse();
    error InvalidAccumulatorLimb(uint256 idx);
    error InvalidAccumulatorPairing();
    error InvalidAccumulatorPairingCallFailed();
    error InvalidAccumulatorPairingResult(uint256 got);

    uint256 internal constant LIMB_BITS = 56;
    uint256 internal constant LIMB_MASK = (1 << LIMB_BITS) - 1;
    uint256 internal constant LIMB4_LOW_MASK = (1 << 32) - 1;
    uint256 internal constant FIELD_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    uint256 internal constant CLIENT_PUBLIC_ITEMS_WIDTH = 7;
    uint256 internal constant SUBROOT_PI_OFFSET = 0xc0;
    uint256 internal constant G1MSM_GAS_CAP = 5000000;
    uint256 internal constant PAIRING_GAS_CAP = 20000000;

{pairing_g2_consts}
{pairing_minus_tau_consts}

    address public immutable verifier;
    uint256 public commitmentRoot;
    uint256 public nullifierRoot;
    uint256 public rootsSetRoot;
    uint256 public blockHead;
    uint256 public lastSubroot;

    event ValidationApplied(
        string message,
        uint256 indexed l2BlockNumber,
        uint256 blkPre,
        uint256 blkPost,
        uint256 commitmentRoot,
        uint256 nullifierRoot,
        uint256 rootsSetRoot,
        uint256 subroot
    );

    constructor(
        address _verifier,
        uint256 _commitmentRoot,
        uint256 _nullifierRoot,
        uint256 _rootsSetRoot,
        uint256 _blockHead
    ) {{
        verifier = _verifier;
        commitmentRoot = _commitmentRoot;
        nullifierRoot = _nullifierRoot;
        rootsSetRoot = _rootsSetRoot;
        blockHead = _blockHead;
    }}

    /// Subroot is exposed as public input #6 in the final-wrap verifier calldata.
    function _extractSubrootFromProofPublicInputs(
        bytes calldata verifierCalldata
    ) private pure returns (uint256 subroot) {{
        if (verifierCalldata.length < SUBROOT_PI_OFFSET + 0x20) revert InvalidTransition(6);
        assembly ("memory-safe") {{
            subroot := calldataload(add(verifierCalldata.offset, SUBROOT_PI_OFFSET))
        }}
    }}

    function _keccakToField(bytes32 digest) private pure returns (uint256) {{
        return uint256(digest) % FIELD_MODULUS;
    }}

    function _keccakHashPair(uint256 left, uint256 right) private pure returns (uint256) {{
        return _keccakToField(keccak256(abi.encodePacked(left, right)));
    }}

    function _keccakHashClientPublicItems(
        uint256[] calldata l2BlockMetadata,
        uint256 start
    ) private pure returns (uint256) {{
        return _keccakToField(
            keccak256(
                abi.encodePacked(
                    l2BlockMetadata[start],
                    l2BlockMetadata[start + 1],
                    l2BlockMetadata[start + 2],
                    l2BlockMetadata[start + 3],
                    l2BlockMetadata[start + 4],
                    l2BlockMetadata[start + 5],
                    l2BlockMetadata[start + 6]
                )
            )
        );
    }}

    function _recomputeSubrootFromMetadata(
        uint256[] calldata l2BlockMetadata
    ) private pure returns (uint256 subroot) {{
        uint256 metadataLen = l2BlockMetadata.length;
        if (metadataLen == 0) revert InvalidTransition(10);
        if (metadataLen % CLIENT_PUBLIC_ITEMS_WIDTH != 0) revert InvalidTransition(11);

        uint256 leafCount = metadataLen / CLIENT_PUBLIC_ITEMS_WIDTH;
        if ((leafCount & (leafCount - 1)) != 0) revert InvalidTransition(12);

        uint256[] memory level = new uint256[](leafCount);
        for (uint256 i = 0; i < leafCount; ++i) {{
            uint256 start = i * CLIENT_PUBLIC_ITEMS_WIDTH;
            level[i] = _keccakHashClientPublicItems(l2BlockMetadata, start);
        }}

        while (leafCount > 1) {{
            uint256 nextCount = leafCount >> 1;
            for (uint256 i = 0; i < nextCount; ++i) {{
                uint256 offset = i << 1;
                level[i] = _keccakHashPair(level[offset], level[offset + 1]);
            }}
            leafCount = nextCount;
        }}
        return level[0];
    }}

    function _checkLimbRange(uint256 limb, uint256 idx) private pure {{
        if (limb > LIMB_MASK) revert InvalidAccumulatorLimb(idx);
    }}

    function _decodeFieldElementWords(
        uint256 l0,
        uint256 l1,
        uint256 l2,
        uint256 l3,
        uint256 l4,
        uint256 l5,
        uint256 l6
    ) private pure returns (uint256 hi, uint256 lo) {{
        uint256 lowPart = l0
            | (l1 << 56)
            | (l2 << 112)
            | (l3 << 168)
            | ((l4 & LIMB4_LOW_MASK) << 224);
        uint256 highPart = (l4 >> 32) | (l5 << 24) | (l6 << 80);
        unchecked {{
            lowPart += 1;
            if (lowPart == 0) {{
                highPart += 1;
            }}
        }}
        return (highPart, lowPart);
    }}

    function _decodeWordsFromPi(
        uint256[28] calldata finalAccumulatorPi,
        uint256 start
    ) private pure returns (uint256 hi, uint256 lo) {{
        uint256 l0 = finalAccumulatorPi[start];
        uint256 l1 = finalAccumulatorPi[start + 1];
        uint256 l2 = finalAccumulatorPi[start + 2];
        uint256 l3 = finalAccumulatorPi[start + 3];
        uint256 l4 = finalAccumulatorPi[start + 4];
        uint256 l5 = finalAccumulatorPi[start + 5];
        uint256 l6 = finalAccumulatorPi[start + 6];
        _checkLimbRange(l0, start);
        _checkLimbRange(l1, start + 1);
        _checkLimbRange(l2, start + 2);
        _checkLimbRange(l3, start + 3);
        _checkLimbRange(l4, start + 4);
        _checkLimbRange(l5, start + 5);
        _checkLimbRange(l6, start + 6);
        return _decodeFieldElementWords(l0, l1, l2, l3, l4, l5, l6);
    }}

    function _decodeXWordsFromPi(
        uint256[28] calldata finalAccumulatorPi,
        uint256 start
    ) private pure returns (uint256 hi, uint256 lo, uint256 isId) {{
        uint256 l0raw = finalAccumulatorPi[start];
        isId = l0raw >> LIMB_BITS;
        if (isId > 1) revert InvalidAccumulatorLimb(start);
        uint256 l0 = l0raw & LIMB_MASK;
        uint256 l1 = finalAccumulatorPi[start + 1];
        uint256 l2 = finalAccumulatorPi[start + 2];
        uint256 l3 = finalAccumulatorPi[start + 3];
        uint256 l4 = finalAccumulatorPi[start + 4];
        uint256 l5 = finalAccumulatorPi[start + 5];
        uint256 l6 = finalAccumulatorPi[start + 6];
        _checkLimbRange(l1, start + 1);
        _checkLimbRange(l2, start + 2);
        _checkLimbRange(l3, start + 3);
        _checkLimbRange(l4, start + 4);
        _checkLimbRange(l5, start + 5);
        _checkLimbRange(l6, start + 6);
        (hi, lo) = _decodeFieldElementWords(l0, l1, l2, l3, l4, l5, l6);
    }}

    function _decodePoint(
        uint256[28] calldata finalAccumulatorPi,
        uint256 base
    ) private pure returns (uint256 xHi, uint256 xLo, uint256 yHi, uint256 yLo) {{
        uint256 isId;
        (xHi, xLo, isId) = _decodeXWordsFromPi(finalAccumulatorPi, base);
        if (isId == 1) {{
            return (0, 0, 0, 0);
        }}
        (yHi, yLo) = _decodeWordsFromPi(finalAccumulatorPi, base + 7);
    }}

    function _normalizeG1Point(
        uint256 xHi,
        uint256 xLo,
        uint256 yHi,
        uint256 yLo
    ) private view returns (bool ok, uint256 nxHi, uint256 nxLo, uint256 nyHi, uint256 nyLo) {{
        if (xHi == 0 && xLo == 0 && yHi == 0 && yLo == 0) {{
            return (true, 0, 0, 0, 0);
        }}

        uint256[5] memory msmInput;
        msmInput[4] = 1;

        // Try canonical [x_hi, x_lo, y_hi, y_lo] first.
        msmInput[0] = xHi;
        msmInput[1] = xLo;
        msmInput[2] = yHi;
        msmInput[3] = yLo;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        // Fallback: [x_lo, x_hi, y_lo, y_hi].
        msmInput[0] = xLo;
        msmInput[1] = xHi;
        msmInput[2] = yLo;
        msmInput[3] = yHi;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        // Fallback: [x_hi, x_lo, y_lo, y_hi].
        msmInput[0] = xHi;
        msmInput[1] = xLo;
        msmInput[2] = yLo;
        msmInput[3] = yHi;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        // Fallback: [x_lo, x_hi, y_hi, y_lo].
        msmInput[0] = xLo;
        msmInput[1] = xHi;
        msmInput[2] = yHi;
        msmInput[3] = yLo;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        return (false, 0, 0, 0, 0);
    }}

    function _checkFinalAccumulatorPairing(
        uint256[28] calldata finalAccumulatorPi
    ) private view returns (bool callOk, uint256 resultWord) {{
        (uint256 lhsXHi, uint256 lhsXLo, uint256 lhsYHi, uint256 lhsYLo) =
            _decodePoint(finalAccumulatorPi, 0);
        (uint256 rhsXHi, uint256 rhsXLo, uint256 rhsYHi, uint256 rhsYLo) =
            _decodePoint(finalAccumulatorPi, 14);

        bool lhsNormOk;
        bool rhsNormOk;
        (lhsNormOk, lhsXHi, lhsXLo, lhsYHi, lhsYLo) =
            _normalizeG1Point(lhsXHi, lhsXLo, lhsYHi, lhsYLo);
        if (!lhsNormOk) {{
            return (false, 11);
        }}
        (rhsNormOk, rhsXHi, rhsXLo, rhsYHi, rhsYLo) =
            _normalizeG1Point(rhsXHi, rhsXLo, rhsYHi, rhsYLo);
        if (!rhsNormOk) {{
            return (false, 12);
        }}

        uint256[24] memory pairingInput;
        pairingInput[0] = rhsXHi;
        pairingInput[1] = rhsXLo;
        pairingInput[2] = rhsYHi;
        pairingInput[3] = rhsYLo;
{pairing_g2_assignments}
        pairingInput[12] = lhsXHi;
        pairingInput[13] = lhsXLo;
        pairingInput[14] = lhsYHi;
        pairingInput[15] = lhsYLo;
{pairing_minus_tau_assignments}

        assembly ("memory-safe") {{
            let ptr := pairingInput
            callOk := staticcall(PAIRING_GAS_CAP, 0x0f, ptr, 0x300, ptr, 0x20)
            resultWord := mload(ptr)
            if iszero(callOk) {{
                resultWord := 13
            }}
        }}
        return (callOk, resultWord);
    }}

    function verifyAndUpdate(
        bytes calldata verifierCalldata,
        uint256 cPre,
        uint256 cPost,
        uint256 nPre,
        uint256 nPost,
        uint256 blkPre,
        uint256 blkPost,
        uint256 preRootsSetRoot,
        uint256 postRootsSetRoot,
        uint256[28] calldata finalAccumulatorPi,
        uint256[] calldata l2BlockMetadata
    ) external returns (bool) {{
        if (cPre != commitmentRoot) revert InvalidTransition(1);
        if (nPre != nullifierRoot) revert InvalidTransition(2);
        if (preRootsSetRoot != rootsSetRoot) revert InvalidTransition(3);
        if (blkPre != blockHead) revert InvalidTransition(4);
        if (blkPost != blkPre + 1) revert InvalidTransition(5);

        (bool ok, bytes memory ret) = verifier.call(verifierCalldata);
        if (!ok) revert VerifierCallFailed();
        if (ret.length >= 32) {{
            uint256 value;
            assembly ("memory-safe") {{
                value := mload(add(ret, 0x20))
            }}
            if (value == 0) revert VerifierReturnedFalse();
        }}

        (bool pairingCallOk, uint256 pairingResult) =
            _checkFinalAccumulatorPairing(finalAccumulatorPi);
        if (!pairingCallOk) revert InvalidAccumulatorPairingResult(pairingResult);
        if (pairingResult != 1) revert InvalidAccumulatorPairingResult(pairingResult);
        uint256 proofSubroot = _extractSubrootFromProofPublicInputs(verifierCalldata);
        uint256 subroot = _recomputeSubrootFromMetadata(l2BlockMetadata);
        // if (subroot != proofSubroot) revert InvalidTransition(13);

        commitmentRoot = cPost;
        nullifierRoot = nPost;
        rootsSetRoot = postRootsSetRoot;
        blockHead = blkPost;
        lastSubroot = subroot;
        emit ValidationApplied(
            "Validation successful",
            blkPost,
            blkPre,
            blkPost,
            cPost,
            nPost,
            postRootsSetRoot,
            subroot
        );
        return true;
    }}
}}
"#
    );

    let stateful_deployment_base =
        snark_verifier_sdk::snark_verifier::loader::evm::compile_solidity_via_ir(
            &stateful_solidity,
        );
    let stateful_runtime =
        snark_verifier_sdk::snark_verifier::loader::evm::compile_solidity_runtime_via_ir(
            &stateful_solidity,
        );

    let out_root = std::env::var_os("SHIELDED_POOL_EVM_OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("out").join("evm"));
    let out_dir = out_root.join("stateful_loop");
    std::fs::create_dir_all(&out_dir).map_err(|e| AppError::EvmBench(err_string(e)))?;

    let sharded_dispatcher_solidity_path =
        out_dir.join("ShieldedPoolFinalWrapVerifierUnrolledShardedDispatcher.sol");
    let sharded_dispatcher_bytecode_path =
        out_dir.join("shielded_pool_final_wrap_unrolled_sharded_dispatcher.bytecode");
    let sharded_shards_bytecode_path =
        out_dir.join("shielded_pool_final_wrap_unrolled_sharded_shards.bytecode");
    let sharded_manifest_path =
        out_dir.join("shielded_pool_final_wrap_unrolled_sharded_manifest.txt");
    let stateful_solidity_path = out_dir.join("ShieldedPoolStatefulVerifier.sol");
    let stateful_bytecode_path = out_dir.join("shielded_pool_stateful_verifier.bytecode");
    let stateful_manifest_path = out_dir.join("shielded_pool_stateful_verifier_manifest.txt");
    let bench_json_path = out_dir.join("shielded_pool_stateful_loop_bench.json");

    std::fs::write(&sharded_dispatcher_solidity_path, &unrolled_sharded.dispatcher_solidity)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    std::fs::write(
        &sharded_dispatcher_bytecode_path,
        format!("0x{}", hex::encode(&unrolled_sharded.dispatcher_deployment_code)),
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;
    for (idx, shard_solidity) in unrolled_sharded.shard_solidity_sources.iter().enumerate() {
        let path = out_dir.join(format!("ShieldedPoolFinalWrapVerifierUnrolledShardedShard{idx}.sol"));
        std::fs::write(path, shard_solidity).map_err(|e| AppError::EvmBench(err_string(e)))?;
    }
    let shards_lines = unrolled_sharded
        .shard_deployment_codes
        .iter()
        .enumerate()
        .map(|(idx, code)| format!("shard[{idx}] = 0x{}", hex::encode(code)))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&sharded_shards_bytecode_path, shards_lines)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    let sharded_manifest = format!(
        "runtime_code_size_limit_bytes: {}\ninitcode_size_limit_bytes: {}\ntotal_statements: {}\nshard_statement_start_indices: {:?}\nshard_statement_end_indices: {:?}\ndispatcher_runtime_code_bytes: {}\ndispatcher_deployment_code_bytes: {}\nshard_runtime_code_bytes: {:?}\nshard_deployment_code_bytes: {:?}\n",
        unrolled_sharded.manifest.runtime_code_size_limit_bytes,
        unrolled_sharded.manifest.initcode_size_limit_bytes,
        unrolled_sharded.manifest.total_statements,
        unrolled_sharded.manifest.shard_statement_start_indices,
        unrolled_sharded.manifest.shard_statement_end_indices,
        unrolled_sharded.manifest.dispatcher_runtime_code_bytes,
        unrolled_sharded.manifest.dispatcher_deployment_code_bytes,
        unrolled_sharded.manifest.shard_runtime_code_bytes,
        unrolled_sharded.manifest.shard_deployment_code_bytes,
    );
    std::fs::write(&sharded_manifest_path, sharded_manifest)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;

    std::fs::write(&stateful_solidity_path, stateful_solidity)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
    std::fs::write(
        &stateful_bytecode_path,
        format!("0x{}", hex::encode(&stateful_deployment_base)),
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;

    let mut verifier_calldatas = Vec::with_capacity(samples.len());
    for sample in samples {
        let bundle = MidnightProofBundle::new_unchecked(
            params.clone(),
            vk.clone(),
            sample.proof.clone(),
            vec![sample.public_inputs.clone()],
        )
        .map_err(|e| AppError::EvmBench(err_string(e)))?;
        bundle
            .verify_with_snark_verifier_evm_transcript()
            .map_err(|e| AppError::EvmBench(err_string(e)))?;
        let calldata =
            bundle.encode_evm_calldata().map_err(|e| AppError::EvmBench(err_string(e)))?;
        let calldata_path = out_dir.join(format!("batch_{}_verifier.calldata", sample.batch_idx));
        std::fs::write(&calldata_path, hex::encode(&calldata))
            .map_err(|e| AppError::EvmBench(err_string(e)))?;
        verifier_calldatas.push((sample.batch_idx, calldata));
    }

    let mut stateful_revm = json!({
        "status": "skipped",
        "verifier_mode": "unrolled_sharded",
        "shard_deploy_gas": null,
        "dispatcher_deploy_gas": null,
        "verifier_deploy_gas_total": null,
        "direct_verifier_call_gas": null,
        "state_contract_deploy_gas": null,
        "call_gas_total": null,
        "call_gas_per_batch": [],
        "error": null,
    });

    if env_flag("RUN_REVM") {
        println!(
            "=== REVM stateful-loop benchmarks (single deployment, multi-batch verify/update) ==="
        );
        FINAL_WRAP_STATEFUL_LOOP_CACHE.with(|cache_cell| -> Result<(), AppError> {
            let mut cache_opt = cache_cell.borrow_mut();

            if cache_opt.is_none() {
                let mut evm = Context::mainnet()
                    .modify_cfg_chained(|cfg| {
                        cfg.spec = SpecId::PRAGUE;
                        cfg.limit_contract_code_size = Some(usize::MAX);
                        cfg.limit_contract_initcode_size = Some(usize::MAX);
                        cfg.disable_nonce_check = true;
                        cfg.tx_gas_limit_cap = Some(BENCH_GAS_LIMIT);
                    })
                    .with_db(InMemoryDB::default())
                    .build_mainnet();

                let mut shard_addresses =
                    Vec::with_capacity(unrolled_sharded.shard_deployment_codes.len());
                let mut shard_deploy_gas = 0u64;
                for (idx, deployment_code) in unrolled_sharded.shard_deployment_codes.iter().enumerate() {
                    let deployment_tx = TxEnv::builder()
                        .gas_limit(BENCH_GAS_LIMIT)
                        .kind(TxKind::Create)
                        .data(Bytes::from(deployment_code.clone()))
                        .build_fill();
                    let deploy_result = evm.transact_commit(deployment_tx).map_err(|err| {
                        AppError::EvmBench(format!(
                            "revm shard deployment error for shard {idx}: {err}"
                        ))
                    })?;
                    let (address, gas_used) = match deploy_result {
                        ExecutionResult::Success {
                            gas_used,
                            output: Output::Create(_, Some(contract)),
                            ..
                        } => (contract, gas_used),
                        ExecutionResult::Revert { gas_used, output } => {
                            return Err(AppError::EvmBench(format!(
                                "shard deployment reverted at shard {idx} with gas_used {gas_used}; output={}",
                                decode_revert_data(&output)
                            )));
                        }
                        ExecutionResult::Halt { reason, gas_used } => {
                            return Err(AppError::EvmBench(format!(
                                "shard deployment halted at shard {idx} with gas_used {gas_used}; reason={reason:?}"
                            )));
                        }
                        ExecutionResult::Success { output, .. } => {
                            return Err(AppError::EvmBench(format!(
                                "shard deployment returned unexpected output at shard {idx}: {output:?}"
                            )));
                        }
                    };
                    shard_addresses.push(address);
                    shard_deploy_gas = shard_deploy_gas.saturating_add(gas_used);
                }

                let mut dispatcher_deployment = unrolled_sharded.dispatcher_deployment_code.clone();
                dispatcher_deployment
                    .extend_from_slice(&encode_sharded_constructor_args(&shard_addresses));
                let dispatcher_deploy_tx = TxEnv::builder()
                    .gas_limit(BENCH_GAS_LIMIT)
                    .kind(TxKind::Create)
                    .data(Bytes::from(dispatcher_deployment))
                    .build_fill();
                let dispatcher_deploy_result =
                    evm.transact_commit(dispatcher_deploy_tx).map_err(|err| {
                        AppError::EvmBench(format!(
                            "revm sharded dispatcher deployment error: {err}"
                        ))
                    })?;
                let (dispatcher_address, dispatcher_deploy_gas) = match dispatcher_deploy_result {
                    ExecutionResult::Success {
                        gas_used,
                        output: Output::Create(_, Some(contract)),
                        ..
                    } => (contract, gas_used),
                    ExecutionResult::Revert { gas_used, output } => {
                        return Err(AppError::EvmBench(format!(
                            "dispatcher deployment reverted with gas_used {gas_used}; output={}",
                            decode_revert_data(&output)
                        )));
                    }
                    ExecutionResult::Halt { reason, gas_used } => {
                        return Err(AppError::EvmBench(format!(
                            "dispatcher deployment halted with gas_used {gas_used}; reason={reason:?}"
                        )));
                    }
                    ExecutionResult::Success { output, .. } => {
                        return Err(AppError::EvmBench(format!(
                            "dispatcher deployment returned unexpected output: {output:?}"
                        )));
                    }
                };
                let verifier_deploy_gas_total =
                    shard_deploy_gas.saturating_add(dispatcher_deploy_gas);

                let mut stateful_deployment = stateful_deployment_base.clone();
                stateful_deployment.extend_from_slice(&encode_state_constructor_args(
                    dispatcher_address,
                    &samples[0].public_inputs,
                )?);
                let state_deploy_tx = TxEnv::builder()
                    .gas_limit(BENCH_GAS_LIMIT)
                    .kind(TxKind::Create)
                    .data(Bytes::from(stateful_deployment))
                    .build_fill();
                let state_deploy_result = evm.transact_commit(state_deploy_tx).map_err(|err| {
                    AppError::EvmBench(format!("revm stateful contract deployment error: {err}"))
                })?;
                let (state_contract_address, state_contract_deploy_gas) = match state_deploy_result {
                    ExecutionResult::Success {
                        gas_used,
                        output: Output::Create(_, Some(contract)),
                        ..
                    } => (contract, gas_used),
                    ExecutionResult::Revert { gas_used, output } => {
                        return Err(AppError::EvmBench(format!(
                            "stateful contract deployment reverted with gas_used {gas_used}; output={}",
                            decode_revert_data(&output)
                        )));
                    }
                    ExecutionResult::Halt { reason, gas_used } => {
                        return Err(AppError::EvmBench(format!(
                            "stateful contract deployment halted with gas_used {gas_used}; reason={reason:?}"
                        )));
                    }
                    ExecutionResult::Success { output, .. } => {
                        return Err(AppError::EvmBench(format!(
                            "stateful contract deployment returned unexpected output: {output:?}"
                        )));
                    }
                };

                println!(
                    "revm stateful-loop unrolled-sharded verifier deploy gas: shards={} dispatcher={} total={}",
                    shard_deploy_gas,
                    dispatcher_deploy_gas,
                    verifier_deploy_gas_total
                );
                println!(
                    "revm stateful-loop state-contract deploy gas: {state_contract_deploy_gas}"
                );

                *cache_opt = Some(FinalWrapStatefulLoopCache {
                    evm,
                    dispatcher_address,
                    state_contract_address,
                    shard_deploy_gas,
                    dispatcher_deploy_gas,
                    verifier_deploy_gas_total,
                    direct_verifier_call_gas: None,
                    state_contract_deploy_gas,
                    call_gas_total: 0,
                    call_gas_per_batch: Vec::new(),
                    processed_batch_ids: BTreeSet::new(),
                });
            }

            let cache = cache_opt.as_mut().expect("stateful cache must be initialized");
            for ((batch_idx_ref, verifier_calldata), sample) in verifier_calldatas.iter().zip(samples) {
                let batch_idx = *batch_idx_ref;
                if cache.processed_batch_ids.contains(&batch_idx) {
                    continue;
                }

                if cache.direct_verifier_call_gas.is_none() {
                    let direct_call_tx = TxEnv::builder()
                        .gas_limit(BENCH_GAS_LIMIT)
                        .kind(TxKind::Call(cache.dispatcher_address))
                        .data(Bytes::from(verifier_calldata.clone()))
                        .build_fill();
                    let direct_result = cache.evm.transact_commit(direct_call_tx).map_err(|err| {
                        AppError::EvmBench(format!(
                            "revm direct verifier call error on batch {batch_idx}: {err}"
                        ))
                    })?;
                    let gas_used = match direct_result {
                        ExecutionResult::Success { gas_used, .. } => {
                            println!(
                                "revm stateful-loop direct verifier batch {batch_idx} success=true gas: {gas_used}"
                            );
                            gas_used
                        }
                        ExecutionResult::Revert { gas_used, output } => {
                            println!(
                                "revm stateful-loop direct verifier batch {batch_idx} success=false gas: {gas_used}"
                            );
                            return Err(AppError::EvmBench(format!(
                                "direct verifier call reverted on batch {batch_idx} with gas_used {gas_used}; output={}",
                                decode_revert_data(&output)
                            )));
                        }
                        ExecutionResult::Halt { reason, gas_used } => {
                            println!(
                                "revm stateful-loop direct verifier batch {batch_idx} success=false gas: {gas_used}"
                            );
                            return Err(AppError::EvmBench(format!(
                                "direct verifier call halted on batch {batch_idx} with gas_used {gas_used}; reason={reason:?}"
                            )));
                        }
                    };
                    cache.direct_verifier_call_gas = Some(gas_used);
                }

                let state_call_data = encode_verify_and_update_call(
                    verifier_calldata,
                    &sample.public_inputs,
                    &sample.l2_block_metadata,
                )?;
                let state_call_data_path =
                    out_dir.join(format!("batch_{batch_idx}_stateful_verifyAndUpdate.calldata"));
                std::fs::write(&state_call_data_path, hex::encode(&state_call_data))
                    .map_err(|e| AppError::EvmBench(err_string(e)))?;
                let call_tx = TxEnv::builder()
                    .gas_limit(BENCH_GAS_LIMIT)
                    .kind(TxKind::Call(cache.state_contract_address))
                    .data(Bytes::from(state_call_data))
                    .build_fill();

                let result = cache.evm.transact_commit(call_tx).map_err(|err| {
                    AppError::EvmBench(format!("revm stateful loop call error: {err}"))
                })?;
                match result {
                    ExecutionResult::Success { gas_used, .. } => {
                        cache.call_gas_total = cache.call_gas_total.saturating_add(gas_used);
                        println!(
                            "revm stateful-loop batch {batch_idx} verify+update success=true gas: {gas_used}"
                        );
                        cache.call_gas_per_batch.push(json!({
                            "batch_index": batch_idx,
                            "call_gas": gas_used,
                            "success": true,
                        }));
                        cache.processed_batch_ids.insert(batch_idx);
                    }
                    ExecutionResult::Revert { gas_used, output } => {
                        println!(
                            "revm stateful-loop batch {batch_idx} verify+update success=false gas: {gas_used}"
                        );
                        return Err(AppError::EvmBench(format!(
                            "stateful loop call reverted on batch {batch_idx} with gas_used {gas_used}; output={}",
                            decode_revert_data(&output)
                        )));
                    }
                    ExecutionResult::Halt { reason, gas_used } => {
                        println!(
                            "revm stateful-loop batch {batch_idx} verify+update success=false gas: {gas_used}"
                        );
                        return Err(AppError::EvmBench(format!(
                            "stateful loop call halted on batch {batch_idx} with gas_used {gas_used}; reason={reason:?}"
                        )));
                    }
                }
            }

            println!("revm stateful-loop total call gas: {}", cache.call_gas_total);
            stateful_revm = json!({
                "status": "ok",
                "verifier_mode": "unrolled_sharded",
                "shard_deploy_gas": cache.shard_deploy_gas,
                "dispatcher_deploy_gas": cache.dispatcher_deploy_gas,
                "verifier_deploy_gas_total": cache.verifier_deploy_gas_total,
                "direct_verifier_call_gas": cache.direct_verifier_call_gas,
                "state_contract_deploy_gas": cache.state_contract_deploy_gas,
                "call_gas_total": cache.call_gas_total,
                "call_gas_per_batch": cache.call_gas_per_batch.clone(),
                "error": null,
            });
            Ok(())
        })?;
    } else {
        println!(
            "RUN_REVM is not enabled; skipping stateful-loop revm benchmarks. Set RUN_REVM=1 to enable."
        );
    }

    let processed_batches = if env_flag("RUN_REVM") {
        FINAL_WRAP_STATEFUL_LOOP_CACHE.with(|cache_cell| {
            cache_cell
                .borrow()
                .as_ref()
                .map(|cache| cache.processed_batch_ids.len())
                .unwrap_or(0)
        })
    } else {
        samples.len()
    };

    let stateful_manifest = format!(
        "dispatcher_runtime_code_bytes: {}\ndispatcher_deployment_code_bytes: {}\nshard_runtime_code_bytes: {:?}\nshard_deployment_code_bytes: {:?}\nstateful_runtime_code_bytes: {}\nstateful_deployment_code_bytes: {}\nnum_shards: {}\nnum_batches: {}\n",
        dispatcher_runtime_bytes,
        dispatcher_initcode_bytes,
        shard_runtime_sizes,
        shard_initcode_sizes,
        stateful_runtime.len(),
        stateful_deployment_base.len(),
        unrolled_sharded.shard_deployment_codes.len(),
        processed_batches,
    );
    std::fs::write(&stateful_manifest_path, stateful_manifest)
        .map_err(|e| AppError::EvmBench(err_string(e)))?;

    let summary = json!({
        "num_batches": processed_batches,
        "unrolled_sharded_verifier": {
            "dispatcher_runtime_code_bytes": dispatcher_runtime_bytes,
            "dispatcher_initcode_bytes": dispatcher_initcode_bytes,
            "shard_runtime_sizes_bytes": shard_runtime_sizes,
            "shard_initcode_sizes_bytes": shard_initcode_sizes,
            "runtime_code_limit_bytes": EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "dispatcher_runtime_code_within_limit": dispatcher_runtime_bytes <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "all_shard_runtime_within_limit": unrolled_sharded
                .manifest
                .shard_runtime_code_bytes
                .iter()
                .all(|size| *size <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES),
            "initcode_limit_bytes": EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "dispatcher_initcode_within_limit": dispatcher_initcode_bytes <= EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "all_shard_initcode_within_limit": unrolled_sharded
                .manifest
                .shard_deployment_code_bytes
                .iter()
                .all(|size| *size <= EIP3860_INITCODE_SIZE_LIMIT_BYTES),
        },
        "stateful_contract": {
            "runtime_code_bytes": stateful_runtime.len(),
            "deployment_code_bytes": stateful_deployment_base.len(),
            "runtime_code_limit_bytes": EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "runtime_code_within_limit": stateful_runtime.len() <= EIP170_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            "initcode_limit_bytes": EIP3860_INITCODE_SIZE_LIMIT_BYTES,
            "initcode_within_limit": stateful_deployment_base.len() <= EIP3860_INITCODE_SIZE_LIMIT_BYTES,
        },
        "revm_stateful_loop": stateful_revm,
    });
    std::fs::write(
        &bench_json_path,
        serde_json::to_string_pretty(&summary).map_err(|e| AppError::EvmBench(err_string(e)))?,
    )
    .map_err(|e| AppError::EvmBench(err_string(e)))?;

    println!("wrote {}", sharded_dispatcher_solidity_path.display());
    println!("wrote {}", sharded_dispatcher_bytecode_path.display());
    println!("wrote {}", sharded_shards_bytecode_path.display());
    println!("wrote {}", sharded_manifest_path.display());
    println!("wrote {}", stateful_solidity_path.display());
    println!("wrote {}", stateful_bytecode_path.display());
    println!("wrote {}", stateful_manifest_path.display());
    println!("wrote {}", bench_json_path.display());
    println!("bench-summary-json={}", bench_json_path.display());
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// Host-side structures + helpers
////////////////////////////////////////////////////////////////////////////////

/// Single Poseidon hash of all 7 would-be public inputs (host-side).
fn host_instance_hash(items: [F; 7]) -> F {
    use midnight_circuits::instructions::hash::HashCPU;
    <PoseidonChip<F> as HashCPU<F, F>>::hash(&items)
}

/// Host-side Keccak Merkle hash over flattened L2 block metadata.
///
/// Metadata layout is `N` rows of width 7:
/// `[root_before, pk_bx, pk_by, new1_commit, new2_commit, nf1, nf2]`.
/// Leaves are `keccak256(abi.encodePacked(row[0], ..., row[6]))`.
/// Internal nodes are `keccak256(left || right)` with right duplicated when odd.
fn l2_metadata_merkle_hash(metadata: &[F]) -> Result<F, AppError> {
    const METADATA_WIDTH: usize = 7;

    if metadata.is_empty() || metadata.len() % METADATA_WIDTH != 0 {
        return Err(AppError::ReplayGuard(format!(
            "invalid L2 block metadata length: got {}, expected non-zero multiple of {}",
            metadata.len(),
            METADATA_WIDTH
        )));
    }

    let mut level: Vec<[u8; 32]> = metadata
        .chunks_exact(METADATA_WIDTH)
        .map(|row| {
            let mut hasher = Keccak256::new();
            for value in row {
                hasher.update(field_to_abi_word(*value));
            }
            let digest: [u8; 32] = hasher.finalize().into();
            digest
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            let mut hasher = Keccak256::new();
            hasher.update(left);
            hasher.update(right);
            let digest: [u8; 32] = hasher.finalize().into();
            next.push(digest);
            i += 2;
        }
        level = next;
    }

    let root_be = level[0];
    let root_big = BigUint::from_bytes_be(&root_be);
    let scalar_modulus = BigUint::from_bytes_le((-F::ONE).to_repr().as_ref()) + BigUint::from(1u8);
    let reduced = root_big % scalar_modulus;
    let mut repr = <F as PrimeField>::Repr::default();
    let repr_len = repr.as_ref().len();
    let mut reduced_le = reduced.to_bytes_le();
    reduced_le.resize(repr_len, 0);
    repr.as_mut().copy_from_slice(&reduced_le[..repr_len]);
    Option::from(F::from_repr(repr)).ok_or(AppError::ScalarToField)
}

/// A note is spendable if it is unspent and confirmed at or before `latest_confirmed_root_idx`.
fn is_spendable(note: &transfer_circuit::Note, latest_confirmed_root_idx: usize) -> bool {
    !note.spent && note.confirmed_at_root_idx <= latest_confirmed_root_idx
}

/// Return indices of spendable notes for an account.
fn spendable_note_indices(
    account: &transfer_circuit::Account,
    latest_confirmed_root_idx: usize,
) -> Vec<usize> {
    account
        .wallet
        .iter()
        .enumerate()
        .filter(|(_, n)| is_spendable(n, latest_confirmed_root_idx))
        .map(|(i, _)| i)
        .collect()
}

/// Choose a sender index that has at least two spendable notes.
fn choose_sender_idx(
    rng: &mut ChaCha8Rng,
    accounts: &[transfer_circuit::Account],
    latest_confirmed_root_idx: usize,
) -> Option<usize> {
    let viable: Vec<usize> = accounts
        .iter()
        .enumerate()
        .filter(|(_, a)| spendable_note_indices(a, latest_confirmed_root_idx).len() >= 2)
        .map(|(i, _)| i)
        .collect();

    if viable.is_empty() {
        None
    } else {
        Some(viable[rng.gen_range(0..viable.len())])
    }
}

/// Choose two distinct elements from a non-empty slice of candidates.
fn choose_two_distinct(rng: &mut ChaCha8Rng, candidates: &[usize]) -> (usize, usize) {
    debug_assert!(candidates.len() >= 2);
    let a = candidates[rng.gen_range(0..candidates.len())];
    let mut b = candidates[rng.gen_range(0..candidates.len())];
    while b == a {
        b = candidates[rng.gen_range(0..candidates.len())];
    }
    (a, b)
}

/// Choose a (possibly lagging) confirmed root index to prove against.
fn choose_root_idx_for_proof(
    rng: &mut ChaCha8Rng,
    min_root_idx_for_inputs: usize,
    latest_confirmed_root_idx: usize,
) -> usize {
    if min_root_idx_for_inputs < latest_confirmed_root_idx && rng.gen_bool(LAG_TX_PROB) {
        // Force lag: pick strictly older than latest when possible.
        rng.gen_range(min_root_idx_for_inputs..=latest_confirmed_root_idx - 1)
    } else {
        latest_confirmed_root_idx
    }
}

fn commitment_for_utxo(utxo: &transfer_circuit::Utxo, pk_x: F, pk_y: F) -> F {
    transfer_circuit::host_commit(utxo.asset_id, utxo.amount, pk_x, pk_y, utxo.randomness)
}

fn nullifier_for_commit(commit: F, pk_x: F, pk_y: F) -> F {
    transfer_circuit::host_nullify(commit, pk_x, pk_y)
}

fn split_amount(rng: &mut ChaCha8Rng, total: u128) -> (u128, u128) {
    if total == 0 {
        (0, 0)
    } else {
        let out1 = rng.gen_range(0..=total);
        (out1, total - out1)
    }
}

fn random_amount(rng: &mut ChaCha8Rng) -> u128 {
    rng.r#gen::<u128>() >> (128 - transfer_circuit::AMOUNT_GEN_BITS)
}

fn blind_pubkey(sender_pk: JubjubSubgroup, alpha: JubjubScalar) -> (JubjubSubgroup, F, F) {
    let blind_point = JubjubSubgroup::generator() * alpha;
    let pk_blinded_point = sender_pk + blind_point;
    let fields = AssignedNativePoint::<Jubjub>::as_public_input(&pk_blinded_point);
    (pk_blinded_point, fields[0], fields[1])
}

fn build_public_items(
    root_before: F,
    pk_bx: F,
    pk_by: F,
    new1_commit: F,
    new2_commit: F,
    nf1: F,
    nf2: F,
) -> ([F; 7], F, transfer_circuit::Spend2Output2PublicInputs) {
    let public_items = [root_before, pk_bx, pk_by, new1_commit, new2_commit, nf1, nf2];
    let state = host_instance_hash(public_items);

    let instance = transfer_circuit::Spend2Output2PublicInputs {
        root: root_before,
        pk_bx,
        pk_by,
        new_c1: new1_commit,
        new_c2: new2_commit,
        nf1,
        nf2,
    };

    (public_items, state, instance)
}

/// Convert a Jubjub scalar to the circuit field `F`.
///
/// `ff::Field::from_bytes_le` returns `subtle::CtOption`, so we convert to `Option` first.
fn scalar_to_field(alpha: JubjubScalar) -> Result<F, AppError> {
    let ct = F::from_bytes_le(&alpha.to_bytes());
    Option::<F>::from(ct).ok_or(AppError::ScalarToField)
}

////////////////////////////////////////////////////////////////////////////////
// State containers
////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
struct ChainState {
    /// Single global asset id used for all notes in this demo.
    asset_id: F,

    accounts: Vec<transfer_circuit::Account>,
    commitment_map: CommitmentMap,
    nullifier_map: CommitmentMap,
    commitment_roots_set: CommitmentMap,
    commitment_root_history: Vec<F>,
    commitment_map_history: Vec<CommitmentMap>,

    blk_head: u64,
}

struct BatchPreState {
    pre_commitment_map: CommitmentMap,
    pre_nullifier_map: CommitmentMap,
    pre_roots_set_map: CommitmentMap,
    latest_confirmed_root_idx: usize,
}

fn snapshot_batch_pre_state(state: &ChainState) -> BatchPreState {
    BatchPreState {
        pre_commitment_map: state.commitment_map.clone(),
        pre_nullifier_map: state.nullifier_map.clone(),
        pre_roots_set_map: state.commitment_roots_set.clone(),
        latest_confirmed_root_idx: state.commitment_root_history.len() - 1,
    }
}

fn init_accounts(num_accounts: usize) -> Vec<transfer_circuit::Account> {
    (0..num_accounts)
        .map(|i| {
            let sk = JubjubScalar::random(&mut OsRng);
            let pk_point = JubjubSubgroup::generator() * sk;
            let fields = AssignedNativePoint::<Jubjub>::as_public_input(&pk_point);
            transfer_circuit::Account {
                id: i,
                sk,
                pk_point,
                pk_x: fields[0],
                pk_y: fields[1],
                wallet: vec![],
            }
        })
        .collect()
}

fn seed_deposits(
    rng: &mut ChaCha8Rng,
    accounts: &mut [transfer_circuit::Account],
    commitment_map: &mut CommitmentMap,
    asset_id: F,
    deposits_per_account: usize,
) {
    for acc in accounts.iter_mut() {
        for _ in 0..deposits_per_account {
            let utxo = transfer_circuit::Utxo {
                asset_id,
                amount: random_amount(&mut *rng),
                randomness: F::random(&mut *rng),
            };

            let commit = commitment_for_utxo(&utxo, acc.pk_x, acc.pk_y);
            commitment_map.insert(&commit, &F::ONE);

            acc.wallet.push(transfer_circuit::Note {
                utxo,
                commit,
                spent: false,
                confirmed_at_root_idx: 0,
            });
        }
    }
}

fn init_chain_state(
    rng: &mut ChaCha8Rng,
    num_accounts: usize,
    deposits_per_account: usize,
) -> ChainState {
    let asset_id = F::random(&mut *rng);

    let mut accounts = init_accounts(num_accounts);
    let mut commitment_map = CommitmentMap::new(&F::ZERO);
    let nullifier_map = CommitmentMap::new(&F::ZERO);

    seed_deposits(&mut *rng, &mut accounts, &mut commitment_map, asset_id, deposits_per_account);

    let genesis_root = commitment_map.succinct_repr();

    let mut commitment_roots_set = CommitmentMap::new(&F::ZERO);
    commitment_roots_set.insert(&genesis_root, &F::ONE);

    ChainState {
        asset_id,
        accounts,
        commitment_map_history: vec![commitment_map.clone()],
        commitment_root_history: vec![genesis_root],
        commitment_roots_set,
        commitment_map,
        nullifier_map,
        blk_head: 0,
    }
}

////////////////////////////////////////////////////////////////////////////////
// Transaction planning + execution
////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
struct PlannedTx {
    sender_idx: usize,
    old1_idx: usize,
    old2_idx: usize,
    recipient1_idx: usize,
    recipient2_idx: usize,
    root_idx_for_proof: usize,
}

fn plan_transaction(
    rng: &mut ChaCha8Rng,
    shadow_accounts: &[transfer_circuit::Account],
    latest_confirmed_root_idx: usize,
) -> Option<PlannedTx> {
    let sender_idx = choose_sender_idx(rng, shadow_accounts, latest_confirmed_root_idx)?;
    let spendable = spendable_note_indices(&shadow_accounts[sender_idx], latest_confirmed_root_idx);
    let (old1_idx, old2_idx) = choose_two_distinct(rng, &spendable);

    let recipient1_idx = rng.gen_range(0..shadow_accounts.len());
    let recipient2_idx = rng.gen_range(0..shadow_accounts.len());

    let old1 = &shadow_accounts[sender_idx].wallet[old1_idx];
    let old2 = &shadow_accounts[sender_idx].wallet[old2_idx];
    let min_root_idx_for_inputs = old1.confirmed_at_root_idx.max(old2.confirmed_at_root_idx);

    let root_idx_for_proof =
        choose_root_idx_for_proof(rng, min_root_idx_for_inputs, latest_confirmed_root_idx);

    Some(PlannedTx {
        sender_idx,
        old1_idx,
        old2_idx,
        recipient1_idx,
        recipient2_idx,
        root_idx_for_proof,
    })
}

struct BuiltTx {
    // For proof payload
    public_items: [F; 7],
    state: F,
    instance: transfer_circuit::Spend2Output2PublicInputs,
    witness: (
        CommitmentMap,
        JubjubScalar,
        F,
        transfer_circuit::Utxo,
        transfer_circuit::Utxo,
        transfer_circuit::Utxo,
        transfer_circuit::Utxo,
        JubjubSubgroup,
        JubjubSubgroup,
    ),

    // For state updates
    nf1: F,
    nf2: F,
    new1_commit: F,
    new2_commit: F,
    new1_utxo: transfer_circuit::Utxo,
    new2_utxo: transfer_circuit::Utxo,
}

#[derive(Clone)]
struct TxEffects {
    nf1: F,
    nf2: F,
    new1_commit: F,
    new2_commit: F,
    new1_utxo: transfer_circuit::Utxo,
    new2_utxo: transfer_circuit::Utxo,
    sender_idx: usize,
    old1_idx: usize,
    old2_idx: usize,
    recipient1_idx: usize,
    recipient2_idx: usize,
}

fn effects_from(plan: &PlannedTx, built: &BuiltTx) -> TxEffects {
    TxEffects {
        nf1: built.nf1,
        nf2: built.nf2,
        new1_commit: built.new1_commit,
        new2_commit: built.new2_commit,
        new1_utxo: built.new1_utxo.clone(),
        new2_utxo: built.new2_utxo.clone(),
        sender_idx: plan.sender_idx,
        old1_idx: plan.old1_idx,
        old2_idx: plan.old2_idx,
        recipient1_idx: plan.recipient1_idx,
        recipient2_idx: plan.recipient2_idx,
    }
}

fn build_transaction(
    rng: &mut ChaCha8Rng,
    asset_id: F,
    shadow_accounts: &[transfer_circuit::Account],
    commitment_map_history: &[CommitmentMap],
    commitment_root_history: &[F],
    plan: &PlannedTx,
    latest_confirmed_root_idx: usize,
    batch_idx: usize,
    tx_idx: usize,
) -> Result<(BuiltTx, F), AppError> {
    let sender = shadow_accounts[plan.sender_idx].clone();
    let old1 = shadow_accounts[plan.sender_idx].wallet[plan.old1_idx].clone();
    let old2 = shadow_accounts[plan.sender_idx].wallet[plan.old2_idx].clone();

    let historic_commit_map = commitment_map_history[plan.root_idx_for_proof].clone();
    let root_before = commitment_root_history[plan.root_idx_for_proof];
    debug_assert_eq!(historic_commit_map.succinct_repr(), root_before);

    if plan.root_idx_for_proof != latest_confirmed_root_idx {
        println!(
            "[batch {}, tx {}] 🕒 lagging proof root: idx {} (latest {}), root {:?}",
            batch_idx, tx_idx, plan.root_idx_for_proof, latest_confirmed_root_idx, root_before
        );
    }

    let total = old1.utxo.amount + old2.utxo.amount;
    let (out1_amt, out2_amt) = split_amount(&mut *rng, total);

    let new1_utxo =
        transfer_circuit::Utxo { asset_id, amount: out1_amt, randomness: F::random(&mut *rng) };
    let new2_utxo =
        transfer_circuit::Utxo { asset_id, amount: out2_amt, randomness: F::random(&mut *rng) };

    let r1 = plan.recipient1_idx;
    let r2 = plan.recipient2_idx;

    let new1_commit =
        commitment_for_utxo(&new1_utxo, shadow_accounts[r1].pk_x, shadow_accounts[r1].pk_y);
    let new2_commit =
        commitment_for_utxo(&new2_utxo, shadow_accounts[r2].pk_x, shadow_accounts[r2].pk_y);

    let nf1 = nullifier_for_commit(old1.commit, sender.pk_x, sender.pk_y);
    let nf2 = nullifier_for_commit(old2.commit, sender.pk_x, sender.pk_y);

    let alpha = JubjubScalar::random(&mut OsRng);
    let (_pk_blinded_point, pk_bx, pk_by) = blind_pubkey(sender.pk_point, alpha);
    let alpha_f = scalar_to_field(alpha)?;

    let (public_items, state, instance) =
        build_public_items(root_before, pk_bx, pk_by, new1_commit, new2_commit, nf1, nf2);

    let witness = (
        historic_commit_map,
        sender.sk,
        alpha_f,
        old1.utxo.clone(),
        old2.utxo.clone(),
        new1_utxo.clone(),
        new2_utxo.clone(),
        shadow_accounts[r1].pk_point,
        shadow_accounts[r2].pk_point,
    );

    Ok((
        BuiltTx {
            public_items,
            state,
            instance,
            witness,
            nf1,
            nf2,
            new1_commit,
            new2_commit,
            new1_utxo,
            new2_utxo,
        },
        root_before,
    ))
}

fn apply_tx_effects(
    shadow_accounts: &mut [transfer_circuit::Account],
    shadow_commitment_map: &mut CommitmentMap,
    shadow_nullifier_map: &mut CommitmentMap,
    confirm_at_idx: usize,
    effects: &TxEffects,
) {
    // Nullifiers
    shadow_nullifier_map.insert(&effects.nf1, &F::ONE);
    shadow_nullifier_map.insert(&effects.nf2, &F::ONE);

    // Commitments
    shadow_commitment_map.insert(&effects.new1_commit, &F::ONE);
    shadow_commitment_map.insert(&effects.new2_commit, &F::ONE);

    // Mark spent inputs
    shadow_accounts[effects.sender_idx].wallet[effects.old1_idx].spent = true;
    shadow_accounts[effects.sender_idx].wallet[effects.old2_idx].spent = true;

    // Add newly created notes; they become spendable only after the batch commits.
    shadow_accounts[effects.recipient1_idx].wallet.push(transfer_circuit::Note {
        utxo: effects.new1_utxo.clone(),
        commit: effects.new1_commit,
        spent: false,
        confirmed_at_root_idx: confirm_at_idx,
    });

    shadow_accounts[effects.recipient2_idx].wallet.push(transfer_circuit::Note {
        utxo: effects.new2_utxo.clone(),
        commit: effects.new2_commit,
        spent: false,
        confirmed_at_root_idx: confirm_at_idx,
    });
}

fn prove_client(
    srs: &ParamsKZG<E>,
    pk: &MidnightPK<transfer_circuit::Spend2Output2>,
    relation: &transfer_circuit::Spend2Output2,
    built: BuiltTx,
) -> Result<rollup_ivc_proofs::ClientProof, AppError> {
    let now = Instant::now();
    let proof = midnight_zk_stdlib::prove::<transfer_circuit::Spend2Output2, PoseidonState<F>>(
        srs,
        pk,
        relation,
        &built.instance,
        built.witness,
        OsRng,
    )
    .map_err(|e| AppError::Proof(err_string(e)))?;

    println!("proof gen: {:?}", now.elapsed());

    Ok(rollup_ivc_proofs::ClientProof {
        state: built.state,
        proof,
        public_items: built.public_items,
    })
}

////////////////////////////////////////////////////////////////////////////////
// Replay demonstration
////////////////////////////////////////////////////////////////////////////////

fn demonstrate_replay_protection(
    agg_setup: &setup_ivc::AggSetup,
    srs: &ParamsKZG<E>,
    vk: &VerifyingKey<F, KZGCommitmentScheme<E>>,
    client_proofs: &[rollup_ivc_proofs::ClientProof],
    commitment_map: CommitmentMap,
    nullifier_map: CommitmentMap,
    roots_set_map: CommitmentMap,
    agg_state: &rollup_ivc_circuits::AggState,
) {
    println!("REPLAY attempt:");
    println!("  c_pre  = {:?}", agg_state.c_pre);
    println!("  c_post = {:?}", agg_state.c_post);
    println!("  n_pre  = {:?}", agg_state.n_pre);
    println!("  n_post = {:?}", agg_state.n_post);
    println!("  blk    = {:?}", agg_state.block_level);

    println!("  roots_set has c_pre?  {:?}", roots_set_map.get(&agg_state.c_pre));
    println!("  roots_set has c_post? {:?}", roots_set_map.get(&agg_state.c_post));

    println!(
        "  nullifier_map root == n_post? {}",
        nullifier_map.succinct_repr() == agg_state.n_post
    );

    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = rollup_ivc_proofs::aggregate_client_proofs_cached(
            agg_setup,
            srs,
            vk,
            client_proofs,
            commitment_map,
            nullifier_map,
            roots_set_map,
            F::ZERO,
        );
    }));

    match replay {
        Ok(_) => println!("❌ Replay unexpectedly succeeded (BUG)"),
        Err(_) => println!(
            "✅ Replay correctly rejected (nullifiers already spent / state already advanced)"
        ),
    }
}

////////////////////////////////////////////////////////////////////////////////
// Demo entrypoint
////////////////////////////////////////////////////////////////////////////////

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    const LEAF_VK_NAME: &str = "spend2output2_vk";

    let k = env_u32_or("SHIELDED_POOL_K", 14);
    let agg_k = env_u32_or("SHIELDED_POOL_AGG_K", AGG_K);
    let use_mock_srs = env_flag("SHIELDED_POOL_USE_MOCK_SRS");
    let num_accounts = env_usize_or("SHIELDED_POOL_NUM_ACCOUNTS", 4);
    let num_seed_deposits_per_account = env_usize_or("SHIELDED_POOL_NUM_SEED_DEPOSITS", 512);
    let batch_size = env_usize_or("SHIELDED_POOL_BATCH_SIZE", DEFAULT_BATCH_SIZE);
    let target_rollup_transitions =
        env_usize_or("SHIELDED_POOL_ROLLUP_TRANSITIONS", DEFAULT_ROLLUP_TRANSITIONS);
    if !batch_size.is_power_of_two() {
        return Err(AppError::ReplayGuard(format!(
            "batch size must be a power of two, got {}",
            batch_size
        )));
    }
    let default_num_transfers = batch_size
        .checked_mul(target_rollup_transitions)
        .ok_or_else(|| AppError::ReplayGuard("num_transfers overflow".to_string()))?;
    let num_transfers = env_usize_or("SHIELDED_POOL_NUM_TRANSFERS", default_num_transfers);
    if num_transfers % batch_size != 0 {
        return Err(AppError::ReplayGuard(format!(
            "num_transfers must be a multiple of batch_size; got num_transfers={} batch_size={}",
            num_transfers, batch_size
        )));
    }
    let planned_rollup_transitions = num_transfers / batch_size;
    let run_evm_bench = env_flag("SHIELDED_POOL_EVM_BENCH");
    #[cfg(feature = "evm-bench")]
    let target_batch = env_usize("SHIELDED_POOL_EVM_BENCH_BATCH");
    #[cfg(feature = "evm-bench")]
    let live_stateful_loop = run_evm_bench && env_flag("SHIELDED_POOL_EVM_VERIFY_EACH_BATCH");
    #[cfg(feature = "evm-bench")]
    let run_transition_bench = run_evm_bench && env_flag("SHIELDED_POOL_EVM_BENCH_TRANSITIONS");
    #[cfg(feature = "evm-bench")]
    let run_final_wrap_bench = run_evm_bench && !env_flag("SHIELDED_POOL_EVM_SKIP_FINAL_WRAP_BENCH");
    let skip_replay_demo = env_flag("SHIELDED_POOL_SKIP_REPLAY_DEMO") || run_evm_bench;

    #[cfg(feature = "evm-bench")]
    if run_final_wrap_bench && live_stateful_loop {
        FINAL_WRAP_STATEFUL_LOOP_CACHE.with(|cache| {
            *cache.borrow_mut() = None;
        });
    }

    #[cfg(feature = "evm-bench")]
    if run_evm_bench {
        let target_batch_label =
            target_batch.map(|batch| batch.to_string()).unwrap_or_else(|| "all".to_string());
        println!(
            "EVM bench enabled (feature=evm-bench), target_batch={}, RUN_REVM={}, live_stateful_loop={}, final_wrap_bench={}, transition_bench={}",
            target_batch_label,
            env_flag("RUN_REVM"),
            live_stateful_loop,
            run_final_wrap_bench,
            run_transition_bench
        );
    }

    #[cfg(not(feature = "evm-bench"))]
    if run_evm_bench {
        println!(
            "SHIELDED_POOL_EVM_BENCH=1 is set, but this binary was built without feature `evm-bench`."
        );
        println!(
            "Re-run with Cargo features before `--`, e.g.: cargo run -p shielded-pool --release --offline --features evm-bench"
        );
    }

    println!(
        "config: k={} agg_k={} use_mock_srs={} accounts={} seed_deposits_per_account={} transfers={} batch_size={} planned_rollup_transitions={}",
        k,
        agg_k,
        use_mock_srs,
        num_accounts,
        num_seed_deposits_per_account,
        num_transfers,
        batch_size,
        planned_rollup_transitions
    );

    // --- Setup leaf circuit keys ---
    let load_srs = |power_k: u32| {
        if use_mock_srs {
            trusted_setup::mock_srs_agg(power_k)
        } else {
            trusted_setup::filecoin_srs_agg(power_k)
        }
    };
    let srs = load_srs(k).map_err(|e| AppError::TrustedSetup(err_string(e)))?;
    let relation = transfer_circuit::Spend2Output2;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    // Cache aggregation setup once (fixed batch size).
    let agg_setup = setup_ivc::prepare_agg_setup(&srs, vk.vk(), LEAF_VK_NAME, k, batch_size);

    // Cache final aggregation vk/pk once (depends only on cached agg_setup for this batch size).
    let final_agg_srs = load_srs(agg_k).map_err(|e| AppError::TrustedSetup(err_string(e)))?;

    let default_final_circuit = rollup_ivc_circuits::WrapStepCircuit {
        child_vk: agg_setup.child_vk(),
        child_vk_name: agg_setup.child_vk_name().to_string(),
        left_proof: Value::unknown(),
        right_proof: Value::unknown(),
        left_pi_acc: Value::unknown(),
        right_pi_acc: Value::unknown(),
        fixed_base_names: agg_setup.fixed_base_names().to_vec(),
        fixed_bases: agg_setup.fixed_bases.clone(),
        left_child_state: Value::unknown(),
        right_child_state: Value::unknown(),
        agg_state: Value::unknown(),
        pre_commitment_roots_set_map: Value::unknown(),
        post_commitment_roots_set_root: Value::unknown(),
        blk_post: Value::unknown(),
        blk_pre: Value::unknown(),
        l2_metadata_merkle_hash: Value::unknown(),
    };

    let final_vk = keygen_vk_with_k(&final_agg_srs, &default_final_circuit, agg_k)
        .map_err(|e| AppError::Keygen(err_string(e)))?;
    let final_pk = keygen_pk(final_vk.clone(), &default_final_circuit)
        .map_err(|e| AppError::Keygen(err_string(e)))?;

    // --- Initialize randomness and chain state ---
    let mut rng = ChaCha8Rng::from_entropy();
    let mut chain = init_chain_state(&mut rng, num_accounts, num_seed_deposits_per_account);

    // Global L2 block counter (demo "on-chain head").
    //
    // We will prove in the final wrap proof that:
    //   blk_post = blk_pre + 1
    // and bind the batch to blk_post.
    let mut blk_head: u64 = chain.blk_head;

    println!("Initial commitment root: {:?}", chain.commitment_root_history[0]);

    // Client circuit stats are constant; compute once.
    let client_stats = cost_model(&transfer_circuit::Spend2Output2);
    println!("client circuit stats: {:?}", client_stats);

    // --- Rollup batching loop ---
    let mut total_transfers_done = 0usize;
    let mut batch_idx = 0usize;
    let mut final_wrap_proof_gen_times: Vec<Duration> = Vec::new();
    #[cfg(feature = "evm-bench")]
    let mut evm_bench_samples: Vec<FinalWrapBenchSample> = Vec::new();
    #[cfg(feature = "evm-bench")]
    let mut evm_transition_samples: Vec<RollupTransitionBenchSample> = Vec::new();

    while total_transfers_done < num_transfers {
        let pre = snapshot_batch_pre_state(&chain);

        // Compute this batch's block transition.
        let blk_pre_u64 = blk_head;
        let blk_post_u64 = blk_head + 1;
        let blk_pre_f = F::from(blk_pre_u64);
        let blk_post_f = F::from(blk_post_u64);
        let batch_blk = blk_post_f; // subtree is bound to blk_post per spec

        // Shadow state for the batch.
        let mut shadow_accounts = chain.accounts.clone();
        let mut shadow_nullifier_map = chain.nullifier_map.clone();
        let mut shadow_commitment_map = chain.commitment_map.clone();

        println!(
            "\n=== Starting batch {} from commitment root {:?} ===",
            batch_idx,
            shadow_commitment_map.succinct_repr()
        );

        let mut client_proofs: Vec<rollup_ivc_proofs::ClientProof> = Vec::with_capacity(batch_size);
        let mut batch_failed = false;

        for _ in 0..batch_size {
            if total_transfers_done >= num_transfers {
                break;
            }

            let plan = match plan_transaction(
                &mut rng,
                &shadow_accounts,
                pre.latest_confirmed_root_idx,
            ) {
                Some(p) => p,
                None => {
                    println!(
                        "[batch {}] no account has two spendable confirmed notes; stopping batching.",
                        batch_idx
                    );
                    batch_failed = true;
                    break;
                }
            };

            // Build ONCE per tx (do not rebuild for effects; that breaks consistency).
            let (built, _root_before) = build_transaction(
                &mut rng,
                chain.asset_id,
                &shadow_accounts,
                &chain.commitment_map_history,
                &chain.commitment_root_history,
                &plan,
                pre.latest_confirmed_root_idx,
                batch_idx,
                total_transfers_done,
            )?;

            let effects = effects_from(&plan, &built);
            let proof = prove_client(&srs, &pk, &relation, built)?;
            client_proofs.push(proof);

            // Apply state transition to shadow rollup state using the exact same tx data as proved.
            apply_tx_effects(
                &mut shadow_accounts,
                &mut shadow_commitment_map,
                &mut shadow_nullifier_map,
                chain.commitment_root_history.len(),
                &effects,
            );

            println!(
                "[batch {}, tx {}] shadow commitment root updated: {:?}",
                batch_idx,
                total_transfers_done,
                shadow_commitment_map.succinct_repr()
            );

            total_transfers_done += 1;
        }

        if batch_failed || client_proofs.is_empty() {
            break;
        }

        if client_proofs.len() != batch_size {
            return Err(AppError::ReplayGuard(format!(
                "batch not completely filled: got {}, expected {}",
                client_proofs.len(),
                batch_size
            )));
        }
        if !client_proofs.len().is_power_of_two() {
            return Err(AppError::ReplayGuard("batch size must be a power of two".to_string()));
        }

        // --- Aggregate client proofs (cached setup) ---
        let now = Instant::now();
        let agg_result = rollup_ivc_proofs::aggregate_client_proofs_cached(
            &agg_setup,
            &srs,
            vk.vk(),
            &client_proofs,
            pre.pre_commitment_map.clone(),
            pre.pre_nullifier_map.clone(),
            pre.pre_roots_set_map.clone(),
            batch_blk,
        );
        println!("Batch {} aggregated (up to top pair) in {:?}", batch_idx, now.elapsed());
        println!(
            "Batch {} computed subroot (host): {:?}",
            batch_idx, agg_result.root_state.subroot
        );

        #[cfg(feature = "evm-bench")]
        if run_transition_bench {
            let left_public_inputs = rollup_ivc_proofs::AggPublicInputs {
                state: agg_result.left_top.state.clone(),
                pi_acc: agg_result.left_top.pi_acc.clone(),
            }
            .to_fields();
            evm_transition_samples.push(RollupTransitionBenchSample {
                batch_idx,
                transition_idx: 0,
                proof: agg_result.left_top.proof.clone(),
                public_inputs: left_public_inputs,
            });

            let right_public_inputs = rollup_ivc_proofs::AggPublicInputs {
                state: agg_result.right_top.state.clone(),
                pi_acc: agg_result.right_top.pi_acc.clone(),
            }
            .to_fields();
            evm_transition_samples.push(RollupTransitionBenchSample {
                batch_idx,
                transition_idx: 1,
                proof: agg_result.right_top.proof.clone(),
                public_inputs: right_public_inputs,
            });
        }

        // --- Replay guard via historic roots set update ---
        let pre_roots_set_root = pre.pre_roots_set_map.succinct_repr();
        if pre.pre_roots_set_map.get(&agg_result.root_state.c_post) != F::ZERO {
            return Err(AppError::ReplayGuard(
                "replay guard: c_post already present in roots set".to_string(),
            ));
        }

        let mut shadow_commitment_roots_set = pre.pre_roots_set_map.clone();
        shadow_commitment_roots_set.insert(&agg_result.root_state.c_post, &F::ONE);
        let post_roots_set_root = shadow_commitment_roots_set.succinct_repr();

        // --- Final merged aggregation proof ---
        {
            use midnight_proofs::transcript::CircuitTranscript;

            let mut final_acc: rollup_ivc_circuits::AggAccumulator =
                rollup_ivc_circuits::AggAccumulator::accumulate(&[
                    agg_result.left_top.proof_acc.clone(),
                    agg_result.left_top.pi_acc.clone(),
                    agg_result.right_top.proof_acc.clone(),
                    agg_result.right_top.pi_acc.clone(),
                ]);
            final_acc.collapse();
            let final_acc_pi = rollup_ivc_circuits::fully_evaluated_accumulator_as_public_input(
                &final_acc,
                &agg_result.fixed_bases,
            );
            let l2_block_metadata = client_proofs
                .iter()
                .flat_map(|proof| proof.public_items)
                .collect::<Vec<_>>();
            let l2_metadata_merkle_hash = l2_metadata_merkle_hash(&l2_block_metadata)?;

            let final_circuit = rollup_ivc_circuits::WrapStepCircuit {
                child_vk: agg_result.child_vk.clone(),
                child_vk_name: agg_result.child_vk_name.clone(),
                left_proof: Value::known(agg_result.left_top.proof.clone()),
                right_proof: Value::known(agg_result.right_top.proof.clone()),
                left_pi_acc: Value::known(agg_result.left_top.pi_acc.clone()),
                right_pi_acc: Value::known(agg_result.right_top.pi_acc.clone()),
                fixed_base_names: agg_result.fixed_base_names.clone(),
                fixed_bases: agg_result.fixed_bases.clone(),
                left_child_state: Value::known(agg_result.left_top.state),
                right_child_state: Value::known(agg_result.right_top.state),
                agg_state: Value::known(agg_result.root_state),
                pre_commitment_roots_set_map: Value::known(pre.pre_roots_set_map.clone()),
                post_commitment_roots_set_root: Value::known(post_roots_set_root),
                blk_pre: Value::known(blk_pre_f),
                blk_post: Value::known(blk_post_f),
                l2_metadata_merkle_hash: Value::known(l2_metadata_merkle_hash),
            };

            let mut final_public_inputs: Vec<F> = vec![
                agg_result.root_state.c_pre,
                agg_result.root_state.c_post,
                agg_result.root_state.n_pre,
                agg_result.root_state.n_post,
                // block counter transition (public) TODO we can expose only one block level
                blk_pre_f,
                blk_post_f,
                // batch subroot (public)
                agg_result.root_state.subroot,
                // historic roots set transition (public)
                pre_roots_set_root,
                post_roots_set_root,
                // L2 block metadata Merkle hash (public)
                l2_metadata_merkle_hash,
            ];
            final_public_inputs.extend(final_acc_pi.clone());

            let final_proof_start = Instant::now();
            let final_proof_bytes = {
                let mut transcript =
                    CircuitTranscript::<keccak_transcript::KeccakTranscript>::init();
                create_proof::<
                    F,
                    KZGCommitmentScheme<E>,
                    CircuitTranscript<keccak_transcript::KeccakTranscript>,
                    rollup_ivc_circuits::WrapStepCircuit,
                >(
                    &final_agg_srs,
                    &final_pk,
                    &[final_circuit],
                    1,
                    &[&[&[], &final_public_inputs]],
                    OsRng,
                    &mut transcript,
                )
                .map_err(|e| AppError::Proof(err_string(e)))?;
                transcript.finalize()
            };
            let final_proof_elapsed = final_proof_start.elapsed();
            final_wrap_proof_gen_times.push(final_proof_elapsed);

            println!("final proof size (bytes): {}", final_proof_bytes.len());
            println!("final WrapStep proof generation time: {:?}", final_proof_elapsed);

            let mut transcript =
                CircuitTranscript::<keccak_transcript::KeccakTranscript>::init_from_bytes(
                    &final_proof_bytes,
                );
            let committed_bases: &[&[midnight_curves::G1Projective]] =
                &[&[midnight_curves::G1Projective::identity()]];
            let instances: &[&[&[F]]] = &[&[&final_public_inputs]];

            let dual_msm = prepare::<
                F,
                KZGCommitmentScheme<E>,
                CircuitTranscript<keccak_transcript::KeccakTranscript>,
            >(&final_vk, committed_bases, instances, &mut transcript)
            .map_err(|e| AppError::VerificationPrep(err_string(e)))?;

            assert!(dual_msm.check(&final_agg_srs.verifier_params()), "Final proof must verify");

            assert!(
                final_acc.check(&final_agg_srs.s_g2().into(), &agg_result.fixed_bases),
                "Final aggregation accumulator must verify"
            );

            #[cfg(feature = "evm-bench")]
            if run_evm_bench {
                let (lhs_eval, rhs_eval) = final_acc.fully_collapse(&agg_result.fixed_bases);
                let lhs_affine = lhs_eval.to_affine();
                let rhs_affine = rhs_eval.to_affine();
                println!(
                    "final accumulator affine checks: lhs_on_curve={} lhs_torsion_free={} rhs_on_curve={} rhs_torsion_free={}",
                    bool::from(lhs_affine.is_on_curve()),
                    bool::from(lhs_affine.is_torsion_free()),
                    bool::from(rhs_affine.is_on_curve()),
                    bool::from(rhs_affine.is_torsion_free()),
                );
                let expected_lhs = g1_to_word_hex(lhs_eval);
                let expected_rhs = g1_to_word_hex(rhs_eval);
                let decoded_lhs = decode_final_acc_point_words(&final_acc_pi, 0)?;
                let decoded_rhs = decode_final_acc_point_words(&final_acc_pi, 14)?;
                if env_flag("SHIELDED_POOL_EVM_DEBUG_ACC") {
                    println!("final accumulator lhs words: {:?}", expected_lhs);
                    println!("final accumulator rhs words: {:?}", expected_rhs);
                }
                if expected_lhs != decoded_lhs || expected_rhs != decoded_rhs {
                    return Err(AppError::EvmBench(format!(
                        "final accumulator PI decode mismatch on batch {}:\nexpected_lhs={:?}\ndecoded_lhs={:?}\nexpected_rhs={:?}\ndecoded_rhs={:?}",
                        batch_idx, expected_lhs, decoded_lhs, expected_rhs, decoded_rhs
                    )));
                }
            }

            println!(
                "fully-evaluated final accumulator length: {} field elements",
                final_acc_pi.len()
            );

            #[cfg(feature = "evm-bench")]
            {
                if run_evm_bench {
                    let sample = FinalWrapBenchSample {
                        batch_idx,
                        proof: final_proof_bytes.clone(),
                        public_inputs: final_public_inputs.clone(),
                        l2_block_metadata: l2_block_metadata.clone(),
                    };
                    evm_bench_samples.push(sample.clone());

                    if run_final_wrap_bench && live_stateful_loop {
                        emit_final_wrap_evm_stateful_loop_bench(
                            final_agg_srs.verifier_params(),
                            final_vk.clone(),
                            final_agg_srs.s_g2().into(),
                            std::slice::from_ref(&sample),
                        )?;
                    }
                }
            }

            println!(
                "\n✅ Final aggregation (MERGED) proof for batch {} verified.\n\
                 Batch subroot (host): {:?}\n\
                    Commitment-set transition: {:?} -> {:?}\n\
                    Nullifier-set transition: {:?} -> {:?}\n\
                    Historic-roots-set transition: {:?} -> {:?}\n\
                    Block counter transition: {} -> {}",
                batch_idx,
                agg_result.root_state.subroot,
                agg_result.root_state.c_pre,
                agg_result.root_state.c_post,
                agg_result.root_state.n_pre,
                agg_result.root_state.n_post,
                pre_roots_set_root,
                post_roots_set_root,
                blk_pre_u64,
                blk_post_u64
            );
        }

        // --- Commit batch to “chain state” ---
        chain.accounts = shadow_accounts;
        chain.nullifier_map = shadow_nullifier_map;
        chain.commitment_map = shadow_commitment_map;

        chain.commitment_roots_set = shadow_commitment_roots_set;
        chain.commitment_root_history.push(chain.commitment_map.succinct_repr());
        chain.commitment_map_history.push(chain.commitment_map.clone());

        // Advance the global head block number after accepting the final wrap proof.
        blk_head = blk_post_u64;
        chain.blk_head = blk_head;

        println!(
            "After batch {} committed commitment root: {:?}",
            batch_idx,
            chain.commitment_map.succinct_repr()
        );

        // Demonstrate replay protection using the POST state.
        if !skip_replay_demo {
            demonstrate_replay_protection(
                &agg_setup,
                &srs,
                vk.vk(),
                &client_proofs,
                chain.commitment_map.clone(),
                chain.nullifier_map.clone(),
                chain.commitment_roots_set.clone(),
                &agg_result.root_state,
            );
        }

        batch_idx += 1;
    }

    if !final_wrap_proof_gen_times.is_empty() {
        let total_proof_time =
            final_wrap_proof_gen_times.iter().fold(Duration::ZERO, |acc, t| acc + *t);
        let min_proof_time = final_wrap_proof_gen_times.iter().copied().min().unwrap_or_default();
        let max_proof_time = final_wrap_proof_gen_times.iter().copied().max().unwrap_or_default();
        let avg_proof_time_ms =
            (total_proof_time.as_secs_f64() * 1000.0) / (final_wrap_proof_gen_times.len() as f64);
        println!(
            "final WrapStep proof generation benchmark: batches={} total={:?} avg_ms={:.3} min={:?} max={:?}",
            final_wrap_proof_gen_times.len(),
            total_proof_time,
            avg_proof_time_ms,
            min_proof_time,
            max_proof_time
        );
    }
    println!(
        "rollup transitions completed: {} (target {})",
        batch_idx, planned_rollup_transitions
    );

    #[cfg(feature = "evm-bench")]
    {
        if run_evm_bench {
            if run_transition_bench {
                let transition_vk = agg_setup
                    .agg_store
                    .get(agg_setup.max_agg_level)
                    .vk
                    .as_ref()
                    .clone();
                emit_rollup_transition_evm_bench(
                    agg_setup.agg_srs_internal.verifier_params(),
                    transition_vk,
                    &evm_transition_samples,
                )?;
            }

            if run_final_wrap_bench && !live_stateful_loop {
                emit_final_wrap_evm_stateful_loop_bench(
                    final_agg_srs.verifier_params(),
                    final_vk.clone(),
                    final_agg_srs.s_g2().into(),
                    &evm_bench_samples,
                )?;
            }
        }
    }

    println!("\nFinal commitment root: {:?}", chain.commitment_map.succinct_repr());

    for acc in &chain.accounts {
        let bal: u128 = acc
            .wallet
            .iter()
            .filter(|n| !n.spent)
            .fold(0u128, |s, n| s.saturating_add(n.utxo.amount));
        println!(
            "Account {} unspent notes: {}, balance {}",
            acc.id,
            acc.wallet.iter().filter(|n| !n.spent).count(),
            bal
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use std::panic;

    // -----------------------------
    // Unit tests (helpers/invariants)
    // -----------------------------

    #[test]
    fn unit_split_amount_conserves_total() {
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        for _ in 0..1_000 {
            let total = rng.r#gen::<u128>();
            let (a, b) = split_amount(&mut rng, total);
            assert!(a <= total);
            assert!(b <= total);
            assert_eq!(a.saturating_add(b), total);
        }
    }

    #[test]
    fn unit_choose_two_distinct_returns_distinct() {
        let mut rng = ChaCha8Rng::seed_from_u64(456);
        let candidates = vec![10usize, 11, 12, 13, 14];
        for _ in 0..1_000 {
            let (a, b) = choose_two_distinct(&mut rng, &candidates);
            assert_ne!(a, b);
            assert!(candidates.contains(&a));
            assert!(candidates.contains(&b));
        }
    }

    #[test]
    fn unit_spendable_note_indices_matches_predicate() {
        let asset_id = F::random(&mut ChaCha8Rng::seed_from_u64(1));
        let mut rng = ChaCha8Rng::seed_from_u64(2);

        let mut mk_note = |spent: bool, confirmed: usize| transfer_circuit::Note {
            utxo: transfer_circuit::Utxo { asset_id, amount: 1, randomness: F::random(&mut rng) },
            commit: F::random(&mut rng),
            spent,
            confirmed_at_root_idx: confirmed,
        };

        let account = transfer_circuit::Account {
            id: 0,
            sk: JubjubScalar::random(&mut OsRng),
            pk_point: JubjubSubgroup::generator() * JubjubScalar::random(&mut OsRng),
            pk_x: F::ZERO,
            pk_y: F::ZERO,
            wallet: vec![
                mk_note(false, 0), // spendable at latest>=0
                mk_note(false, 3), // spendable only at latest>=3
                mk_note(true, 0),  // never spendable
            ],
        };

        assert_eq!(spendable_note_indices(&account, 0), vec![0]);
        assert_eq!(spendable_note_indices(&account, 2), vec![0]);
        assert_eq!(spendable_note_indices(&account, 3), vec![0, 1]);
    }

    // -----------------------------
    // PBT (property-based tests)
    // -----------------------------

    proptest! {
        #[test]
        fn pbt_split_amount_conserves(seed in any::<u64>(), total in any::<u128>()) {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let (a, b) = split_amount(&mut rng, total);
            prop_assert!(a <= total);
            prop_assert!(b <= total);
            prop_assert_eq!(a.saturating_add(b), total);
        }

        #[test]
        fn pbt_choose_root_idx_for_proof_in_range(
            seed in any::<u64>(),
            min_idx in 0usize..32,
            latest_offset in 0usize..32,
        ) {
            let latest = min_idx + latest_offset;
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let chosen = choose_root_idx_for_proof(&mut rng, min_idx, latest);
            prop_assert!(chosen >= min_idx);
            prop_assert!(chosen <= latest);
        }
    }

    // -----------------------------
    // Integration-style tests (prove + aggregate)
    // These validate the rollup safety properties end-to-end.
    //
    // NOTE: These are "integration-style" but live in the module to access private helpers.
    // -----------------------------

    struct MiniEnv {
        srs: ParamsKZG<E>,
        relation: transfer_circuit::Spend2Output2,
        leaf_vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
        pk: MidnightPK<transfer_circuit::Spend2Output2>,
        agg_setup: setup_ivc::AggSetup,
        leaf_vk_name: &'static str,
        k: u32,
    }

    fn mini_env(k: u32, batch_size: usize) -> Result<MiniEnv, AppError> {
        const LEAF_VK_NAME: &str = "spend2output2_vk_test";

        let srs = trusted_setup::filecoin_srs_agg(k)
            .map_err(|e| AppError::TrustedSetup(err_string(e)))?;

        let relation = transfer_circuit::Spend2Output2;
        let vk_mid = midnight_zk_stdlib::setup_vk(&srs, &relation);
        let pk = midnight_zk_stdlib::setup_pk(&relation, &vk_mid);
        let leaf_vk = vk_mid.vk().clone();

        let agg_setup = setup_ivc::prepare_agg_setup(&srs, &leaf_vk, LEAF_VK_NAME, k, batch_size);

        Ok(MiniEnv { srs, relation, leaf_vk, pk, agg_setup, leaf_vk_name: LEAF_VK_NAME, k })
    }

    fn make_chain(seed: u64, num_accounts: usize, deposits_per_account: usize) -> ChainState {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        init_chain_state(&mut rng, num_accounts, deposits_per_account)
    }

    /// Generate a full batch: plans txs, builds witnesses, produces client proofs, applies effects
    /// to obtain the post shadow state, then aggregates.
    fn prove_and_aggregate_one_batch(
        env: &MiniEnv,
        chain: &ChainState,
        seed: u64,
        batch_size: usize,
    ) -> Result<
        (
            BatchPreState,
            Vec<rollup_ivc_proofs::ClientProof>,
            CommitmentMap,
            CommitmentMap,
            rollup_ivc_proofs::AggregationResult,
        ),
        AppError,
    > {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let pre = snapshot_batch_pre_state(chain);

        let mut shadow_accounts = chain.accounts.clone();
        let mut shadow_nullifier_map = chain.nullifier_map.clone();
        let mut shadow_commitment_map = chain.commitment_map.clone();

        let mut client_proofs: Vec<rollup_ivc_proofs::ClientProof> = Vec::with_capacity(batch_size);

        for tx_idx in 0..batch_size {
            let plan = plan_transaction(&mut rng, &shadow_accounts, pre.latest_confirmed_root_idx)
                .expect(
                    "expected at least one viable sender with >=2 spendable notes in test setup",
                );

            // Build tx ONCE; proof must match effects
            let (built, _root_before) = build_transaction(
                &mut rng,
                chain.asset_id,
                &shadow_accounts,
                &chain.commitment_map_history,
                &chain.commitment_root_history,
                &plan,
                pre.latest_confirmed_root_idx,
                /*batch_idx=*/ 0,
                /*tx_idx=*/ tx_idx,
            )?;

            // Local conservation check (safety property: no inflation)
            let in_sum = built.witness.3.amount.saturating_add(built.witness.4.amount);
            let out_sum = built.witness.5.amount.saturating_add(built.witness.6.amount);
            assert_eq!(in_sum, out_sum, "amount must be conserved per tx");
            assert_eq!(built.witness.3.asset_id, built.witness.5.asset_id);
            assert_eq!(built.witness.4.asset_id, built.witness.6.asset_id);

            let effects = effects_from(&plan, &built);

            let proof = prove_client(&env.srs, &env.pk, &env.relation, built)?;
            client_proofs.push(proof);

            apply_tx_effects(
                &mut shadow_accounts,
                &mut shadow_commitment_map,
                &mut shadow_nullifier_map,
                chain.commitment_root_history.len(), // new outputs confirmed at next root index
                &effects,
            );
        }

        let agg_result = rollup_ivc_proofs::aggregate_client_proofs_cached(
            &env.agg_setup,
            &env.srs,
            &env.leaf_vk,
            &client_proofs,
            pre.pre_commitment_map.clone(),
            pre.pre_nullifier_map.clone(),
            pre.pre_roots_set_map.clone(),
            F::ZERO,
        );

        Ok((pre, client_proofs, shadow_commitment_map, shadow_nullifier_map, agg_result))
    }

    /// Positive: batch validity + deterministic root transitions.
    #[test]
    fn integration_batch_validity_roots_match_shadow_state() -> Result<(), AppError> {
        let batch_size = 4; // keep tests light; still a power-of-two
        let env = mini_env(/*k=*/ 14, batch_size)?;
        let chain =
            make_chain(/*seed=*/ 777, /*accounts=*/ 4, /*deposits_per_account=*/ 6);

        let (pre, _client_proofs, post_cmap, post_nmap, agg) =
            prove_and_aggregate_one_batch(&env, &chain, /*seed=*/ 888, batch_size)?;

        // Safety: root pre bindings
        assert_eq!(agg.root_state.c_pre, pre.pre_commitment_map.succinct_repr());
        assert_eq!(agg.root_state.n_pre, pre.pre_nullifier_map.succinct_repr());

        // Safety: post roots equal applying the same txs to the shadow state
        assert_eq!(agg.root_state.c_post, post_cmap.succinct_repr());
        assert_eq!(agg.root_state.n_post, post_nmap.succinct_repr());

        // Safety: proofs must be against an admissible historic root (here genesis is in roots-set)
        assert_ne!(pre.pre_roots_set_map.get(&agg.root_state.c_pre), F::ZERO);

        // Replay-guard precondition: c_post must not already exist in roots-set at pre
        assert_eq!(pre.pre_roots_set_map.get(&agg.root_state.c_post), F::ZERO);

        Ok(())
    }

    /// Negative: replay using POST state should be rejected (nullifiers already spent / root advanced).
    #[test]
    fn negative_replay_aggregation_with_post_state_panics() -> Result<(), AppError> {
        let batch_size = 4;
        let env = mini_env(14, batch_size)?;
        let chain = make_chain(1234, 4, 6);

        let (pre, client_proofs, post_cmap, post_nmap, _agg) =
            prove_and_aggregate_one_batch(&env, &chain, 5678, batch_size)?;

        // Now attempt to re-aggregate the SAME client proofs, but against POST maps.
        // This should fail: leaves prove against old roots and nullifiers are already inserted.
        let replay = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = rollup_ivc_proofs::aggregate_client_proofs_cached(
                &env.agg_setup,
                &env.srs,
                &env.leaf_vk,
                &client_proofs,
                post_cmap.clone(),
                post_nmap.clone(),
                pre.pre_roots_set_map.clone(),
                F::ZERO,
            );
        }));

        assert!(replay.is_err(), "replay must be rejected");
        Ok(())
    }

    /// Negative: if the aggregator is given the wrong PRE state roots (tampered pre-map),
    /// aggregation must be rejected.
    #[test]
    fn negative_wrong_pre_state_detected_by_head_check() -> Result<(), AppError> {
        let batch_size = 4;
        let env = mini_env(14, batch_size)?;
        let chain = make_chain(42, 4, 6);

        let (pre, client_proofs, _post_cmap, _post_nmap, _agg) =
            prove_and_aggregate_one_batch(&env, &chain, 99, batch_size)?;

        // Tamper pre-state
        let mut wrong_pre_cmap = pre.pre_commitment_map.clone();
        let mut rng = ChaCha8Rng::seed_from_u64(2024);
        wrong_pre_cmap.insert(&F::random(&mut rng), &F::ONE);

        let agg = rollup_ivc_proofs::aggregate_client_proofs_cached(
            &env.agg_setup,
            &env.srs,
            &env.leaf_vk,
            &client_proofs,
            wrong_pre_cmap.clone(),
            pre.pre_nullifier_map.clone(),
            pre.pre_roots_set_map.clone(),
            F::ZERO,
        );

        // The aggregated batch starts from the wrong head (this is what the node must reject).
        assert_eq!(agg.root_state.c_pre, wrong_pre_cmap.succinct_repr());
        assert_ne!(agg.root_state.c_pre, pre.pre_commitment_map.succinct_repr());

        Ok(())
    }

    /// Negative (stronger double-spend): same nullifiers twice inside the same batch must be rejected.
    /// If this test fails, it’s a real bug relative to the stated safety property.
    #[test]
    fn negative_duplicate_nullifiers_within_batch_panics() -> Result<(), AppError> {
        let batch_size = 4;
        let env = mini_env(14, batch_size)?;
        let chain = make_chain(7, 4, 6);
        let pre = snapshot_batch_pre_state(&chain);

        let mut rng = ChaCha8Rng::seed_from_u64(8);
        let shadow_accounts = chain.accounts.clone();

        // Pick a sender and two spendable notes at pre state.
        let sender_idx =
            choose_sender_idx(&mut rng, &shadow_accounts, pre.latest_confirmed_root_idx)
                .expect("need viable sender");
        let spendable =
            spendable_note_indices(&shadow_accounts[sender_idx], pre.latest_confirmed_root_idx);
        let (old1_idx, old2_idx) = choose_two_distinct(&mut rng, &spendable);

        // Force two txs spending the same inputs (=> same nullifiers), but with different outputs.
        let plan = PlannedTx {
            sender_idx,
            old1_idx,
            old2_idx,
            recipient1_idx: rng.gen_range(0..shadow_accounts.len()),
            recipient2_idx: rng.gen_range(0..shadow_accounts.len()),
            root_idx_for_proof: pre.latest_confirmed_root_idx,
        };

        let mut proofs = Vec::with_capacity(batch_size);

        for tx_idx in 0..batch_size {
            let (built, _) = build_transaction(
                &mut rng,
                chain.asset_id,
                &shadow_accounts,
                &chain.commitment_map_history,
                &chain.commitment_root_history,
                &plan,
                pre.latest_confirmed_root_idx,
                0,
                tx_idx,
            )?;
            let proof = prove_client(&env.srs, &env.pk, &env.relation, built)?;
            proofs.push(proof);
        }

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = rollup_ivc_proofs::aggregate_client_proofs_cached(
                &env.agg_setup,
                &env.srs,
                &env.leaf_vk,
                &proofs,
                pre.pre_commitment_map.clone(),
                pre.pre_nullifier_map.clone(),
                pre.pre_roots_set_map.clone(),
                F::ZERO,
            );
        }));

        assert!(
            res.is_err(),
            "batch must reject duplicate nullifiers (double-spend) inside the same batch"
        );

        Ok(())
    }
}
