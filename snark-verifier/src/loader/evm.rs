//! `Loader` implementation for generating yul code as EVM verifier.

mod code;
/// Solidity add-on snippets for custom checks layered on top of generated verifiers.
pub mod addons;
/// Compact EVM verifier runtime/artifact generator.
pub mod compact_codegen;
/// Compact instruction set and program encoding for EVM verifier execution.
pub mod compact_ir;
pub(crate) mod loader;
pub(crate) mod util;

pub use code::{EvmCodegenMode, UnrolledShardedProgramManifest, UnrolledShardedVerifierArtifacts};
pub use compact_codegen::{
    build_compact_verifier_artifacts, data_page_deployment_code, encode_compact_constructor_args,
    CompactVerifierArtifacts,
};
pub use addons::{final_accumulator_pairing_addon_solidity, uhf_addon_solidity};
pub use compact_ir::{CompactProgram, CompactProgramManifest, COMPACT_OPCODE_VERSION};
pub use loader::{EcPoint, EvmLoader, Scalar};
pub use util::{
    compile_solidity, compile_solidity_runtime, compile_solidity_runtime_via_ir,
    compile_solidity_via_ir, encode_calldata, estimate_gas, fe_to_u256, modulus, u256_to_fe,
    Address, B256, U256, U512,
};
#[cfg(feature = "revm")]
pub use util::{
    deploy_and_call, deploy_and_call_with_metrics, deploy_compact_and_call,
    deploy_compact_and_call_with_metrics, deploy_unrolled_sharded_and_call,
    deploy_unrolled_sharded_and_call_with_metrics, CompactExecutionMetrics, EvmExecutionMetrics,
    UnrolledShardedExecutionMetrics,
};
