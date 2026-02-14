pub enum Precompiled {
    BigModExp = 0x05,
    // EIP-2537 (Prague): BLS12-381 precompile addresses.
    Bls12_381G1Msm = 0x0c,
    Bls12_381Pairing = 0x0f,
}

/// EVM verifier codegen backend selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmCodegenMode {
    /// Emit direct unrolled assembly statements.
    Unrolled,
    /// Emit unrolled verifier logic split across delegate-called shard contracts.
    UnrolledSharded,
    /// Emit compact bytecode program interpreted by a small runtime.
    Compact,
    /// Emit compact program with hot scalar arithmetic opcodes for lower gas.
    Hybrid,
}

/// Size and layout metadata for a sharded unrolled verifier program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnrolledShardedProgramManifest {
    /// Runtime bytecode size limit enforced for each generated contract.
    pub runtime_code_size_limit_bytes: usize,
    /// Initcode size limit enforced for each generated contract.
    pub initcode_size_limit_bytes: usize,
    /// Total number of emitted unrolled statement blocks before sharding.
    pub total_statements: usize,
    /// Inclusive start statement index for each shard.
    pub shard_statement_start_indices: Vec<usize>,
    /// Exclusive end statement index for each shard.
    pub shard_statement_end_indices: Vec<usize>,
    /// Dispatcher runtime bytecode size in bytes.
    pub dispatcher_runtime_code_bytes: usize,
    /// Dispatcher initcode size in bytes.
    pub dispatcher_deployment_code_bytes: usize,
    /// Runtime bytecode size in bytes for each shard.
    pub shard_runtime_code_bytes: Vec<usize>,
    /// Initcode size in bytes for each shard.
    pub shard_deployment_code_bytes: Vec<usize>,
}

/// Solidity sources and bytecode artifacts for an unrolled-sharded verifier.
#[derive(Clone, Debug)]
pub struct UnrolledShardedVerifierArtifacts {
    /// Dispatcher Solidity source.
    pub dispatcher_solidity: String,
    /// Dispatcher deployment bytecode.
    pub dispatcher_deployment_code: Vec<u8>,
    /// Dispatcher runtime bytecode.
    pub dispatcher_runtime_code: Vec<u8>,
    /// Shard Solidity sources ordered by execution order.
    pub shard_solidity_sources: Vec<String>,
    /// Shard deployment bytecodes ordered by execution order.
    pub shard_deployment_codes: Vec<Vec<u8>>,
    /// Shard runtime bytecodes ordered by execution order.
    pub shard_runtime_codes: Vec<Vec<u8>>,
    /// Build manifest with sizes and statement partition metadata.
    pub manifest: UnrolledShardedProgramManifest,
}

#[derive(Clone, Debug)]
pub struct SolidityAssemblyCode {
    // runtime code area
    runtime: String,
    runtime_blocks: Vec<String>,
}

impl SolidityAssemblyCode {
    pub fn new() -> Self {
        Self { runtime: String::new(), runtime_blocks: Vec::new() }
    }

    pub fn code(&self, scalar_modulus: String) -> String {
        format!(
            "
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

contract Halo2Verifier {{
    fallback(bytes calldata) external returns (bytes memory) {{
        assembly (\"memory-safe\") {{
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {{
                revert(0, 0)
            }}

            let success := true
            let f_q := {scalar_modulus}
            {}
        }}
    }}
}}
        ",
            self.runtime
        )
    }

    pub fn runtime_append(&mut self, mut code: String) {
        self.runtime_blocks.push(code.clone());
        code.push('\n');
        self.runtime.push_str(&code);
    }

    pub fn runtime_blocks(&self) -> &[String] {
        &self.runtime_blocks
    }
}
