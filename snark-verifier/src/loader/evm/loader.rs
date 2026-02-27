use crate::{
    loader::{
        evm::{
            code::{
                Precompiled, SolidityAssemblyCode, UnrolledShardedProgramManifest,
                UnrolledShardedVerifierArtifacts,
            },
            compile_solidity, compile_solidity_runtime, fe_to_u256, modulus, u256_to_fe, U256,
            U512,
        },
        EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader,
    },
    util::{
        arithmetic::{Coordinates, CurveAffine, FieldOps, PrimeField},
        Itertools,
    },
};
use hex;
use std::{
    cell::{RefCell, RefMut},
    collections::HashMap,
    fmt::{self, Debug},
    iter,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
};

/// Memory pointer starts at 0x80, which is the end of the Solidity memory layout scratch space.
pub const MEM_PTR_START: usize = 0x80;
const BLS_ENCODED_FP_BYTES: usize = 0x40;
const BLS_G1_BYTES: usize = 2 * BLS_ENCODED_FP_BYTES;
const BLS_G2_BYTES: usize = 4 * BLS_ENCODED_FP_BYTES;
const EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES: usize = 24_576;
const EVM_INITCODE_SIZE_LIMIT_BYTES: usize = 49_152;
const SHARDED_INITIAL_GROUP_SIZE: usize = 64;

/// Half-open index range `[start, end)` over emitted runtime statement blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShardStatementRange {
    start: usize,
    end: usize,
}

impl ShardStatementRange {
    /// Returns the number of statements covered by this half-open range.
    fn len(self) -> usize {
        self.end - self.start
    }

    /// Splits the range into two contiguous halves.
    ///
    /// Panics when called for a single-statement range.
    fn bisect(self) -> (Self, Self) {
        assert!(self.len() > 1, "cannot bisect a single-statement range");
        let mid = self.start + self.len() / 2;
        (Self { start: self.start, end: mid }, Self { start: mid, end: self.end })
    }
}

#[derive(Clone, Debug)]
pub enum Value<T> {
    Constant(T),
    Memory(usize),
    Negated(Box<Value<T>>),
    Sum(Box<Value<T>>, Box<Value<T>>),
    Product(Box<Value<T>>, Box<Value<T>>),
}

impl<T: Debug> PartialEq for Value<T> {
    fn eq(&self, other: &Self) -> bool {
        self.identifier() == other.identifier()
    }
}

impl<T: Debug> Value<T> {
    fn identifier(&self) -> String {
        match self {
            Value::Constant(_) | Value::Memory(_) => format!("{self:?}"),
            Value::Negated(value) => format!("-({value:?})"),
            Value::Sum(lhs, rhs) => format!("({lhs:?} + {rhs:?})"),
            Value::Product(lhs, rhs) => format!("({lhs:?} * {rhs:?})"),
        }
    }
}

/// `Loader` implementation for generating yul code as EVM verifier.
#[derive(Clone, Debug)]
pub struct EvmLoader {
    scalar_modulus: U256,
    base_field_bytes: usize,
    invert_modexp_input_ptr: RefCell<Option<usize>>,
    code: RefCell<SolidityAssemblyCode>,
    ptr: RefCell<usize>,
    cache: RefCell<HashMap<String, usize>>,
}

fn hex_encode_u256(value: &U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

/// Returns deterministic shard contract names (`Halo2VerifierShard{index}`).
fn unrolled_shard_contract_name(index: usize) -> String {
    format!("Halo2VerifierShard{index}")
}

/// Wraps a shard runtime-body snippet in a full deployable Solidity contract.
fn build_unrolled_shard_solidity(contract_name: &str, scalar_modulus: U256, body: &str) -> String {
    format!(
        r#"
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

contract {contract_name} {{
    fallback(bytes calldata) external returns (bytes memory) {{
        assembly ("memory-safe") {{
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {{
                revert(0, 0)
            }}

            let success := 1
            let f_q := {scalar_modulus}
{body}
            mstore(0x00, success)
            return(0x00, 0x20)
        }}
    }}
}}
"#,
        scalar_modulus = hex_encode_u256(&scalar_modulus),
    )
}

/// Builds the fixed dispatcher contract that delegate-calls each verifier shard.
fn build_unrolled_dispatcher_solidity() -> String {
    // `shards` is the first state variable and occupies storage slot 0.
    // Dynamic-array element base slot is `keccak256(abi.encode(slot))`.
    r#"
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

contract Halo2VerifierDispatcher {
    address[] private shards;

    constructor(address[] memory _shards) {
        shards = _shards;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {
                revert(0, 0)
            }

            let calldata_ptr := 0x80
            let calldata_len := calldatasize()
            calldatacopy(calldata_ptr, 0, calldata_len)

            let len := sload(0)
            mstore(0x00, 0)
            let base := keccak256(0x00, 0x20)

            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let shard := and(
                    sload(add(base, i)),
                    0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
                )
                if iszero(delegatecall(gas(), shard, calldata_ptr, calldata_len, 0, 0)) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
                if iszero(eq(returndatasize(), 0x20)) {
                    revert(0, 0)
                }
                returndatacopy(0, 0, 0x20)
                if iszero(mload(0)) {
                    revert(0, 0)
                }
            }
            return(0, 0)
        }
    }
}
"#
    .to_string()
}

/// Best-effort compiles Solidity source into deployment/runtime bytecode.
///
/// Returns `None` when either compile panics.
fn try_compile_solidity_sizes(solidity: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let deployment = catch_unwind(AssertUnwindSafe(|| compile_solidity(solidity))).ok()?;
    let runtime = catch_unwind(AssertUnwindSafe(|| compile_solidity_runtime(solidity))).ok()?;
    Some((deployment, runtime))
}

/// Concatenates a statement-block sub-range with newlines.
fn join_statement_blocks(blocks: &[String], start: usize, end: usize) -> String {
    blocks[start..end].iter().map(String::as_str).join("\n")
}

/// Returns whether compiled deployment/runtime bytecode sizes satisfy EIP-3860 and EIP-170.
fn fits_evm_code_size_limits(deployment: &[u8], runtime: &[u8]) -> bool {
    runtime.len() <= EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES
        && deployment.len() <= EVM_INITCODE_SIZE_LIMIT_BYTES
}

/// Decodes little-endian bytes into two padded big-endian 256-bit words.
fn le_bytes_to_padded_be_words(bytes_le: &[u8]) -> [U256; 2] {
    assert!(bytes_le.len() <= BLS_ENCODED_FP_BYTES);
    let mut padded = [0u8; BLS_ENCODED_FP_BYTES];
    let be = bytes_le.iter().rev().copied().collect_vec();
    let offset = BLS_ENCODED_FP_BYTES - be.len();
    padded[offset..].copy_from_slice(&be);
    [U256::from_be_slice(&padded[..0x20]), U256::from_be_slice(&padded[0x20..BLS_ENCODED_FP_BYTES])]
}

impl EvmLoader {
    /// Initialize a [`EvmLoader`] with base and scalar field.
    pub fn new<Base, Scalar>() -> Rc<Self>
    where
        Base: PrimeField,
        Scalar: PrimeField<Repr = [u8; 32]>,
    {
        let base_field_bytes = Base::Repr::default().as_ref().len();
        assert!(
            base_field_bytes <= BLS_ENCODED_FP_BYTES,
            "Base field encoding length must be <= 64 bytes"
        );
        let scalar_modulus = modulus::<Scalar>();
        let code = SolidityAssemblyCode::new();

        Rc::new(Self {
            scalar_modulus,
            base_field_bytes,
            invert_modexp_input_ptr: RefCell::new(None),
            code: RefCell::new(code),
            ptr: RefCell::new(MEM_PTR_START),
            cache: Default::default(),
        })
    }

    /// Returns generated Solidity code. This is "Solidity" code that is wrapped in an assembly block.
    /// In other words, it's basically just assembly (equivalently, Yul).
    pub fn solidity_code(self: &Rc<Self>) -> String {
        let code = "
                    // Revert if anything fails
                    if iszero(success) { revert(0, 0) }

                    // Return empty bytes on success
                    return(0, 0)"
            .to_string();
        self.code.borrow_mut().runtime_append(code);
        self.code.borrow().code(hex_encode_u256(&self.scalar_modulus))
    }

    /// Returns a mutable handle to the underlying assembly code buffer.
    pub fn code_mut(&self) -> RefMut<'_, SolidityAssemblyCode> {
        self.code.borrow_mut()
    }

    /// Compiles one shard candidate for a statement range and returns Solidity + bytecode.
    fn compile_shard_candidate(
        &self,
        statement_blocks: &[String],
        contract_name: &str,
        range: ShardStatementRange,
    ) -> (String, Option<(Vec<u8>, Vec<u8>)>) {
        let body = join_statement_blocks(statement_blocks, range.start, range.end);
        let solidity = build_unrolled_shard_solidity(contract_name, self.scalar_modulus, &body);
        let artifacts = try_compile_solidity_sizes(&solidity);
        (solidity, artifacts)
    }

    /// Ensures `grouped_ranges[cursor]` is compilable and within code-size limits.
    ///
    /// If the current range fails, it is bisected in-place and retried until it fits
    /// or until a single-statement range proves irreducible.
    fn ensure_grouped_range_fits(
        &self,
        statement_blocks: &[String],
        grouped_ranges: &mut Vec<ShardStatementRange>,
        cursor: usize,
    ) {
        loop {
            let range = grouped_ranges[cursor];
            let (_, artifacts) = self.compile_shard_candidate(
                statement_blocks,
                "Halo2VerifierShardCandidate",
                range,
            );
            match artifacts {
                Some((deployment, runtime)) if fits_evm_code_size_limits(&deployment, &runtime) => {
                    return;
                }
                Some((deployment, runtime)) if range.len() <= 1 => {
                    panic!(
                        "single statement range [{}..{}) exceeds EVM limits: runtime={} initcode={}",
                        range.start,
                        range.end,
                        runtime.len(),
                        deployment.len()
                    );
                }
                None if range.len() <= 1 => {
                    panic!(
                        "failed to compile unrolled-sharded candidate for statement range [{}..{})",
                        range.start, range.end
                    );
                }
                _ => {
                    let (left, right) = range.bisect();
                    grouped_ranges.splice(cursor..=cursor, [left, right]);
                }
            }
        }
    }

    /// Finds the largest contiguous grouped-range prefix starting at `cursor` that still fits.
    fn find_largest_fitting_group_end(
        &self,
        statement_blocks: &[String],
        grouped_ranges: &[ShardStatementRange],
        cursor: usize,
    ) -> usize {
        let mut lo = cursor + 1;
        let mut hi = grouped_ranges.len() + 1;
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            let range = ShardStatementRange {
                start: grouped_ranges[cursor].start,
                end: grouped_ranges[mid - 1].end,
            };
            let (_, artifacts) = self.compile_shard_candidate(
                statement_blocks,
                "Halo2VerifierShardCandidate",
                range,
            );
            let fits = artifacts
                .as_ref()
                .map(|(deployment, runtime)| fits_evm_code_size_limits(deployment, runtime))
                .unwrap_or(false);
            if fits {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Creates compiled shard Solidity/runtime artifacts from final statement ranges.
    fn build_shard_artifacts(
        &self,
        statement_blocks: &[String],
        shards: &[ShardStatementRange],
    ) -> (Vec<String>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<usize>, Vec<usize>) {
        shards
            .iter()
            .enumerate()
            .map(|(idx, &range)| {
                let contract_name = unrolled_shard_contract_name(idx);
                let (solidity, artifacts) =
                    self.compile_shard_candidate(statement_blocks, &contract_name, range);
                let (deployment_code, runtime_code) = artifacts.unwrap_or_else(|| {
                    panic!(
                        "failed to compile finalized unrolled-sharded contract {contract_name} for statement range [{}..{})",
                        range.start, range.end
                    )
                });
                assert!(
                    fits_evm_code_size_limits(&deployment_code, &runtime_code),
                    "unrolled-sharded shard exceeds EVM limits: runtime={} initcode={}",
                    runtime_code.len(),
                    deployment_code.len()
                );
                (solidity, deployment_code, runtime_code, range.start, range.end)
            })
            .multiunzip()
    }

    /// Returns unrolled-sharded verifier dispatcher plus shard artifacts.
    ///
    /// Strategy:
    /// 1. Split emitted runtime statements into coarse groups.
    /// 2. Recursively bisect non-fitting groups until each group is individually deployable.
    /// 3. Binary-search the largest contiguous group window that still fits each shard.
    /// 4. Compile finalized shard contracts and dispatcher and return all artifacts.
    pub fn unrolled_sharded_verifier_artifacts(&self) -> UnrolledShardedVerifierArtifacts {
        let statement_blocks = self.code.borrow().runtime_blocks().to_vec();
        assert!(
            !statement_blocks.is_empty(),
            "unrolled-sharded verifier generation requires at least one emitted statement block"
        );

        let total_statements = statement_blocks.len();

        // Start with coarse blocks, then refine only where needed.
        let mut grouped_ranges = (0..total_statements)
            .step_by(SHARDED_INITIAL_GROUP_SIZE)
            .map(|start| ShardStatementRange {
                start,
                end: (start + SHARDED_INITIAL_GROUP_SIZE).min(total_statements),
            })
            .collect_vec();

        let mut cursor = 0usize;
        let shards = iter::from_fn(|| {
            (cursor < grouped_ranges.len()).then(|| {
                self.ensure_grouped_range_fits(&statement_blocks, &mut grouped_ranges, cursor);
                let end_group =
                    self.find_largest_fitting_group_end(&statement_blocks, &grouped_ranges, cursor);
                let shard = ShardStatementRange {
                    start: grouped_ranges[cursor].start,
                    end: grouped_ranges[end_group - 1].end,
                };
                cursor = end_group;
                shard
            })
        })
        .collect_vec();

        let (
            shard_solidity_sources,
            shard_deployment_codes,
            shard_runtime_codes,
            shard_statement_start_indices,
            shard_statement_end_indices,
        ) = self.build_shard_artifacts(&statement_blocks, &shards);

        let dispatcher_solidity = build_unrolled_dispatcher_solidity();
        let (dispatcher_deployment_code, dispatcher_runtime_code) =
            try_compile_solidity_sizes(&dispatcher_solidity)
                .expect("failed to compile unrolled-sharded dispatcher Solidity");
        assert!(
            fits_evm_code_size_limits(&dispatcher_deployment_code, &dispatcher_runtime_code),
            "unrolled-sharded dispatcher exceeds EVM limits: runtime={} initcode={}",
            dispatcher_runtime_code.len(),
            dispatcher_deployment_code.len()
        );

        let manifest = UnrolledShardedProgramManifest {
            runtime_code_size_limit_bytes: EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES,
            initcode_size_limit_bytes: EVM_INITCODE_SIZE_LIMIT_BYTES,
            total_statements,
            shard_statement_start_indices,
            shard_statement_end_indices,
            dispatcher_runtime_code_bytes: dispatcher_runtime_code.len(),
            dispatcher_deployment_code_bytes: dispatcher_deployment_code.len(),
            shard_runtime_code_bytes: shard_runtime_codes.iter().map(Vec::len).collect(),
            shard_deployment_code_bytes: shard_deployment_codes.iter().map(Vec::len).collect(),
        };

        UnrolledShardedVerifierArtifacts {
            dispatcher_solidity,
            dispatcher_deployment_code,
            dispatcher_runtime_code,
            shard_solidity_sources,
            shard_deployment_codes,
            shard_runtime_codes,
            manifest,
        }
    }

    /// Allocates memory chunk with given `size` and returns pointer.
    pub fn allocate(self: &Rc<Self>, size: usize) -> usize {
        let ptr = *self.ptr.borrow();
        *self.ptr.borrow_mut() += size;
        ptr
    }

    pub(crate) fn ptr(&self) -> usize {
        *self.ptr.borrow()
    }

    pub(crate) fn proof_ec_point_bytes(&self) -> usize {
        2 * self.base_field_bytes
    }

    pub(crate) fn evm_ec_point_bytes(&self) -> usize {
        BLS_G1_BYTES
    }

    fn emit_mstore_const(self: &Rc<Self>, ptr: usize, value: U256) {
        self.code
            .borrow_mut()
            .runtime_append(format!("mstore({ptr:#x}, {})", hex_encode_u256(&value)));
    }

    fn push(self: &Rc<Self>, scalar: &Scalar) -> String {
        match scalar.value.clone() {
            Value::Constant(constant) => {
                format!("{constant}")
            }
            Value::Memory(ptr) => {
                format!("mload({ptr:#x})")
            }
            Value::Negated(value) => {
                let v = self.push(&self.scalar(*value));
                format!("sub(f_q, {v})")
            }
            Value::Sum(lhs, rhs) => {
                let lhs = self.push(&self.scalar(*lhs));
                let rhs = self.push(&self.scalar(*rhs));
                format!("addmod({lhs}, {rhs}, f_q)")
            }
            Value::Product(lhs, rhs) => {
                let lhs = self.push(&self.scalar(*lhs));
                let rhs = self.push(&self.scalar(*rhs));
                format!("mulmod({lhs}, {rhs}, f_q)")
            }
        }
    }

    /// Packs `LIMBS` limbs into one 512-bit big-endian field element (`hi || lo`) in memory.
    ///
    /// The returned string is Yul code that:
    /// 1. reconstructs low/high 256-bit accumulators by shifting each limb by `idx * BITS`;
    /// 2. stores `(hi, lo)` into `ptr` and `ptr + 0x20`.
    fn pack_limbs_to_field_code<const LIMBS: usize, const BITS: usize>(
        self: &Rc<Self>,
        limbs: [&Scalar; LIMBS],
        lo_var: &str,
        hi_var: &str,
        ptr: usize,
    ) -> String {
        let init = format!("let {lo_var} := 0\nlet {hi_var} := 0\n");
        let accum = limbs
            .iter()
            .enumerate()
            .map(|(idx, limb)| {
                let shift = idx * BITS;
                assert!(shift < 512, "limb decomposition exceeds 512 bits");
                let limb_value = self.push(limb);
                if shift < 256 {
                    format!("{lo_var} := add({lo_var}, shl({shift}, {limb_value}))\n")
                } else {
                    format!("{hi_var} := add({hi_var}, shl({}, {limb_value}))\n", shift - 256)
                }
            })
            .join("");
        format!("{init}{accum}mstore({ptr:#x}, {hi_var})\nmstore({:#x}, {lo_var})\n", ptr + 0x20)
    }

    /// Calldata load a field element.
    pub fn calldataload_scalar(self: &Rc<Self>, offset: usize) -> Scalar {
        let ptr = self.allocate(0x20);
        let code = format!("mstore({ptr:#x}, mod(calldataload({offset:#x}), f_q))");
        self.code.borrow_mut().runtime_append(code);
        self.scalar(Value::Memory(ptr))
    }

    /// Calldata load an elliptic curve point and validate it's on affine plane.
    /// Note that identity will cause the verification to fail.
    pub fn calldataload_ec_point(self: &Rc<Self>, offset: usize) -> EcPoint {
        let x_ptr = self.allocate(BLS_G1_BYTES);
        let y_ptr = x_ptr + BLS_ENCODED_FP_BYTES;
        let coord_bytes = self.base_field_bytes;
        let pad = BLS_ENCODED_FP_BYTES - coord_bytes;
        let x_cd_ptr = offset;
        let y_cd_ptr = offset + coord_bytes;
        let low_word_init = if coord_bytes < 0x20 {
            format!(
                "\n                    mstore({:#x}, 0)\n                    mstore({:#x}, 0)",
                x_ptr + 0x20,
                y_ptr + 0x20
            )
        } else {
            String::new()
        };
        let code = format!(
            "
                {{
                    mstore({x_ptr:#x}, 0)
                    mstore({y_ptr:#x}, 0)
                    {low_word_init}
                    calldatacopy({:#x}, {x_cd_ptr:#x}, {coord_bytes:#x})
                    calldatacopy({:#x}, {y_cd_ptr:#x}, {coord_bytes:#x})
                }}",
            x_ptr + pad,
            y_ptr + pad,
            low_word_init = low_word_init
        );
        self.code.borrow_mut().runtime_append(code);
        self.ec_point(Value::Memory(x_ptr))
    }

    /// Decode an elliptic curve point from limbs.
    pub fn ec_point_from_limbs<const LIMBS: usize, const BITS: usize>(
        self: &Rc<Self>,
        x_limbs: [&Scalar; LIMBS],
        y_limbs: [&Scalar; LIMBS],
    ) -> EcPoint {
        let ptr = self.allocate(BLS_G1_BYTES);
        let code = format!(
            "{}{}",
            self.pack_limbs_to_field_code::<LIMBS, BITS>(x_limbs, "x_lo", "x_hi", ptr),
            self.pack_limbs_to_field_code::<LIMBS, BITS>(
                y_limbs,
                "y_lo",
                "y_hi",
                ptr + BLS_ENCODED_FP_BYTES
            )
        );

        let code = format!(
            "{{
                    {code}
                }}"
        );
        self.code.borrow_mut().runtime_append(code);
        self.ec_point(Value::Memory(ptr))
    }

    pub(crate) fn scalar(self: &Rc<Self>, value: Value<U256>) -> Scalar {
        let value = if matches!(value, Value::Constant(_) | Value::Memory(_) | Value::Negated(_)) {
            value
        } else {
            let identifier = value.identifier();
            let some_ptr = self.cache.borrow().get(&identifier).cloned();
            let ptr = if let Some(ptr) = some_ptr {
                ptr
            } else {
                let ptr = self.allocate(0x20);
                let v = self.push(&Scalar { loader: self.clone(), value });
                self.code.borrow_mut().runtime_append(format!("mstore({ptr:#x}, {v})"));
                self.cache.borrow_mut().insert(identifier, ptr);
                ptr
            };
            Value::Memory(ptr)
        };
        Scalar { loader: self.clone(), value }
    }

    fn ec_point(self: &Rc<Self>, value: Value<(U256, U256)>) -> EcPoint {
        EcPoint { loader: self.clone(), value }
    }

    /// Performs `KECCAK256` on `memory[ptr..ptr+len]` and returns pointer of
    /// hash.
    pub fn keccak256(self: &Rc<Self>, ptr: usize, len: usize) -> usize {
        let hash_ptr = self.allocate(0x20);
        let code = format!("mstore({hash_ptr:#x}, keccak256({ptr:#x}, {len}))");
        self.code.borrow_mut().runtime_append(code);
        hash_ptr
    }

    /// Copies a field element into given `ptr`.
    pub fn copy_scalar(self: &Rc<Self>, scalar: &Scalar, ptr: usize) {
        let scalar = self.push(scalar);
        self.code.borrow_mut().runtime_append(format!("mstore({ptr:#x}, {scalar})"));
    }

    /// Allocates a new field element and copies the given value into it.
    pub fn dup_scalar(self: &Rc<Self>, scalar: &Scalar) -> Scalar {
        let ptr = self.allocate(0x20);
        self.copy_scalar(scalar, ptr);
        self.scalar(Value::Memory(ptr))
    }

    /// Truncate a scalar to its low 128 bits.
    ///
    /// This is used by Midnight's optional `truncated-challenges` mode.
    #[cfg(feature = "truncated-challenges")]
    pub fn truncate_scalar_to_128(self: &Rc<Self>, scalar: &Scalar) -> Scalar {
        let mask = U256::from(u128::MAX);
        // Fold constants immediately so we avoid emitting unnecessary runtime memory ops.
        if let Value::Constant(constant) = scalar.value {
            return self.scalar(Value::Constant(constant & mask));
        }

        // For memory-backed scalars, mask in place with one `and(mload(...), mask)` sequence.
        let ptr = self.allocate(0x20);
        self.copy_scalar(scalar, ptr);
        let mask_hex = hex_encode_u256(&mask);
        self.code
            .borrow_mut()
            .runtime_append(format!("mstore({ptr:#x}, and(mload({ptr:#x}), {mask_hex}))"));
        self.scalar(Value::Memory(ptr))
    }

    /// Allocates a new elliptic curve point and copies the given value into it.
    pub fn copy_ec_point(self: &Rc<Self>, value: &EcPoint, ptr: usize) {
        match value.value {
            Value::Memory(src_ptr) => {
                let src_words = (0..(BLS_G1_BYTES / 0x20)).map(|idx| src_ptr + idx * 0x20);
                let dst_words = (0..(BLS_G1_BYTES / 0x20)).map(|idx| ptr + idx * 0x20);
                let stores = dst_words
                    .zip(src_words)
                    .map(|(dst, src)| format!("mstore({dst:#x}, mload({src:#x}))"))
                    .join("\n");
                let code = format!(
                    "{{
                            {stores}
                        }}"
                );
                self.code.borrow_mut().runtime_append(code);
            }
            Value::Constant(_) | Value::Negated(_) | Value::Sum(_, _) | Value::Product(_, _) => {
                unreachable!()
            }
        }
    }

    /// Allocates a new elliptic curve point and copies the given value into it.
    pub fn dup_ec_point(self: &Rc<Self>, value: &EcPoint) -> EcPoint {
        let ptr = self.allocate(BLS_G1_BYTES);
        self.copy_ec_point(value, ptr);
        self.ec_point(Value::Memory(ptr))
    }

    fn staticcall(self: &Rc<Self>, precompile: Precompiled, cd_ptr: usize, rd_ptr: usize) {
        let (cd_len, rd_len) = match precompile {
            Precompiled::BigModExp => (0xc0, 0x20),
            // We use G1MSM with a single pair: [G1 point (128 bytes) || scalar (32 bytes)].
            Precompiled::Bls12_381G1Msm => (BLS_G1_BYTES + 0x20, BLS_G1_BYTES),
            // 2 pairings in one call:
            //   [G1 (128) || G2 (256)] * 2 = 768 bytes
            Precompiled::Bls12_381Pairing => (2 * (BLS_G1_BYTES + BLS_G2_BYTES), 0x20),
        };
        self.staticcall_sized(precompile as usize, cd_ptr, cd_len, rd_ptr, rd_len)
    }

    fn staticcall_sized(
        self: &Rc<Self>,
        precompile: usize,
        cd_ptr: usize,
        cd_len: usize,
        rd_ptr: usize,
        rd_len: usize,
    ) {
        let code = format!(
            "success := and(eq(staticcall(gas(), {precompile:#x}, {cd_ptr:#x}, {cd_len:#x}, {rd_ptr:#x}, {rd_len:#x}), 1), success)"
        );
        self.code.borrow_mut().runtime_append(code);
    }

    fn inversion_modexp_input_ptr(self: &Rc<Self>) -> usize {
        if let Some(ptr) = *self.invert_modexp_input_ptr.borrow() {
            return ptr;
        }

        let ptr = self.allocate(0xc0);
        self.emit_mstore_const(ptr, U256::from(0x20));
        self.emit_mstore_const(ptr + 0x20, U256::from(0x20));
        self.emit_mstore_const(ptr + 0x40, U256::from(0x20));
        self.emit_mstore_const(ptr + 0x80, self.scalar_modulus - U256::from(2));
        self.emit_mstore_const(ptr + 0xa0, self.scalar_modulus);
        *self.invert_modexp_input_ptr.borrow_mut() = Some(ptr);
        ptr
    }

    fn invert(self: &Rc<Self>, scalar: &Scalar) -> Scalar {
        let rd_ptr = self.allocate(0x20);
        let cd_ptr = self.inversion_modexp_input_ptr();
        self.copy_scalar(scalar, cd_ptr + 0x60);
        self.staticcall_sized(Precompiled::BigModExp as usize, cd_ptr, 0xc0, rd_ptr, 0x20);
        self.scalar(Value::Memory(rd_ptr))
    }

    fn ec_point_scalar_mul(self: &Rc<Self>, ec_point: &EcPoint, scalar: &Scalar) -> EcPoint {
        let rd_ptr = self.dup_ec_point(ec_point).ptr();
        self.dup_scalar(scalar);
        self.staticcall(Precompiled::Bls12_381G1Msm, rd_ptr, rd_ptr);
        self.ec_point(Value::Memory(rd_ptr))
    }

    fn ec_point_multi_scalar_mul(self: &Rc<Self>, pairs: &[(&Scalar, &EcPoint)]) -> EcPoint {
        assert!(!pairs.is_empty(), "pairs should not be empty");

        // Preserve tiny-case behavior for compatibility and avoid oversized precompile calldata.
        if pairs.len() == 1 {
            let (scalar, ec_point) = pairs[0];
            return match scalar.value {
                Value::Constant(constant) if U256::from(1) == constant => ec_point.clone(),
                _ => self.ec_point_scalar_mul(ec_point, scalar),
            };
        }

        // Pack all (point, scalar) pairs contiguously and call G1MSM once.
        let pair_bytes = BLS_G1_BYTES + 0x20;
        let cd_len = pairs.len().checked_mul(pair_bytes).expect("MSM calldata length overflow");
        let cd_ptr = self.ptr();
        for (scalar, ec_point) in pairs.iter().copied() {
            self.dup_ec_point(ec_point);
            self.dup_scalar(scalar);
        }
        let rd_ptr = self.allocate(BLS_G1_BYTES);
        self.staticcall_sized(
            Precompiled::Bls12_381G1Msm as usize,
            cd_ptr,
            cd_len,
            rd_ptr,
            BLS_G1_BYTES,
        );
        self.ec_point(Value::Memory(rd_ptr))
    }

    /// Performs pairing.
    pub fn pairing(
        self: &Rc<Self>,
        lhs: &EcPoint,
        g2: &[U256],
        rhs: &EcPoint,
        minus_s_g2: &[U256],
    ) {
        assert_eq!(g2.len(), BLS_G2_BYTES / 0x20, "g2 must contain exactly 8 words (256 bytes)");
        assert_eq!(
            minus_s_g2.len(),
            BLS_G2_BYTES / 0x20,
            "minus_s_g2 must contain exactly 8 words (256 bytes)"
        );

        let rd_ptr = self.dup_ec_point(lhs).ptr();
        self.allocate(BLS_G2_BYTES);
        for (idx, word) in g2.iter().enumerate() {
            self.emit_mstore_const(rd_ptr + BLS_G1_BYTES + idx * 0x20, *word);
        }

        self.dup_ec_point(rhs);
        self.allocate(BLS_G2_BYTES);
        for (idx, word) in minus_s_g2.iter().enumerate() {
            self.emit_mstore_const(
                rd_ptr + (BLS_G1_BYTES + BLS_G2_BYTES) + BLS_G1_BYTES + idx * 0x20,
                *word,
            );
        }

        self.staticcall(Precompiled::Bls12_381Pairing, rd_ptr, rd_ptr);
        let code = format!("success := and(eq(mload({rd_ptr:#x}), 1), success)");
        self.code.borrow_mut().runtime_append(code);
    }

    fn add(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if let (Value::Constant(lhs), Value::Constant(rhs)) = (&lhs.value, &rhs.value) {
            let out = (U512::from(*lhs) + U512::from(*rhs)) % U512::from(self.scalar_modulus);
            return self.scalar(Value::Constant(U256::from(out)));
        }

        self.scalar(Value::Sum(Box::new(lhs.value.clone()), Box::new(rhs.value.clone())))
    }

    fn sub(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if rhs.is_const() {
            return self.add(lhs, &self.neg(rhs));
        }

        self.scalar(Value::Sum(
            Box::new(lhs.value.clone()),
            Box::new(Value::Negated(Box::new(rhs.value.clone()))),
        ))
    }

    fn mul(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if let (Value::Constant(lhs), Value::Constant(rhs)) = (&lhs.value, &rhs.value) {
            let out = (U512::from(*lhs) * U512::from(*rhs)) % U512::from(self.scalar_modulus);
            return self.scalar(Value::Constant(U256::from(out)));
        }

        self.scalar(Value::Product(Box::new(lhs.value.clone()), Box::new(rhs.value.clone())))
    }

    fn neg(self: &Rc<Self>, scalar: &Scalar) -> Scalar {
        if let Value::Constant(constant) = scalar.value {
            // Preserve exact zero to avoid wrapping `modulus - 0` into an invalid field representative.
            if constant == U256::ZERO {
                return self.scalar(Value::Constant(U256::ZERO));
            }
            return self.scalar(Value::Constant(self.scalar_modulus - constant));
        }

        self.scalar(Value::Negated(Box::new(scalar.value.clone())))
    }
}

#[cfg(test)]
impl EvmLoader {
    fn start_gas_metering(self: &Rc<Self>, _: &str) {
        //  unimplemented
    }

    fn end_gas_metering(self: &Rc<Self>) {
        //  unimplemented
    }

    #[allow(dead_code)]
    fn print_gas_metering(self: &Rc<Self>, _: Vec<u64>) {
        //  unimplemented
    }
}

/// Elliptic curve point.
#[derive(Clone)]
pub struct EcPoint {
    loader: Rc<EvmLoader>,
    value: Value<(U256, U256)>,
}

impl EcPoint {
    pub(crate) fn loader(&self) -> &Rc<EvmLoader> {
        &self.loader
    }

    pub(crate) fn value(&self) -> Value<(U256, U256)> {
        self.value.clone()
    }

    pub(crate) fn ptr(&self) -> usize {
        match self.value {
            Value::Memory(ptr) => ptr,
            _ => unreachable!(),
        }
    }
}

impl Debug for EcPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPoint").field("value", &self.value).finish()
    }
}

impl PartialEq for EcPoint {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<C> LoadedEcPoint<C> for EcPoint
where
    C: CurveAffine,
    C::ScalarExt: PrimeField<Repr = [u8; 0x20]>,
{
    type Loader = Rc<EvmLoader>;

    fn loader(&self) -> &Rc<EvmLoader> {
        &self.loader
    }
}

/// Field element.
#[derive(Clone)]
pub struct Scalar {
    loader: Rc<EvmLoader>,
    value: Value<U256>,
}

impl Scalar {
    pub(crate) fn loader(&self) -> &Rc<EvmLoader> {
        &self.loader
    }

    pub(crate) fn value(&self) -> Value<U256> {
        self.value.clone()
    }

    pub(crate) fn is_const(&self) -> bool {
        matches!(self.value, Value::Constant(_))
    }

    pub(crate) fn ptr(&self) -> usize {
        match self.value {
            Value::Memory(ptr) => ptr,
            _ => *self.loader.cache.borrow().get(&self.value.identifier()).unwrap(),
        }
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar").field("value", &self.value).finish()
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.loader.add(&self, &rhs)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.loader.sub(&self, &rhs)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        self.loader.mul(&self, &rhs)
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        self.loader.neg(&self)
    }
}

impl<'a> Add<&'a Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self {
        self.loader.add(&self, rhs)
    }
}

impl<'a> Sub<&'a Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self {
        self.loader.sub(&self, rhs)
    }
}

impl<'a> Mul<&'a Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &'a Self) -> Self {
        self.loader.mul(&self, rhs)
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.loader.add(self, &rhs);
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.loader.sub(self, &rhs);
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.loader.mul(self, &rhs);
    }
}

impl<'a> AddAssign<&'a Self> for Scalar {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = self.loader.add(self, rhs);
    }
}

impl<'a> SubAssign<&'a Self> for Scalar {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = self.loader.sub(self, rhs);
    }
}

impl<'a> MulAssign<&'a Self> for Scalar {
    fn mul_assign(&mut self, rhs: &'a Self) {
        *self = self.loader.mul(self, rhs);
    }
}

impl FieldOps for Scalar {
    fn invert(&self) -> Option<Scalar> {
        Some(self.loader.invert(self))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<F: PrimeField<Repr = [u8; 0x20]>> LoadedScalar<F> for Scalar {
    type Loader = Rc<EvmLoader>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }

    fn pow_var(&self, _exp: &Self, _exp_max_bits: usize) -> Self {
        todo!()
    }
}

impl<C> EcPointLoader<C> for Rc<EvmLoader>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    type LoadedEcPoint = EcPoint;

    fn ec_point_load_const(&self, value: &C) -> EcPoint {
        // Encode affine coordinates in EVM word layout, with identity mapped to (0,0).
        let [x_words, y_words] = match Option::<Coordinates<C>>::from(value.coordinates()) {
            Some(coordinates) => [coordinates.x(), coordinates.y()]
                .map(|coordinate| le_bytes_to_padded_be_words(coordinate.to_repr().as_ref())),
            // EVM precompiles encode point-at-infinity as (0, 0).
            None => [[U256::ZERO, U256::ZERO], [U256::ZERO, U256::ZERO]],
        };

        let ptr = self.allocate(BLS_G1_BYTES);
        self.emit_mstore_const(ptr, x_words[0]);
        self.emit_mstore_const(ptr + 0x20, x_words[1]);
        self.emit_mstore_const(ptr + BLS_ENCODED_FP_BYTES, y_words[0]);
        self.emit_mstore_const(ptr + BLS_ENCODED_FP_BYTES + 0x20, y_words[1]);
        self.ec_point(Value::Memory(ptr))
    }

    fn ec_point_assert_eq(&self, _: &str, _: &EcPoint, _: &EcPoint) {
        unimplemented!()
    }

    fn multi_scalar_multiplication(
        pairs: &[(&<Self as ScalarLoader<C::Scalar>>::LoadedScalar, &EcPoint)],
    ) -> EcPoint {
        // Route all MSM calls through the batched G1MSM precompile helper.
        pairs.first().expect("pairs should not be empty").1.loader.ec_point_multi_scalar_mul(pairs)
    }
}

impl<F: PrimeField<Repr = [u8; 0x20]>> ScalarLoader<F> for Rc<EvmLoader> {
    type LoadedScalar = Scalar;

    fn load_const(&self, value: &F) -> Scalar {
        self.scalar(Value::Constant(fe_to_u256(*value)))
    }

    fn assert_eq(&self, _: &str, _: &Scalar, _: &Scalar) {
        unimplemented!()
    }

    fn sum_with_coeff_and_const(&self, values: &[(F, &Scalar)], constant: F) -> Scalar {
        if values.is_empty() {
            return self.load_const(&constant);
        }

        let push_addend = |(coeff, value): &(F, &Scalar)| {
            assert_ne!(*coeff, F::ZERO);
            match (*coeff == F::ONE, &value.value) {
                (true, _) => self.push(value),
                (false, Value::Constant(value)) => self.push(
                    &self.scalar(Value::Constant(fe_to_u256(*coeff * u256_to_fe::<F>(*value)))),
                ),
                (false, _) => {
                    let value = self.push(value);
                    let coeff = self.push(&self.scalar(Value::Constant(fe_to_u256(*coeff))));
                    format!("mulmod({value}, {coeff}, f_q)")
                }
            }
        };

        let mut values = values.iter();
        let initial_value = if constant == F::ZERO {
            push_addend(values.next().unwrap())
        } else {
            self.push(&self.scalar(Value::Constant(fe_to_u256(constant))))
        };

        let mut code = format!("let result := {initial_value}\n");
        for value in values {
            let v = push_addend(value);
            let addend = format!("result := addmod({v}, result, f_q)\n");
            code.push_str(addend.as_str());
        }

        let ptr = self.allocate(0x20);
        code.push_str(format!("mstore({ptr}, result)").as_str());
        self.code.borrow_mut().runtime_append(format!(
            "{{
            {code}
        }}"
        ));

        self.scalar(Value::Memory(ptr))
    }

    fn sum_products_with_coeff_and_const(
        &self,
        values: &[(F, &Scalar, &Scalar)],
        constant: F,
    ) -> Scalar {
        if values.is_empty() {
            return self.load_const(&constant);
        }

        let push_addend = |(coeff, lhs, rhs): &(F, &Scalar, &Scalar)| {
            assert_ne!(*coeff, F::ZERO);
            match (*coeff == F::ONE, &lhs.value, &rhs.value) {
                (_, Value::Constant(lhs), Value::Constant(rhs)) => {
                    self.push(&self.scalar(Value::Constant(fe_to_u256(
                        *coeff * u256_to_fe::<F>(*lhs) * u256_to_fe::<F>(*rhs),
                    ))))
                }
                (_, value @ Value::Memory(_), Value::Constant(constant))
                | (_, Value::Constant(constant), value @ Value::Memory(_)) => {
                    let v1 = self.push(&self.scalar(value.clone()));
                    let v2 =
                        self.push(&self.scalar(Value::Constant(fe_to_u256(
                            *coeff * u256_to_fe::<F>(*constant),
                        ))));
                    format!("mulmod({v1}, {v2}, f_q)")
                }
                (true, _, _) => {
                    let rhs = self.push(rhs);
                    let lhs = self.push(lhs);
                    format!("mulmod({rhs}, {lhs}, f_q)")
                }
                (false, _, _) => {
                    let rhs = self.push(rhs);
                    let lhs = self.push(lhs);
                    let value = self.push(&self.scalar(Value::Constant(fe_to_u256(*coeff))));
                    format!("mulmod({rhs}, mulmod({lhs}, {value}, f_q), f_q)")
                }
            }
        };

        let mut values = values.iter();
        let initial_value = if constant == F::ZERO {
            push_addend(values.next().unwrap())
        } else {
            self.push(&self.scalar(Value::Constant(fe_to_u256(constant))))
        };

        let mut code = format!("let result := {initial_value}\n");
        for value in values {
            let v = push_addend(value);
            let addend = format!("result := addmod({v}, result, f_q)\n");
            code.push_str(addend.as_str());
        }

        let ptr = self.allocate(0x20);
        code.push_str(format!("mstore({ptr}, result)").as_str());
        self.code.borrow_mut().runtime_append(format!(
            "{{
            {code}
        }}"
        ));

        self.scalar(Value::Memory(ptr))
    }

    // batch_invert algorithm
    // n := values.len() - 1
    // input : values[0], ..., values[n]
    // output : values[0]^{-1}, ..., values[n]^{-1}
    // 1. products[i] <- values[0] * ... * values[i], i = 1, ..., n
    // 2. inv <- (products[n])^{-1}
    // 3. v_n <- values[n]
    // 4. values[n] <- products[n - 1] * inv (values[n]^{-1})
    // 5. inv <- v_n * inv
    fn batch_invert<'a>(values: impl IntoIterator<Item = &'a mut Scalar>) {
        let mut values = values.into_iter().collect_vec();
        // No work for empty batches.
        if values.is_empty() {
            return;
        }

        let loader = &values.first().unwrap().loader;
        // Always use the zero-safe fast path for deterministic Midnight EVM behavior.

        // Snapshot inputs into dedicated memory so repeated pointers do not get clobbered
        // by reverse writes in the batch inversion schedule.
        let inputs = values.iter().map(|value| loader.dup_scalar(value)).collect_vec();
        let products = iter::repeat_with(|| loader.allocate(0x20))
            .map(|ptr| loader.scalar(Value::Memory(ptr)))
            .take(inputs.len())
            .collect_vec();
        let outputs = iter::repeat_with(|| loader.allocate(0x20))
            .map(|ptr| loader.scalar(Value::Memory(ptr)))
            .take(inputs.len())
            .collect_vec();

        let first = loader.push(&inputs[0]);
        let first_ptr = products[0].ptr();
        let mut code = format!(
            "
            let v := {first}
            // Replace zero inputs with one while building products; zeros are restored later.
            let isz := iszero(mod(v, f_q))
            let masked := add(v, isz)
            let prod := masked
            mstore({first_ptr:#x}, prod)
        "
        );
        for idx in 1..inputs.len() {
            let v = loader.push(&inputs[idx]);
            let ptr = products[idx].ptr();
            code.push_str(
                format!(
                    "
                    v := {v}
                    isz := iszero(mod(v, f_q))
                    masked := add(v, isz)
                    prod := mulmod(masked, prod, f_q)
                    mstore({ptr:#x}, prod)
                "
                )
                .as_str(),
            );
        }
        loader.code.borrow_mut().runtime_append(format!(
            "{{
            {code}
        }}"
        ));

        let inv = loader.push(&loader.invert(products.last().unwrap()));

        let mut code = format!(
            "
            let inv := {inv}
            let v
            let isz
            let masked
        "
        );
        // Reverse pass writes each inverse, masking zeros back to zero via (1 - isz).
        for idx in (1..inputs.len()).rev() {
            let out_ptr = outputs[idx].ptr();
            let prod_ptr = products[idx - 1].ptr();
            let v = loader.push(&inputs[idx]);
            code.push_str(
                format!(
                    "
                    v := {v}
                    isz := iszero(mod(v, f_q))
                    masked := add(v, isz)
                    mstore({out_ptr:#x}, mulmod(mulmod(mload({prod_ptr:#x}), inv, f_q), sub(1, isz), f_q))
                    inv := mulmod(masked, inv, f_q)
                "
                )
                .as_str(),
            );
        }
        // Final element uses the remaining accumulator inverse.
        let out_ptr = outputs[0].ptr();
        let v = loader.push(&inputs[0]);
        code.push_str(
            format!(
                "
                v := {v}
                isz := iszero(mod(v, f_q))
                mstore({out_ptr:#x}, mulmod(inv, sub(1, isz), f_q))
            "
            )
            .as_str(),
        );
        loader.code.borrow_mut().runtime_append(format!(
            "{{
            {code}
        }}"
        ));

        // Publish outputs after assembly execution so aliased callers see final inverses only.
        for (value, output) in values.iter_mut().zip(outputs.into_iter()) {
            **value = output;
        }
    }
}

impl<C> Loader<C> for Rc<EvmLoader>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    #[cfg(test)]
    fn start_cost_metering(&self, identifier: &str) {
        self.start_gas_metering(identifier)
    }

    #[cfg(test)]
    fn end_cost_metering(&self) {
        self.end_gas_metering()
    }
}
