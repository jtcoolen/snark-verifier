//! Transcript for verifier on EVM.

use crate::halo2_proofs;
use crate::{
    loader::{
        evm::{loader::Value, u256_to_fe, util::MemoryChunk, EcPoint, EvmLoader, Scalar, U256},
        native::{self, NativeLoader},
        Loader,
    },
    util::{
        arithmetic::{Coordinates, CurveAffine, Field, PrimeField},
        hash::{Digest, Keccak256},
        transcript::{Transcript, TranscriptRead},
        Itertools,
    },
    Error,
};
use halo2_proofs::transcript::EncodedChallenge;
use std::{
    io::{self, Read, Write},
    iter,
    marker::PhantomData,
    rc::Rc,
};

/// Transcript for verifier on EVM using keccak256 as hasher.
#[derive(Debug)]
pub struct EvmTranscript<C: CurveAffine, L: Loader<C>, S, B> {
    loader: L,
    stream: S,
    buf: B,
    _marker: PhantomData<C>,
}

impl<C> EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    /// Initialize [`EvmTranscript`] given [`Rc<EvmLoader>`] and pre-allocate an
    /// u256 for `transcript_initial_state`.
    pub fn new(loader: &Rc<EvmLoader>) -> Self {
        let ptr = loader.allocate(0x20);
        let mut buf = MemoryChunk::new(ptr);
        buf.extend(0x20);
        Self { loader: loader.clone(), stream: 0, buf, _marker: PhantomData }
    }

    /// Load `num_instance` instances from calldata to memory.
    pub fn load_instances(&mut self, num_instance: Vec<usize>) -> Vec<Vec<Scalar>> {
        let instances = num_instance
            .into_iter()
            .map(|len| {
                iter::repeat_with(|| {
                    let scalar = self.loader.calldataload_scalar(self.stream);
                    self.stream += 0x20;
                    scalar
                })
                .take(len)
                .collect_vec()
            })
            .collect();

        // Keep transcript bytes in a dedicated contiguous region after
        // preloaded calldata values.
        if self.buf.end() != self.loader.ptr() {
            let ptr = self.loader.allocate(0x20);
            self.buf.reset(ptr);
            self.buf.extend(0x20);
        }

        instances
    }
}

impl<C> Transcript<C, Rc<EvmLoader>> for EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn loader(&self) -> &Rc<EvmLoader> {
        &self.loader
    }

    /// Does not allow the input to be a one-byte sequence, because the Transcript trait only supports writing scalars and elliptic curve points.
    /// If the one-byte sequence `[0x01]` is a valid input to the transcript, the empty input `[]` will have the same transcript result as `[0x01]`.
    fn squeeze_challenge(&mut self) -> Scalar {
        let len = if self.buf.len() == 0x20 {
            assert_eq!(self.loader.ptr(), self.buf.end());
            let buf_end = self.buf.end();
            let code = format!("mstore8({buf_end}, 1)");
            self.loader.code_mut().runtime_append(code);
            0x21
        } else {
            self.buf.len()
        };
        let hash_ptr = self.loader.keccak256(self.buf.ptr(), len);

        let challenge_ptr = self.loader.allocate(0x20);
        let dup_hash_ptr = self.loader.allocate(0x20);
        let code = format!(
            "{{
            let hash := mload({hash_ptr:#x})
            mstore({challenge_ptr:#x}, mod(hash, f_q))
            mstore({dup_hash_ptr:#x}, hash)
        }}"
        );
        self.loader.code_mut().runtime_append(code);

        self.buf.reset(dup_hash_ptr);
        self.buf.extend(0x20);

        self.loader.scalar(Value::Memory(challenge_ptr))
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint) -> Result<(), Error> {
        if let Value::Memory(ptr) = ec_point.value() {
            if self.buf.end() == ptr {
                self.buf.extend(self.loader.evm_ec_point_bytes());
            } else {
                // Re-copy into the contiguous transcript buffer when source memory is disjoint.
                let dst = self.loader.dup_ec_point(ec_point);
                if let Value::Memory(dst_ptr) = dst.value() {
                    assert_eq!(self.buf.end(), dst_ptr);
                    self.buf.extend(self.loader.evm_ec_point_bytes());
                } else {
                    unreachable!()
                }
            }
        } else {
            unreachable!()
        }
        Ok(())
    }

    fn common_scalar(&mut self, scalar: &Scalar) -> Result<(), Error> {
        match scalar.value() {
            Value::Constant(_) if self.buf.len() == 0x20 => {
                self.loader.copy_scalar(scalar, self.buf.ptr());
            }
            Value::Constant(_) => {
                let ptr = self.loader.allocate(0x20);
                assert_eq!(self.buf.end(), ptr);
                self.loader.copy_scalar(scalar, ptr);
                self.buf.extend(0x20);
            }
            Value::Memory(ptr) => {
                if self.buf.end() == ptr {
                    self.buf.extend(0x20);
                } else {
                    // Re-copy into the contiguous transcript buffer when source memory is disjoint.
                    let dst = self.loader.allocate(0x20);
                    assert_eq!(self.buf.end(), dst);
                    self.loader
                        .code_mut()
                        .runtime_append(format!("mstore({dst:#x}, mload({ptr:#x}))"));
                    self.buf.extend(0x20);
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl<C> TranscriptRead<C, Rc<EvmLoader>> for EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn read_scalar(&mut self) -> Result<Scalar, Error> {
        let scalar = self.loader.calldataload_scalar(self.stream);
        self.stream += 0x20;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint, Error> {
        let ec_point = self.loader.calldataload_ec_point(self.stream);
        self.stream += self.loader.proof_ec_point_bytes();
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C, S> EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
{
    /// Initialize [`EvmTranscript`] given readable or writeable stream for
    /// verifying or proving with [`NativeLoader`].
    pub fn new(stream: S) -> Self {
        Self { loader: NativeLoader, stream, buf: Vec::new(), _marker: PhantomData }
    }
}

impl<C, S> Transcript<C, NativeLoader> for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn loader(&self) -> &NativeLoader {
        &native::LOADER
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        let data = self
            .buf
            .iter()
            .cloned()
            .chain(if self.buf.len() == 0x20 { Some(1) } else { None })
            .collect_vec();
        let hash: [u8; 32] = Keccak256::digest(data).into();
        self.buf = hash.to_vec();
        u256_to_fe(U256::from_be_bytes(hash))
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        // Encode finite points as padded big-endian coordinates matching EVM calldata layout.
        if let Some(coordinates) = Option::<Coordinates<C>>::from(ec_point.coordinates()) {
            [coordinates.x(), coordinates.y()].map(|coordinate| {
                let repr = coordinate.to_repr();
                let repr = repr.as_ref();
                let encoded_len = match repr.len() {
                    0..=0x20 => 0x20,
                    0x21..=0x40 => 0x40,
                    _ => unreachable!("unsupported base-field encoding length: {}", repr.len()),
                };
                self.buf.extend(iter::repeat(0).take(encoded_len - repr.len()));
                self.buf.extend(repr.iter().rev().copied());
            });
        } else {
            // EVM precompiles represent point-at-infinity as (0, 0).
            let repr_len = <C::Base as PrimeField>::Repr::default().as_ref().len();
            let encoded_len = match repr_len {
                0..=0x20 => 0x20,
                0x21..=0x40 => 0x40,
                _ => unreachable!("unsupported base-field encoding length: {}", repr_len),
            };
            self.buf.extend(iter::repeat(0).take(2 * encoded_len));
        }

        Ok(())
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        self.buf.extend(scalar.to_repr().as_ref().iter().rev());

        Ok(())
    }
}

impl<C, S> TranscriptRead<C, NativeLoader> for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
    S: Read,
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        let mut data = [0; 32];
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        data.reverse();
        let scalar = C::Scalar::from_repr_vartime(data).ok_or_else(|| {
            Error::Transcript(io::ErrorKind::Other, "Invalid scalar encoding in proof".to_string())
        })?;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<C, Error> {
        let [mut x, mut y] = [<C::Base as PrimeField>::Repr::default(); 2];
        for repr in [&mut x, &mut y] {
            self.stream
                .read_exact(repr.as_mut())
                .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
            repr.as_mut().reverse();
        }
        let x = Option::from(<C::Base as PrimeField>::from_repr(x)).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid x-coordinate encoding in proof".to_string(),
            )
        })?;
        let y = Option::from(<C::Base as PrimeField>::from_repr(y)).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid y-coordinate encoding in proof".to_string(),
            )
        })?;
        // EVM precompiles represent point-at-infinity as (0, 0).
        // Translate the sentinel back into the curve identity before transcript absorption.
        let ec_point = if x == C::Base::ZERO && y == C::Base::ZERO {
            C::identity()
        } else {
            Option::from(C::from_xy(x, y)).ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point encoding in proof".to_string(),
                )
            })?
        };
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C, S> EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    S: Write,
{
    /// Returns mutable `stream`.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Finalize transcript and returns `stream`.
    pub fn finalize(self) -> S {
        self.stream
    }
}

/// [`EncodedChallenge`] implemented for verifier on EVM, which use input in
/// big-endian as the challenge.
#[derive(Debug)]
pub struct ChallengeEvm<C>(C::Scalar)
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>;

impl<C> EncodedChallenge<C> for ChallengeEvm<C>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    type Input = [u8; 32];

    fn new(challenge_input: &[u8; 32]) -> Self {
        ChallengeEvm(u256_to_fe(U256::from_be_bytes(*challenge_input)))
    }

    fn get_scalar(&self) -> C::Scalar {
        self.0
    }
}

impl<C, S> halo2_proofs::transcript::Transcript<C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn squeeze_challenge(&mut self) -> ChallengeEvm<C> {
        ChallengeEvm(Transcript::squeeze_challenge(self))
    }

    fn common_point(&mut self, ec_point: C) -> io::Result<()> {
        match Transcript::common_ec_point(self, &ec_point) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        match Transcript::common_scalar(self, &scalar) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }
}

impl<C, R: Read> halo2_proofs::transcript::TranscriptRead<C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, R, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn read_point(&mut self) -> io::Result<C> {
        match TranscriptRead::read_ec_point(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value),
        }
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        match TranscriptRead::read_scalar(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value),
        }
    }
}

impl<C, R: Read> halo2_proofs::transcript::TranscriptReadBuffer<R, C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, R, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn init(reader: R) -> Self {
        Self::new(reader)
    }
}

impl<C, W: Write> halo2_proofs::transcript::TranscriptWrite<C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, W, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn write_point(&mut self, ec_point: C) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeEvm<C>>::common_point(self, ec_point)?;
        let coords: Coordinates<C> = Option::from(ec_point.coordinates()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Cannot write points at infinity to the transcript",
            )
        })?;
        let mut x = coords.x().to_repr();
        let mut y = coords.y().to_repr();
        x.as_mut().reverse();
        y.as_mut().reverse();
        self.stream_mut().write_all(x.as_ref())?;
        self.stream_mut().write_all(y.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeEvm<C>>::common_scalar(self, scalar)?;
        let mut data = scalar.to_repr();
        data.as_mut().reverse();
        self.stream_mut().write_all(data.as_ref())
    }
}

impl<C, W: Write> halo2_proofs::transcript::TranscriptWriterBuffer<W, C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, W, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn init(writer: W) -> Self {
        Self::new(writer)
    }

    fn finalize(self) -> W {
        self.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        halo2_proofs::halo2curves::bls12_381::{Fq, Fr, G1Affine},
        loader::evm::fe_to_u256,
        loader::EcPointLoader,
    };
    #[cfg(feature = "revm")]
    use crate::{
        loader::evm::{compile_solidity, deploy_unrolled_sharded_and_call, modulus, U256},
        util::hash::{Digest, Keccak256},
    };

    #[cfg(feature = "revm")]
    fn deploy_and_call_with_output(deployment_code: Vec<u8>, calldata: Vec<u8>) -> Vec<u8> {
        use revm::{
            context::TxEnv,
            context_interface::result::{ExecutionResult, Output},
            database::InMemoryDB,
            primitives::{hardfork::SpecId, Bytes, TxKind},
            Context, ExecuteCommitEvm, MainBuilder, MainContext,
        };

        const GAS_LIMIT: u64 = 1_000_000_000;

        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| {
                cfg.spec = SpecId::PRAGUE;
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_nonce_check = true;
                cfg.tx_gas_limit_cap = Some(GAS_LIMIT);
            })
            .with_db(InMemoryDB::default())
            .build_mainnet();

        let deployment_tx = TxEnv::builder()
            .gas_limit(GAS_LIMIT)
            .kind(TxKind::Create)
            .data(Bytes::from(deployment_code))
            .build_fill();
        let deployment_result =
            evm.transact_commit(deployment_tx).expect("revm deployment transaction failed");
        let contract = match deployment_result {
            ExecutionResult::Success { output: Output::Create(_, Some(contract)), .. } => contract,
            ExecutionResult::Success { output, .. } => {
                panic!("unexpected deployment output: {output:?}")
            }
            ExecutionResult::Revert { output, .. } => {
                panic!("deployment reverted: 0x{}", hex::encode(output))
            }
            ExecutionResult::Halt { reason, .. } => panic!("deployment halted: {reason:?}"),
        };

        let call_tx = TxEnv::builder()
            .gas_limit(GAS_LIMIT)
            .kind(TxKind::Call(contract))
            .data(Bytes::from(calldata))
            .build_fill();
        let call_result = evm.transact_commit(call_tx).expect("revm call transaction failed");
        match call_result {
            ExecutionResult::Success { output: Output::Call(output), .. } => output.to_vec(),
            ExecutionResult::Success { output, .. } => panic!("unexpected call output: {output:?}"),
            ExecutionResult::Revert { output, .. } => {
                panic!("call reverted: 0x{}", hex::encode(output))
            }
            ExecutionResult::Halt { reason, .. } => panic!("call halted: {reason:?}"),
        }
    }

    #[cfg(feature = "revm")]
    fn abi_word(output: &[u8], index: usize) -> &[u8] {
        let start = index * 32;
        &output[start..start + 32]
    }

    #[cfg(feature = "revm")]
    fn abi_word_to_usize(word: &[u8]) -> usize {
        assert!(word[..24].iter().all(|byte| *byte == 0), "expected usize-sized ABI word");
        u64::from_be_bytes(word[24..32].try_into().unwrap()) as usize
    }

    #[cfg(feature = "revm")]
    fn u256_hex(value: U256) -> String {
        format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
    }

    #[test]
    fn read_ec_point_decodes_zero_zero_as_identity() {
        let coord_len =
            std::mem::size_of::<<<G1Affine as CurveAffine>::Base as PrimeField>::Repr>();
        let input = vec![0u8; 2 * coord_len];
        let mut transcript = EvmTranscript::<G1Affine, NativeLoader, _, _>::new(input.as_slice());
        let point = TranscriptRead::read_ec_point(&mut transcript).unwrap();
        assert_eq!(point, G1Affine::identity());
    }

    #[test]
    fn common_ec_point_encodes_identity_as_padded_zero_words() {
        let mut transcript = EvmTranscript::<G1Affine, NativeLoader, _, _>::new(());
        Transcript::common_ec_point(&mut transcript, &G1Affine::identity()).unwrap();

        let repr_len = std::mem::size_of::<<<G1Affine as CurveAffine>::Base as PrimeField>::Repr>();
        let encoded_len = match repr_len {
            0..=0x20 => 0x20,
            0x21..=0x40 => 0x40,
            _ => panic!("unexpected base-field encoding length: {repr_len}"),
        };
        assert_eq!(transcript.buf.len(), 2 * encoded_len);
        assert!(transcript.buf.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sharded_transcript_ir_contains_expected_equivalence_checks() {
        let scalar_0 = Fr::from(7u64);
        let scalar_1 = Fr::from(42u64);

        let mut rust_transcript = EvmTranscript::<G1Affine, NativeLoader, _, _>::new(());
        Transcript::common_scalar(&mut rust_transcript, &scalar_0).unwrap();
        let expected_challenge_0 = fe_to_u256(Transcript::squeeze_challenge(&mut rust_transcript));
        Transcript::common_ec_point(&mut rust_transcript, &G1Affine::identity()).unwrap();
        Transcript::common_scalar(&mut rust_transcript, &scalar_1).unwrap();
        let expected_challenge_1 = fe_to_u256(Transcript::squeeze_challenge(&mut rust_transcript));

        let expected_challenge_0_hex =
            format!("0x{}", hex::encode(expected_challenge_0.to_be_bytes::<32>()));
        let expected_challenge_1_hex =
            format!("0x{}", hex::encode(expected_challenge_1.to_be_bytes::<32>()));

        let loader = EvmLoader::new::<Fq, Fr>();
        let mut evm_transcript = EvmTranscript::<G1Affine, Rc<EvmLoader>, _, _>::new(&loader);
        let scalar_0_loaded = loader.scalar(Value::Constant(fe_to_u256(scalar_0)));
        Transcript::common_scalar(&mut evm_transcript, &scalar_0_loaded).unwrap();
        let challenge_0 = Transcript::squeeze_challenge(&mut evm_transcript);
        let identity = loader.ec_point_load_const(&G1Affine::identity());
        Transcript::common_ec_point(&mut evm_transcript, &identity).unwrap();
        let scalar_1_loaded = loader.scalar(Value::Constant(fe_to_u256(scalar_1)));
        Transcript::common_scalar(&mut evm_transcript, &scalar_1_loaded).unwrap();
        let challenge_1 = Transcript::squeeze_challenge(&mut evm_transcript);

        let challenge_0_ptr = challenge_0.ptr();
        let challenge_1_ptr = challenge_1.ptr();
        loader.code_mut().runtime_append(format!(
            "
            if iszero(eq(mload({challenge_0_ptr:#x}), {expected_challenge_0_hex})) {{ success := 0 }}
            if iszero(eq(mload({challenge_1_ptr:#x}), {expected_challenge_1_hex})) {{ success := 0 }}
            "
        ));

        {
            let code = loader.code_mut();
            let runtime_blocks = code.runtime_blocks();
            assert!(runtime_blocks.iter().any(|block| block.contains("mstore8(")));
            assert!(runtime_blocks.iter().any(|block| block.contains("mod(hash, f_q)")));
            assert!(runtime_blocks
                .iter()
                .any(|block| block.contains(&format!("mload({challenge_0_ptr:#x})"))));
            assert!(runtime_blocks
                .iter()
                .any(|block| block.contains(&format!("mload({challenge_1_ptr:#x})"))));
        }

        let artifacts = loader.unrolled_sharded_verifier_artifacts();
        assert!(
            artifacts.dispatcher_solidity.contains("delegatecall"),
            "dispatcher should delegatecall shard contracts"
        );
        assert!(
            !artifacts.shard_solidity_sources.is_empty(),
            "sharded generation should produce at least one shard source"
        );
        let shard_sources = artifacts.shard_solidity_sources.join("\n");
        assert!(shard_sources.contains(&expected_challenge_0_hex));
        assert!(shard_sources.contains(&expected_challenge_1_hex));
    }

    #[cfg(feature = "revm")]
    #[test]
    fn rust_and_solidity_transcript_traces_match_per_operation() {
        const SOLIDITY: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract TranscriptTraceHarness {
    function trace(bytes32 scalar0, bytes32 scalar1, uint256 f_q)
        external
        pure
        returns (
            uint256[5] memory lens,
            bytes32[5] memory digests,
            bytes32[2] memory hashes,
            uint256[2] memory challenges
        )
    {
        bytes memory buf = abi.encodePacked(scalar0);
        lens[0] = buf.length;
        digests[0] = keccak256(buf);

        bytes memory squeezeInput = buf.length == 32 ? bytes.concat(buf, hex"01") : buf;
        bytes32 hash0 = keccak256(squeezeInput);
        hashes[0] = hash0;
        challenges[0] = uint256(hash0) % f_q;
        buf = abi.encodePacked(hash0);
        lens[1] = buf.length;
        digests[1] = keccak256(buf);

        buf = bytes.concat(buf, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
        lens[2] = buf.length;
        digests[2] = keccak256(buf);

        buf = bytes.concat(buf, scalar1);
        lens[3] = buf.length;
        digests[3] = keccak256(buf);

        squeezeInput = buf.length == 32 ? bytes.concat(buf, hex"01") : buf;
        bytes32 hash1 = keccak256(squeezeInput);
        hashes[1] = hash1;
        challenges[1] = uint256(hash1) % f_q;
        buf = abi.encodePacked(hash1);
        lens[4] = buf.length;
        digests[4] = keccak256(buf);
    }
}
"#;

        let scalar_0 = Fr::from(7u64);
        let scalar_1 = Fr::from(42u64);

        let mut rust_transcript = EvmTranscript::<G1Affine, NativeLoader, _, _>::new(());
        let mut rust_lens = Vec::new();
        let mut rust_digests = Vec::new();
        let mut rust_hashes = Vec::new();
        let mut rust_challenges = Vec::new();

        Transcript::common_scalar(&mut rust_transcript, &scalar_0).unwrap();
        rust_lens.push(rust_transcript.buf.len());
        rust_digests.push(<[u8; 32]>::from(Keccak256::digest(rust_transcript.buf.as_slice())));

        let challenge_0 = Transcript::squeeze_challenge(&mut rust_transcript);
        rust_hashes.push(<[u8; 32]>::try_from(rust_transcript.buf.clone()).unwrap());
        rust_challenges.push(fe_to_u256(challenge_0));
        rust_lens.push(rust_transcript.buf.len());
        rust_digests.push(<[u8; 32]>::from(Keccak256::digest(rust_transcript.buf.as_slice())));

        Transcript::common_ec_point(&mut rust_transcript, &G1Affine::identity()).unwrap();
        rust_lens.push(rust_transcript.buf.len());
        rust_digests.push(<[u8; 32]>::from(Keccak256::digest(rust_transcript.buf.as_slice())));

        Transcript::common_scalar(&mut rust_transcript, &scalar_1).unwrap();
        rust_lens.push(rust_transcript.buf.len());
        rust_digests.push(<[u8; 32]>::from(Keccak256::digest(rust_transcript.buf.as_slice())));

        let challenge_1 = Transcript::squeeze_challenge(&mut rust_transcript);
        rust_hashes.push(<[u8; 32]>::try_from(rust_transcript.buf.clone()).unwrap());
        rust_challenges.push(fe_to_u256(challenge_1));
        rust_lens.push(rust_transcript.buf.len());
        rust_digests.push(<[u8; 32]>::from(Keccak256::digest(rust_transcript.buf.as_slice())));

        let deployment_code = compile_solidity(SOLIDITY);
        let selector = <[u8; 32]>::from(Keccak256::digest(b"trace(bytes32,bytes32,uint256)"));
        let mut calldata = Vec::with_capacity(4 + 32 * 3);
        calldata.extend_from_slice(&selector[..4]);

        let mut scalar_0_be = scalar_0.to_repr();
        scalar_0_be.as_mut().reverse();
        calldata.extend_from_slice(scalar_0_be.as_ref());

        let mut scalar_1_be = scalar_1.to_repr();
        scalar_1_be.as_mut().reverse();
        calldata.extend_from_slice(scalar_1_be.as_ref());

        calldata.extend_from_slice(&modulus::<Fr>().to_be_bytes::<32>());

        let output = deploy_and_call_with_output(deployment_code, calldata);
        assert_eq!(output.len(), 32 * 14, "unexpected ABI payload size");

        let solidity_lens =
            (0..5).map(|idx| abi_word_to_usize(abi_word(&output, idx))).collect::<Vec<_>>();
        let solidity_digests = (5..10)
            .map(|idx| <[u8; 32]>::try_from(abi_word(&output, idx)).unwrap())
            .collect::<Vec<_>>();
        let solidity_hashes = (10..12)
            .map(|idx| <[u8; 32]>::try_from(abi_word(&output, idx)).unwrap())
            .collect::<Vec<_>>();
        let solidity_challenges =
            (12..14).map(|idx| U256::from_be_slice(abi_word(&output, idx))).collect::<Vec<_>>();

        assert_eq!(solidity_lens, rust_lens, "buffer lengths diverged");
        assert_eq!(solidity_digests, rust_digests, "buffer digests diverged");
        assert_eq!(solidity_hashes, rust_hashes, "squeeze hashes diverged");
        assert_eq!(solidity_challenges, rust_challenges, "challenge reductions diverged");
    }

    #[cfg(feature = "revm")]
    #[test]
    fn sharded_contract_transcript_matches_rust_transcript() {
        let scalar_0 = Fr::from(7u64);
        let scalar_1 = Fr::from(42u64);

        let mut rust_transcript = EvmTranscript::<G1Affine, NativeLoader, _, _>::new(());
        Transcript::common_scalar(&mut rust_transcript, &scalar_0).unwrap();
        let expected_challenge_0 = fe_to_u256(Transcript::squeeze_challenge(&mut rust_transcript));
        Transcript::common_ec_point(&mut rust_transcript, &G1Affine::identity()).unwrap();
        Transcript::common_scalar(&mut rust_transcript, &scalar_1).unwrap();
        let expected_challenge_1 = fe_to_u256(Transcript::squeeze_challenge(&mut rust_transcript));

        let loader = EvmLoader::new::<Fq, Fr>();
        let mut evm_transcript = EvmTranscript::<G1Affine, Rc<EvmLoader>, _, _>::new(&loader);
        let scalar_0_loaded = loader.scalar(Value::Constant(fe_to_u256(scalar_0)));
        Transcript::common_scalar(&mut evm_transcript, &scalar_0_loaded).unwrap();
        let challenge_0 = Transcript::squeeze_challenge(&mut evm_transcript);
        let identity = loader.ec_point_load_const(&G1Affine::identity());
        Transcript::common_ec_point(&mut evm_transcript, &identity).unwrap();
        let scalar_1_loaded = loader.scalar(Value::Constant(fe_to_u256(scalar_1)));
        Transcript::common_scalar(&mut evm_transcript, &scalar_1_loaded).unwrap();
        let challenge_1 = Transcript::squeeze_challenge(&mut evm_transcript);

        let challenge_0_ptr = challenge_0.ptr();
        let challenge_1_ptr = challenge_1.ptr();
        loader.code_mut().runtime_append(format!(
            "
            if iszero(eq(mload({challenge_0_ptr:#x}), {})) {{ success := 0 }}
            if iszero(eq(mload({challenge_1_ptr:#x}), {})) {{ success := 0 }}
            ",
            u256_hex(expected_challenge_0),
            u256_hex(expected_challenge_1),
        ));

        let artifacts = loader.unrolled_sharded_verifier_artifacts();
        deploy_unrolled_sharded_and_call(
            artifacts.shard_deployment_codes,
            artifacts.dispatcher_deployment_code,
            vec![],
        )
        .expect("sharded transcript contract should match rust transcript challenges");

        let loader_bad = EvmLoader::new::<Fq, Fr>();
        let mut evm_transcript_bad =
            EvmTranscript::<G1Affine, Rc<EvmLoader>, _, _>::new(&loader_bad);
        let scalar_0_loaded_bad = loader_bad.scalar(Value::Constant(fe_to_u256(scalar_0)));
        Transcript::common_scalar(&mut evm_transcript_bad, &scalar_0_loaded_bad).unwrap();
        let challenge_0_bad = Transcript::squeeze_challenge(&mut evm_transcript_bad);
        let identity_bad = loader_bad.ec_point_load_const(&G1Affine::identity());
        Transcript::common_ec_point(&mut evm_transcript_bad, &identity_bad).unwrap();
        let scalar_1_loaded_bad = loader_bad.scalar(Value::Constant(fe_to_u256(scalar_1)));
        Transcript::common_scalar(&mut evm_transcript_bad, &scalar_1_loaded_bad).unwrap();
        let challenge_1_bad = Transcript::squeeze_challenge(&mut evm_transcript_bad);
        loader_bad.code_mut().runtime_append(format!(
            "
            if iszero(eq(mload({:#x}), {})) {{ success := 0 }}
            if iszero(eq(mload({:#x}), {})) {{ success := 0 }}
            ",
            challenge_0_bad.ptr(),
            u256_hex(expected_challenge_0),
            challenge_1_bad.ptr(),
            u256_hex(expected_challenge_1 + U256::from(1u64)),
        ));
        let artifacts_bad = loader_bad.unrolled_sharded_verifier_artifacts();
        assert!(
            deploy_unrolled_sharded_and_call(
                artifacts_bad.shard_deployment_codes,
                artifacts_bad.dispatcher_deployment_code,
                vec![],
            )
            .is_err(),
            "wrong expected challenge should fail transcript-equivalence checks"
        );
    }
}
