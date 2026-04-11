#[cfg(feature = "revm")]
use anyhow::anyhow;
use anyhow::Result;
use halo2_base::halo2_proofs::halo2curves::bls12_381::{
    Fq as HaloFq, Fr as HaloFr, G1Affine as HaloG1Affine,
};
use itertools::Itertools;
use snark_verifier::{
    loader::{
        evm::{compile_solidity, encode_calldata, EvmLoader, UnrolledShardedVerifierArtifacts},
        EcPointLoader,
    },
    system::halo2::transcript::evm::EvmTranscript,
};
use std::rc::Rc;

use super::MidnightProofBundle;

impl MidnightProofBundle {
    /// Generate Solidity verifier source code for this Midnight proof protocol.
    ///
    /// The generated contract expects calldata encoded as: instances (32-byte
    /// big-endian words) followed by proof bytes produced in Midnight EVM transcript mode.
    pub fn generate_evm_verifier_solidity(&self) -> Result<String> {
        let loader = self.build_evm_verifier_loader()?;
        Ok(loader.solidity_code())
    }

    /// Generate deployment bytecode for the Midnight Solidity verifier.
    pub fn generate_evm_verifier_bytecode(&self) -> Result<Vec<u8>> {
        let solidity = self.generate_evm_verifier_solidity()?;
        Ok(compile_solidity(&solidity))
    }

    /// Generate unrolled-sharded verifier dispatcher + shard artifacts.
    pub fn generate_evm_verifier_unrolled_sharded_artifacts(
        &self,
    ) -> Result<UnrolledShardedVerifierArtifacts> {
        let loader = self.build_evm_verifier_loader()?;
        Ok(loader.unrolled_sharded_verifier_artifacts())
    }

    /// Encode calldata expected by the generated Solidity verifier.
    ///
    /// The proof bytes must be produced in Midnight EVM transcript mode.
    pub fn encode_evm_calldata(&self) -> Result<Vec<u8>> {
        let instances = self.full_instances_as_halo_fr()?;
        Ok(encode_calldata(&instances, &self.proof))
    }

    /// Deploy and call the generated verifier in local revm.
    ///
    /// Returns gas used by the verification call.
    #[cfg(feature = "revm")]
    pub fn verify_with_generated_solidity_revm(&self) -> Result<u64> {
        let bytecode = self.generate_evm_verifier_bytecode()?;
        let calldata = self.encode_evm_calldata()?;
        snark_verifier::loader::evm::deploy_and_call(bytecode, calldata)
            .map_err(|err| anyhow!("revm deployment/call failed: {err}"))
    }

    /// Deploy and call unrolled-sharded verifier/runtime shards in local revm.
    ///
    /// Returns gas used by the verification call.
    #[cfg(feature = "revm")]
    pub fn verify_with_generated_solidity_revm_unrolled_sharded(&self) -> Result<u64> {
        let sharded = self.generate_evm_verifier_unrolled_sharded_artifacts()?;
        let calldata = self.encode_evm_calldata()?;
        snark_verifier::loader::evm::deploy_unrolled_sharded_and_call(
            sharded.shard_deployment_codes,
            sharded.dispatcher_deployment_code,
            calldata,
        )
        .map_err(|err| anyhow!("revm unrolled-sharded deployment/call failed: {err}"))
    }

    // Build an EVM loader by replaying proof parsing/verification over EVM transcript semantics.
    fn build_evm_verifier_loader(&self) -> Result<Rc<EvmLoader>> {
        let protocol = self.to_snark_protocol()?;
        let num_instance = protocol.num_instance.clone();
        let dk = self.snark_deciding_key()?;

        let loader = EvmLoader::new::<HaloFq, HaloFr>();
        let protocol = protocol.loaded(&loader);
        let mut transcript = EvmTranscript::<HaloG1Affine, Rc<EvmLoader>, _, _>::new(&loader);

        // Load committed-instance constants into EVM memory only when present.
        let committed_instances = self
            .committed_instances_as_halo_points()?
            .iter()
            .map(|point| loader.ec_point_load_const(point))
            .collect_vec();
        let committed_instances = (!committed_instances.is_empty()).then_some(committed_instances);
        let instances = transcript.load_instances(num_instance);

        // Drive the verifier once so the loader accumulates all runtime code.
        Self::run_snark_verifier_flow(
            &dk,
            &protocol,
            &instances,
            committed_instances.as_deref(),
            &mut transcript,
            "failed to parse Midnight proof with EVM transcript",
            "failed to build EVM verifier for Midnight protocol",
        )?;

        Ok(loader)
    }
}

#[cfg(all(test, feature = "midnight", feature = "loader_evm", feature = "revm"))]
mod tests {
    use super::*;
    use crate::midnight_adapter::MidnightBundleOptions;
    use anyhow::{anyhow, Result};
    use ff::Field;
    use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
    use midnight_circuits::{
        hash::poseidon::PoseidonChip,
        instructions::{hash::HashCPU, AssignmentInstructions, PublicInputInstructions},
    };
    use midnight_curves::Bls12;
    use midnight_proofs::{
        circuit::{Layouter, Value},
        plonk::{Error, VerifierAlgebraicTrace},
        poly::{
            commitment::Guard,
            kzg::{params::ParamsKZG, KZGCommitmentScheme},
        },
        transcript::{
            CircuitTranscript, Hashable as MidnightHashable, Transcript as MidnightTranscript,
        },
    };
    use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};
    use rand::{rngs::OsRng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use sha3::Digest;
    use snark_verifier::{
        loader::{evm::U256, native::NativeLoader},
        pcs::kzg::LimbsEncoding,
        util::{
            arithmetic::{Coordinates, CurveAffine as SvCurveAffine},
            transcript::{Transcript as SvTranscript, TranscriptRead as SvTranscriptRead},
        },
        verifier::{plonk::PlonkProof, SnarkVerifier},
    };

    mod midnight_evm_transcript {
        use anyhow::{anyhow, Result};
        use ff::{Field, PrimeField};
        use midnight_curves::{
            CurveAffine as MidnightCurveAffine, Fp as MidnightFp, Fq, G1Affine as MidnightG1Affine,
            G1Projective,
        };
        use midnight_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
        use num_bigint::BigUint;
        use sha3::{Digest, Keccak256};
        use std::{
            io::{self, Read},
            sync::{Mutex, OnceLock},
        };

        const EVM_ENCODED_FP_BYTES: usize = 64;

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum TranscriptEvent {
            Absorb(Vec<u8>),
            Squeeze { hash: [u8; 32], challenge_be: [u8; 32] },
        }

        static TRACE_EVENTS: OnceLock<Mutex<Vec<TranscriptEvent>>> = OnceLock::new();

        fn trace_events() -> &'static Mutex<Vec<TranscriptEvent>> {
            TRACE_EVENTS.get_or_init(|| Mutex::new(Vec::new()))
        }

        fn push_trace_event(event: TranscriptEvent) {
            trace_events().lock().expect("trace mutex poisoned").push(event);
        }

        pub fn reset_trace_events() {
            trace_events().lock().expect("trace mutex poisoned").clear();
        }

        pub fn take_trace_events() -> Vec<TranscriptEvent> {
            std::mem::take(&mut *trace_events().lock().expect("trace mutex poisoned"))
        }

        #[derive(Clone, Debug, Default)]
        pub struct MidnightEvmHash {
            state: Vec<u8>,
        }

        impl TranscriptHash for MidnightEvmHash {
            type Input = Vec<u8>;
            type Output = Vec<u8>;

            fn init() -> Self {
                Self { state: Vec::new() }
            }

            fn absorb(&mut self, input: &Self::Input) {
                self.state.extend_from_slice(input);
            }

            fn squeeze(&mut self) -> Self::Output {
                let mut data = self.state.clone();
                if data.len() == 32 {
                    data.push(1);
                }
                let digest = Keccak256::digest(data);
                self.state = digest.to_vec();
                digest.to_vec()
            }
        }

        #[derive(Clone, Debug, Default)]
        pub struct TracingMidnightEvmHash {
            state: Vec<u8>,
        }

        impl TranscriptHash for TracingMidnightEvmHash {
            type Input = Vec<u8>;
            type Output = Vec<u8>;

            fn init() -> Self {
                Self { state: Vec::new() }
            }

            fn absorb(&mut self, input: &Self::Input) {
                push_trace_event(TranscriptEvent::Absorb(input.clone()));
                self.state.extend_from_slice(input);
            }

            fn squeeze(&mut self) -> Self::Output {
                let mut data = self.state.clone();
                if data.len() == 32 {
                    data.push(1);
                }
                let digest: [u8; 32] = Keccak256::digest(data).into();
                self.state = digest.to_vec();
                digest.to_vec()
            }
        }

        impl Hashable<MidnightEvmHash> for Fq {
            fn to_input(&self) -> Vec<u8> {
                scalar_to_evm_bytes(self)
            }

            fn to_bytes(&self) -> Vec<u8> {
                scalar_to_evm_bytes(self)
            }

            fn read(buffer: &mut impl Read) -> io::Result<Self> {
                let mut be = [0u8; 32];
                buffer.read_exact(&mut be)?;
                scalar_from_evm_bytes(&be)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
            }
        }

        impl Sampleable<MidnightEvmHash> for Fq {
            fn sample(hash_output: Vec<u8>) -> Self {
                assert_eq!(hash_output.len(), 32, "MidnightEvmHash outputs 32 bytes");
                let value = BigUint::from_bytes_be(&hash_output);
                let modulus =
                    BigUint::from_bytes_le((-Fq::ONE).to_repr().as_ref()) + BigUint::from(1u8);
                let reduced = value % modulus;
                let mut repr = <Fq as PrimeField>::Repr::default();
                let repr_len = repr.as_ref().len();
                let mut reduced_le = reduced.to_bytes_le();
                reduced_le.resize(repr_len, 0);
                repr.as_mut().copy_from_slice(&reduced_le[..repr_len]);
                Fq::from_repr(repr).unwrap()
            }
        }

        impl Sampleable<TracingMidnightEvmHash> for Fq {
            fn sample(hash_output: Vec<u8>) -> Self {
                assert_eq!(hash_output.len(), 32, "TracingMidnightEvmHash outputs 32 bytes");
                let hash =
                    <[u8; 32]>::try_from(hash_output.as_slice()).expect("32-byte hash output");
                let value = BigUint::from_bytes_be(&hash_output);
                let modulus =
                    BigUint::from_bytes_le((-Fq::ONE).to_repr().as_ref()) + BigUint::from(1u8);
                let reduced = value % modulus;
                let mut repr = <Fq as PrimeField>::Repr::default();
                let repr_len = repr.as_ref().len();
                let mut reduced_le = reduced.to_bytes_le();
                reduced_le.resize(repr_len, 0);
                repr.as_mut().copy_from_slice(&reduced_le[..repr_len]);
                let challenge = Fq::from_repr(repr).unwrap();

                let mut challenge_be = challenge.to_repr();
                challenge_be.as_mut().reverse();
                push_trace_event(TranscriptEvent::Squeeze {
                    hash,
                    challenge_be: challenge_be
                        .as_ref()
                        .try_into()
                        .expect("scalar repr must be 32 bytes"),
                });
                challenge
            }
        }

        impl Hashable<MidnightEvmHash> for G1Projective {
            fn to_input(&self) -> Vec<u8> {
                let affine = MidnightG1Affine::from(self);
                let coordinates =
                    match Option::<midnight_curves::Coordinates<MidnightG1Affine>>::from(
                        affine.coordinates(),
                    ) {
                        Some(coordinates) => coordinates,
                        None => {
                            return vec![0u8; 2 * EVM_ENCODED_FP_BYTES];
                        }
                    };
                let mut bytes = Vec::with_capacity(2 * EVM_ENCODED_FP_BYTES);
                bytes.extend_from_slice(&fp_to_evm_word(coordinates.x()));
                bytes.extend_from_slice(&fp_to_evm_word(coordinates.y()));
                bytes
            }

            fn to_bytes(&self) -> Vec<u8> {
                let affine = MidnightG1Affine::from(self);
                let coordinates =
                    match Option::<midnight_curves::Coordinates<MidnightG1Affine>>::from(
                        affine.coordinates(),
                    ) {
                        Some(coordinates) => coordinates,
                        None => {
                            return vec![0u8; 2 * midnight_fp_num_bytes()];
                        }
                    };
                let mut bytes = Vec::with_capacity(2 * midnight_fp_num_bytes());
                bytes.extend_from_slice(&fp_to_be_bytes(coordinates.x()));
                bytes.extend_from_slice(&fp_to_be_bytes(coordinates.y()));
                bytes
            }

            fn read(buffer: &mut impl Read) -> io::Result<Self> {
                let coord_bytes = midnight_fp_num_bytes();
                let mut x_be = vec![0u8; coord_bytes];
                let mut y_be = vec![0u8; coord_bytes];
                buffer.read_exact(&mut x_be)?;
                buffer.read_exact(&mut y_be)?;

                let x = fp_from_be_bytes(&x_be)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                let y = fp_from_be_bytes(&y_be)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                if x == MidnightFp::ZERO && y == MidnightFp::ZERO {
                    return Ok(G1Projective::default());
                }
                let affine: MidnightG1Affine = Option::from(MidnightG1Affine::from_xy(x, y))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            "Invalid BLS12-381 point encoding in proof",
                        )
                    })?;
                Ok(G1Projective::from(affine))
            }
        }

        impl Hashable<TracingMidnightEvmHash> for Fq {
            fn to_input(&self) -> Vec<u8> {
                scalar_to_evm_bytes(self)
            }

            fn to_bytes(&self) -> Vec<u8> {
                scalar_to_evm_bytes(self)
            }

            fn read(buffer: &mut impl Read) -> io::Result<Self> {
                let mut be = [0u8; 32];
                buffer.read_exact(&mut be)?;
                scalar_from_evm_bytes(&be)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
            }
        }

        impl Hashable<TracingMidnightEvmHash> for G1Projective {
            fn to_input(&self) -> Vec<u8> {
                let affine = MidnightG1Affine::from(self);
                let coordinates =
                    match Option::<midnight_curves::Coordinates<MidnightG1Affine>>::from(
                        affine.coordinates(),
                    ) {
                        Some(coordinates) => coordinates,
                        None => {
                            return vec![0u8; 2 * EVM_ENCODED_FP_BYTES];
                        }
                    };
                let mut bytes = Vec::with_capacity(2 * EVM_ENCODED_FP_BYTES);
                bytes.extend_from_slice(&fp_to_evm_word(coordinates.x()));
                bytes.extend_from_slice(&fp_to_evm_word(coordinates.y()));
                bytes
            }

            fn to_bytes(&self) -> Vec<u8> {
                let affine = MidnightG1Affine::from(self);
                let coordinates =
                    match Option::<midnight_curves::Coordinates<MidnightG1Affine>>::from(
                        affine.coordinates(),
                    ) {
                        Some(coordinates) => coordinates,
                        None => {
                            return vec![0u8; 2 * midnight_fp_num_bytes()];
                        }
                    };
                let mut bytes = Vec::with_capacity(2 * midnight_fp_num_bytes());
                bytes.extend_from_slice(&fp_to_be_bytes(coordinates.x()));
                bytes.extend_from_slice(&fp_to_be_bytes(coordinates.y()));
                bytes
            }

            fn read(buffer: &mut impl Read) -> io::Result<Self> {
                let coord_bytes = midnight_fp_num_bytes();
                let mut x_be = vec![0u8; coord_bytes];
                let mut y_be = vec![0u8; coord_bytes];
                buffer.read_exact(&mut x_be)?;
                buffer.read_exact(&mut y_be)?;

                let x = fp_from_be_bytes(&x_be)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                let y = fp_from_be_bytes(&y_be)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                if x == MidnightFp::ZERO && y == MidnightFp::ZERO {
                    return Ok(G1Projective::default());
                }
                let affine: MidnightG1Affine = Option::from(MidnightG1Affine::from_xy(x, y))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            "Invalid BLS12-381 point encoding in proof",
                        )
                    })?;
                Ok(G1Projective::from(affine))
            }
        }

        fn midnight_fp_num_bytes() -> usize {
            <MidnightFp as PrimeField>::Repr::default().as_ref().len()
        }

        fn scalar_to_evm_bytes(value: &Fq) -> Vec<u8> {
            let mut bytes = value.to_repr().as_ref().to_vec();
            bytes.reverse();
            bytes
        }

        fn scalar_from_evm_bytes(bytes_be: &[u8]) -> Result<Fq> {
            let expected = <Fq as PrimeField>::Repr::default().as_ref().len();
            if bytes_be.len() != expected {
                return Err(anyhow!(
                    "invalid scalar length: expected {expected} bytes, got {}",
                    bytes_be.len()
                ));
            }
            let mut le = bytes_be.to_vec();
            le.reverse();
            let mut repr = <Fq as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&le);
            Option::from(Fq::from_repr(repr)).ok_or_else(|| anyhow!("invalid scalar encoding"))
        }

        fn fp_to_be_bytes(value: &MidnightFp) -> Vec<u8> {
            let mut bytes = value.to_repr().as_ref().to_vec();
            bytes.reverse();
            bytes
        }

        fn fp_to_evm_word(value: &MidnightFp) -> [u8; EVM_ENCODED_FP_BYTES] {
            let be = fp_to_be_bytes(value);
            let mut out = [0u8; EVM_ENCODED_FP_BYTES];
            let offset = EVM_ENCODED_FP_BYTES - be.len();
            out[offset..].copy_from_slice(&be);
            out
        }

        fn fp_from_be_bytes(bytes_be: &[u8]) -> Result<MidnightFp> {
            let expected = midnight_fp_num_bytes();
            if bytes_be.len() != expected {
                return Err(anyhow!(
                    "invalid base-field coordinate length: expected {expected} bytes, got {}",
                    bytes_be.len()
                ));
            }
            let mut le = bytes_be.to_vec();
            le.reverse();
            let mut repr = <MidnightFp as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&le);
            Option::from(MidnightFp::from_repr(repr))
                .ok_or_else(|| anyhow!("invalid base-field encoding"))
        }
    }
    use midnight_evm_transcript::MidnightEvmHash;

    type F = midnight_curves::Fq;
    type MidnightVerifierTrace = VerifierAlgebraicTrace<F, KZGCommitmentScheme<Bls12>>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum FsTraceEvent {
        Absorb(Vec<u8>),
        Squeeze { hash: [u8; 32], challenge: U256 },
    }

    fn challenge_sequence(trace: &[FsTraceEvent]) -> Vec<U256> {
        trace
            .iter()
            .filter_map(|event| match event {
                FsTraceEvent::Squeeze { challenge, .. } => Some(*challenge),
                FsTraceEvent::Absorb(_) => None,
            })
            .collect()
    }

    fn encode_halo_scalar_to_evm_bytes(value: &HaloFr) -> Vec<u8> {
        let mut repr = value.to_repr();
        repr.as_mut().reverse();
        repr.as_ref().to_vec()
    }

    fn encode_halo_point_to_evm_bytes(point: &HaloG1Affine) -> Vec<u8> {
        if let Some(coordinates) = Option::<Coordinates<HaloG1Affine>>::from(point.coordinates()) {
            [coordinates.x(), coordinates.y()]
                .into_iter()
                .flat_map(|coordinate| {
                    let repr = coordinate.to_repr();
                    let repr: &[u8] = repr.as_ref();
                    let encoded_len = match repr.len() {
                        0..=0x20 => 0x20,
                        0x21..=0x40 => 0x40,
                        _ => unreachable!("unsupported base-field encoding length: {}", repr.len()),
                    };
                    std::iter::repeat(0)
                        .take(encoded_len - repr.len())
                        .chain(repr.iter().rev().copied())
                        .collect::<Vec<_>>()
                })
                .collect()
        } else {
            let repr_len =
                std::mem::size_of::<<<HaloG1Affine as SvCurveAffine>::Base as PrimeField>::Repr>();
            let encoded_len = match repr_len {
                0..=0x20 => 0x20,
                0x21..=0x40 => 0x40,
                _ => unreachable!("unsupported base-field encoding length: {}", repr_len),
            };
            vec![0u8; 2 * encoded_len]
        }
    }

    fn digest_to_challenge(hash: [u8; 32]) -> U256 {
        U256::from_le_bytes(
            snark_verifier::loader::evm::u256_to_fe::<HaloFr>(U256::from_be_bytes(hash)).to_repr(),
        )
    }

    #[derive(Clone, Default)]
    struct PoseidonExample<const REPEATS: usize>;

    impl<const REPEATS: usize> Relation for PoseidonExample<REPEATS> {
        type Instance = F;
        type Witness = [F; 3];

        fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
            Ok(vec![*instance])
        }

        fn circuit(
            &self,
            std_lib: &ZkStdLib,
            layouter: &mut impl Layouter<F>,
            _instance: Value<Self::Instance>,
            witness: Value<Self::Witness>,
        ) -> Result<(), Error> {
            let assigned_message = std_lib.assign_many(layouter, &witness.transpose_array())?;
            let mut output = std_lib.poseidon(layouter, &assigned_message)?;
            for _ in 1..REPEATS {
                output = std_lib.poseidon(layouter, &assigned_message)?;
            }
            std_lib.constrain_as_public_input(layouter, &output)
        }

        fn used_chips(&self) -> ZkStdLibArch {
            ZkStdLibArch { poseidon: true, ..ZkStdLibArch::default() }
        }

        fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
            Ok(())
        }

        fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
            Ok(PoseidonExample)
        }
    }

    struct TracingNativeTranscript<'a> {
        inner: EvmTranscript<HaloG1Affine, NativeLoader, &'a [u8], Vec<u8>>,
        state: Vec<u8>,
        trace: Vec<FsTraceEvent>,
    }

    impl<'a> TracingNativeTranscript<'a> {
        fn new(proof: &'a [u8]) -> Self {
            Self {
                inner: EvmTranscript::<HaloG1Affine, NativeLoader, _, _>::new(proof),
                state: Vec::new(),
                trace: Vec::new(),
            }
        }

        fn absorb(&mut self, bytes: Vec<u8>) {
            self.state.extend_from_slice(&bytes);
            self.trace.push(FsTraceEvent::Absorb(bytes));
        }

        fn into_trace(self) -> Vec<FsTraceEvent> {
            self.trace
        }
    }

    impl<'a> SvTranscript<HaloG1Affine, NativeLoader> for TracingNativeTranscript<'a> {
        fn loader(&self) -> &NativeLoader {
            SvTranscript::loader(&self.inner)
        }

        fn squeeze_challenge(&mut self) -> HaloFr {
            let challenge = SvTranscript::squeeze_challenge(&mut self.inner);
            let mut data = self.state.clone();
            if data.len() == 32 {
                data.push(1);
            }
            let hash: [u8; 32] = sha3::Keccak256::digest(data).into();
            let challenge_u256 = U256::from_le_bytes(challenge.to_repr());
            assert_eq!(
                challenge_u256,
                digest_to_challenge(hash),
                "native transcript wrapper challenge diverged from recomputed hash"
            );
            self.trace.push(FsTraceEvent::Squeeze { hash, challenge: challenge_u256 });
            self.state = hash.to_vec();
            challenge
        }

        fn common_ec_point(
            &mut self,
            ec_point: &HaloG1Affine,
        ) -> Result<(), snark_verifier::Error> {
            self.absorb(encode_halo_point_to_evm_bytes(ec_point));
            SvTranscript::common_ec_point(&mut self.inner, ec_point)
        }

        fn common_scalar(&mut self, scalar: &HaloFr) -> Result<(), snark_verifier::Error> {
            self.absorb(encode_halo_scalar_to_evm_bytes(scalar));
            SvTranscript::common_scalar(&mut self.inner, scalar)
        }
    }

    impl<'a> SvTranscriptRead<HaloG1Affine, NativeLoader> for TracingNativeTranscript<'a> {
        fn read_scalar(&mut self) -> Result<HaloFr, snark_verifier::Error> {
            let scalar = SvTranscriptRead::read_scalar(&mut self.inner)?;
            self.absorb(encode_halo_scalar_to_evm_bytes(&scalar));
            Ok(scalar)
        }

        fn read_ec_point(&mut self) -> Result<HaloG1Affine, snark_verifier::Error> {
            let point = SvTranscriptRead::read_ec_point(&mut self.inner)?;
            self.absorb(encode_halo_point_to_evm_bytes(&point));
            Ok(point)
        }
    }

    fn convert_midnight_trace_event(
        event: midnight_evm_transcript::TranscriptEvent,
    ) -> FsTraceEvent {
        match event {
            midnight_evm_transcript::TranscriptEvent::Absorb(bytes) => FsTraceEvent::Absorb(bytes),
            midnight_evm_transcript::TranscriptEvent::Squeeze { hash, challenge_be } => {
                FsTraceEvent::Squeeze { hash, challenge: U256::from_be_slice(&challenge_be) }
            }
        }
    }

    #[derive(Clone, Debug)]
    struct RustVerifierVariables {
        challenges: Vec<Vec<u8>>,
        z: Vec<u8>,
        evaluations: Vec<Vec<u8>>,
    }

    fn midnight_scalar_to_evm_bytes(value: &F) -> Vec<u8> {
        <F as MidnightHashable<MidnightEvmHash>>::to_input(value)
    }

    fn collect_midnight_verifier_trace<const REPEATS: usize>(
        params_verifier: &midnight_proofs::poly::kzg::params::ParamsVerifierKZG<Bls12>,
        vk: &midnight_zk_stdlib::MidnightVK,
        instance: &F,
        proof: &[u8],
    ) -> Result<(MidnightVerifierTrace, Vec<FsTraceEvent>)> {
        let pi = PoseidonExample::<REPEATS>::format_instance(instance)?;
        let committed = [midnight_curves::G1Projective::default()];
        let committed_batch = [committed.as_slice()];
        let pi_columns = [pi.as_slice()];
        let instance_batch = [pi_columns.as_slice()];

        midnight_evm_transcript::reset_trace_events();
        let mut transcript =
            CircuitTranscript::<midnight_evm_transcript::TracingMidnightEvmHash>::init_from_bytes(
                proof,
            );
        let (guard, trace) = midnight_proofs::plonk::prepare_with_trace::<
            F,
            KZGCommitmentScheme<Bls12>,
            _,
        >(vk.vk(), &committed_batch, &instance_batch, &mut transcript)?;
        transcript.assert_empty().map_err(|_| Error::Opening)?;
        guard.verify(params_verifier).map_err(|_| Error::Opening)?;

        let midnight_trace = midnight_evm_transcript::take_trace_events()
            .into_iter()
            .map(convert_midnight_trace_event)
            .collect::<Vec<_>>();

        Ok((trace, midnight_trace))
    }

    fn collect_rust_verifier_variables_and_trace(
        bundle: &MidnightProofBundle,
    ) -> Result<(RustVerifierVariables, Vec<FsTraceEvent>)> {
        let dk = bundle.snark_deciding_key()?;
        let protocol = bundle.to_snark_protocol()?;
        let instances = bundle.full_instances_as_halo_fr()?;
        let committed_instances = bundle.committed_instances_as_halo_points()?;
        let committed_instances = (!committed_instances.is_empty()).then_some(committed_instances);
        let mut transcript = TracingNativeTranscript::new(bundle.proof.as_slice());
        let svk = dk.svk();

        let proof =
            PlonkProof::<HaloG1Affine, NativeLoader, super::super::HaloAs>::read_with_committed_instances::<
            _,
            LimbsEncoding<{ crate::LIMBS }, { crate::BITS }>,
        >(&svk, &protocol, &instances, committed_instances.as_deref(), &mut transcript)
        .map_err(|e| anyhow!("failed to parse Midnight proof with native EVM transcript: {e:?}"))?;

        <crate::PlonkVerifier<super::super::HaloAs> as SnarkVerifier<
            HaloG1Affine,
            NativeLoader,
        >>::verify(&dk, &protocol, &instances, &proof)
        .map_err(|e| anyhow!("failed to verify Midnight proof with native EVM transcript: {e:?}"))?;

        let vars = RustVerifierVariables {
            challenges: proof.challenges.iter().map(encode_halo_scalar_to_evm_bytes).collect(),
            z: encode_halo_scalar_to_evm_bytes(&proof.z),
            evaluations: proof.evaluations.iter().map(encode_halo_scalar_to_evm_bytes).collect(),
        };

        Ok((vars, transcript.into_trace()))
    }

    fn expected_midnight_evaluation_stream(trace: &MidnightVerifierTrace) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for proof_instance_evals in trace.instance_evals.iter() {
            for (query_idx, eval) in proof_instance_evals.iter().enumerate() {
                if trace.instance_query_columns[query_idx] < trace.nb_committed_instances {
                    out.push(midnight_scalar_to_evm_bytes(eval));
                }
            }
        }
        out.extend(
            trace
                .advice_evals
                .iter()
                .flat_map(|evals| evals.iter().map(midnight_scalar_to_evm_bytes)),
        );
        out.extend(trace.fixed_evals.iter().map(midnight_scalar_to_evm_bytes));
        out.push(midnight_scalar_to_evm_bytes(&trace.vanishing_evaluated.random_eval));
        out.extend(
            trace.permutations_common.permutation_evals.iter().map(midnight_scalar_to_evm_bytes),
        );
        out.extend(trace.permutations_evaluated.iter().flat_map(|evaluated| {
            evaluated.sets.iter().flat_map(|set| {
                let mut set_values = vec![
                    midnight_scalar_to_evm_bytes(&set.permutation_product_eval),
                    midnight_scalar_to_evm_bytes(&set.permutation_product_next_eval),
                ];
                if let Some(last_eval) = set.permutation_product_last_eval {
                    set_values.push(midnight_scalar_to_evm_bytes(&last_eval));
                }
                set_values
            })
        }));
        out.extend(trace.lookups_evaluated.iter().flat_map(|lookups| {
            lookups.iter().flat_map(|lookup| {
                [
                    midnight_scalar_to_evm_bytes(&lookup.product_eval),
                    midnight_scalar_to_evm_bytes(&lookup.product_next_eval),
                    midnight_scalar_to_evm_bytes(&lookup.permuted_input_eval),
                    midnight_scalar_to_evm_bytes(&lookup.permuted_input_inv_eval),
                    midnight_scalar_to_evm_bytes(&lookup.permuted_table_eval),
                ]
            })
        }));
        out.extend(trace.trashcans_evaluated.iter().flat_map(|trashcans| {
            trashcans.iter().map(|trash| midnight_scalar_to_evm_bytes(&trash.trash_eval))
        }));
        out
    }

    fn assert_full_midnight_trace_matches_snark_variables(
        trace: &MidnightVerifierTrace,
        rust: &RustVerifierVariables,
        repeats: usize,
        k: u32,
        seed: u64,
    ) -> Result<()> {
        let midnight_challenges = trace
            .parsed_trace
            .challenges
            .iter()
            .map(midnight_scalar_to_evm_bytes)
            .chain([
                midnight_scalar_to_evm_bytes(&trace.parsed_trace.theta),
                midnight_scalar_to_evm_bytes(&trace.parsed_trace.beta),
                midnight_scalar_to_evm_bytes(&trace.parsed_trace.gamma),
                midnight_scalar_to_evm_bytes(&trace.parsed_trace.trash_challenge),
                midnight_scalar_to_evm_bytes(&trace.parsed_trace.y),
            ])
            .collect::<Vec<_>>();
        if rust.challenges != midnight_challenges {
            return Err(anyhow!(
                "challenge sequence diverged between midnight and snark-verifier traces (repeats={repeats}, k={k}, seed={seed})"
            ));
        }

        if rust.z != midnight_scalar_to_evm_bytes(&trace.x) {
            return Err(anyhow!(
                "opening challenge diverged between midnight and snark-verifier traces (repeats={repeats}, k={k}, seed={seed})"
            ));
        }

        let midnight_evaluations = expected_midnight_evaluation_stream(trace);
        if rust.evaluations != midnight_evaluations {
            return Err(anyhow!(
                "evaluation stream diverged between midnight and snark-verifier traces (repeats={repeats}, k={k}, seed={seed})"
            ));
        }

        Ok(())
    }

    fn build_poseidon_bundle<const REPEATS: usize>(
        k: u32,
        seed: u64,
    ) -> Result<(MidnightProofBundle, Vec<FsTraceEvent>, MidnightVerifierTrace)> {
        let srs = ParamsKZG::<Bls12>::unsafe_setup(k, OsRng);
        let relation = PoseidonExample::<REPEATS>;
        let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
        let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let witness: [F; 3] = core::array::from_fn(|_| F::random(&mut rng));
        let instance = <PoseidonChip<F> as HashCPU<F, F>>::hash(&witness);

        let proof = midnight_zk_stdlib::prove::<PoseidonExample<REPEATS>, MidnightEvmHash>(
            &srs, &pk, &relation, &instance, witness, OsRng,
        )?;
        midnight_zk_stdlib::verify::<PoseidonExample<REPEATS>, MidnightEvmHash>(
            &srs.verifier_params(),
            &vk,
            &instance,
            None,
            &proof,
        )?;

        let (midnight_verifier_trace, midnight_trace) = collect_midnight_verifier_trace::<REPEATS>(
            &srs.verifier_params(),
            &vk,
            &instance,
            &proof,
        )?;

        let bundle = MidnightProofBundle::from_vk(
            srs.verifier_params(),
            vk.vk().clone(),
            proof,
            vec![vec![instance]],
            MidnightBundleOptions::default(),
        )?;

        Ok((bundle, midnight_trace, midnight_verifier_trace))
    }

    fn parse_usize_literal(input: &str) -> Result<usize> {
        let lit = input.trim();
        if let Some(hex) = lit.strip_prefix("0x") {
            usize::from_str_radix(hex, 16)
                .map_err(|err| anyhow!("invalid hex pointer literal {lit}: {err}"))
        } else {
            lit.parse::<usize>()
                .map_err(|err| anyhow!("invalid decimal pointer literal {lit}: {err}"))
        }
    }

    fn extract_transcript_challenge_ptrs(loader: &Rc<EvmLoader>) -> Result<Vec<usize>> {
        let runtime_blocks = loader.code_mut().runtime_blocks().to_vec();
        let mut pointers = Vec::new();
        for block in runtime_blocks {
            for line in block.lines() {
                let marker = ", mod(hash, f_q))";
                if !line.contains(marker) {
                    continue;
                }
                if let Some((_, tail)) = line.split_once("mstore(") {
                    if let Some((ptr_lit, _)) = tail.split_once(marker) {
                        pointers.push(parse_usize_literal(ptr_lit)?);
                    }
                }
            }
        }
        if pointers.is_empty() {
            return Err(anyhow!("no transcript challenge stores found in generated EVM runtime"));
        }
        Ok(pointers)
    }

    fn inject_transcript_equivalence_checks(
        loader: &Rc<EvmLoader>,
        challenge_ptrs: &[usize],
        rust_challenges: &[U256],
    ) -> Result<()> {
        if challenge_ptrs.len() != rust_challenges.len() {
            return Err(anyhow!(
                "challenge pointer count ({}) != rust challenge count ({})",
                challenge_ptrs.len(),
                rust_challenges.len()
            ));
        }
        for (ptr, expected) in challenge_ptrs.iter().zip(rust_challenges.iter()) {
            loader.code_mut().runtime_append(format!(
                "if iszero(eq(mload({ptr:#x}), 0x{})) {{ success := 0 }}",
                hex::encode(expected.to_be_bytes::<32>())
            ));
        }
        Ok(())
    }

    fn build_loader_with_transcript_checks(
        bundle: &MidnightProofBundle,
        rust_challenges: &[U256],
    ) -> Result<Rc<EvmLoader>> {
        let loader = bundle.build_evm_verifier_loader()?;
        let challenge_ptrs = extract_transcript_challenge_ptrs(&loader)?;
        inject_transcript_equivalence_checks(&loader, &challenge_ptrs, rust_challenges)?;
        Ok(loader)
    }

    fn run_transcript_equivalence_case<const REPEATS: usize>(k: u32, seed: u64) -> Result<()> {
        let (bundle, midnight_trace, midnight_verifier_trace) =
            build_poseidon_bundle::<REPEATS>(k, seed)?;
        let (rust_vars, rust_trace) = collect_rust_verifier_variables_and_trace(&bundle)?;
        if rust_trace != midnight_trace {
            return Err(anyhow!(
                "midnight verifier transcript trace diverged from snark-verifier trace (repeats={REPEATS}, k={k}, seed={seed})"
            ));
        }
        assert_full_midnight_trace_matches_snark_variables(
            &midnight_verifier_trace,
            &rust_vars,
            REPEATS,
            k,
            seed,
        )?;
        let rust_challenges = challenge_sequence(&rust_trace);
        if rust_challenges.len() < 8 {
            return Err(anyhow!(
                "full verifier transcript should contain a non-trivial number of challenges; got {}",
                rust_challenges.len()
            ));
        }
        let calldata = bundle.encode_evm_calldata()?;

        // Positive: unrolled Solidity path must match full Rust transcript.
        let loader_unrolled = build_loader_with_transcript_checks(&bundle, &rust_challenges)?;
        let unrolled_bytecode =
            snark_verifier::loader::evm::compile_solidity(&loader_unrolled.solidity_code());
        snark_verifier::loader::evm::deploy_and_call(unrolled_bytecode, calldata.clone()).map_err(
            |err| {
                anyhow!(
                    "unrolled verifier transcript mismatch (repeats={REPEATS}, k={k}, seed={seed}): {err}"
                )
            },
        )?;

        // Positive: sharded Solidity path must match full Rust transcript.
        let loader_sharded = build_loader_with_transcript_checks(&bundle, &rust_challenges)?;
        let sharded = loader_sharded.unrolled_sharded_verifier_artifacts();
        snark_verifier::loader::evm::deploy_unrolled_sharded_and_call(
            sharded.shard_deployment_codes,
            sharded.dispatcher_deployment_code,
            calldata.clone(),
        )
        .map_err(|err| {
            anyhow!(
                "sharded verifier transcript mismatch (repeats={REPEATS}, k={k}, seed={seed}): {err}"
            )
        })?;

        // Negative: mutate one expected challenge; both paths must fail.
        let mut bad_challenges = rust_challenges;
        bad_challenges[0] += U256::from(1u64);

        let loader_bad_unrolled = build_loader_with_transcript_checks(&bundle, &bad_challenges)?;
        let bad_unrolled_bytecode =
            snark_verifier::loader::evm::compile_solidity(&loader_bad_unrolled.solidity_code());
        if snark_verifier::loader::evm::deploy_and_call(bad_unrolled_bytecode, calldata.clone())
            .is_ok()
        {
            return Err(anyhow!(
                "unrolled verifier should fail when any expected transcript challenge is mutated (repeats={REPEATS}, k={k}, seed={seed})"
            ));
        }

        let loader_bad_sharded = build_loader_with_transcript_checks(&bundle, &bad_challenges)?;
        let sharded_bad = loader_bad_sharded.unrolled_sharded_verifier_artifacts();
        if snark_verifier::loader::evm::deploy_unrolled_sharded_and_call(
            sharded_bad.shard_deployment_codes,
            sharded_bad.dispatcher_deployment_code,
            calldata,
        )
        .is_ok()
        {
            return Err(anyhow!(
                "sharded verifier should fail when any expected transcript challenge is mutated (repeats={REPEATS}, k={k}, seed={seed})"
            ));
        }

        Ok(())
    }

    #[test]
    fn midnight_poseidon_full_fiat_shamir_transcript_matches_rust_and_sharded_solidity() {
        run_transcript_equivalence_case::<1>(6, 7)
            .unwrap_or_else(|err| panic!("case (repeats=1, k=6, seed=7) failed: {err:#}"));
        run_transcript_equivalence_case::<1>(6, 11)
            .unwrap_or_else(|err| panic!("case (repeats=1, k=6, seed=11) failed: {err:#}"));
        run_transcript_equivalence_case::<4>(8, 7)
            .unwrap_or_else(|err| panic!("case (repeats=4, k=8, seed=7) failed: {err:#}"));
    }
}
