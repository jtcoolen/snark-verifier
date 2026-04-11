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
        plonk::Error,
        poly::kzg::params::ParamsKZG,
    };
    use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};
    use rand::{rngs::OsRng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use snark_verifier::{
        loader::{evm::U256, native::NativeLoader},
        util::transcript::{Transcript as SvTranscript, TranscriptRead as SvTranscriptRead},
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
        use std::io::{self, Read};

        const EVM_ENCODED_FP_BYTES: usize = 64;

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
        challenges: Vec<U256>,
    }

    impl<'a> TracingNativeTranscript<'a> {
        fn new(proof: &'a [u8]) -> Self {
            Self {
                inner: EvmTranscript::<HaloG1Affine, NativeLoader, _, _>::new(proof),
                challenges: Vec::new(),
            }
        }

        fn into_challenges(self) -> Vec<U256> {
            self.challenges
        }
    }

    impl<'a> SvTranscript<HaloG1Affine, NativeLoader> for TracingNativeTranscript<'a> {
        fn loader(&self) -> &NativeLoader {
            SvTranscript::loader(&self.inner)
        }

        fn squeeze_challenge(&mut self) -> HaloFr {
            let challenge = SvTranscript::squeeze_challenge(&mut self.inner);
            self.challenges.push(U256::from_le_bytes(challenge.to_repr()));
            challenge
        }

        fn common_ec_point(
            &mut self,
            ec_point: &HaloG1Affine,
        ) -> Result<(), snark_verifier::Error> {
            SvTranscript::common_ec_point(&mut self.inner, ec_point)
        }

        fn common_scalar(&mut self, scalar: &HaloFr) -> Result<(), snark_verifier::Error> {
            SvTranscript::common_scalar(&mut self.inner, scalar)
        }
    }

    impl<'a> SvTranscriptRead<HaloG1Affine, NativeLoader> for TracingNativeTranscript<'a> {
        fn read_scalar(&mut self) -> Result<HaloFr, snark_verifier::Error> {
            SvTranscriptRead::read_scalar(&mut self.inner)
        }

        fn read_ec_point(&mut self) -> Result<HaloG1Affine, snark_verifier::Error> {
            SvTranscriptRead::read_ec_point(&mut self.inner)
        }
    }

    fn build_poseidon_bundle<const REPEATS: usize>(
        k: u32,
        seed: u64,
    ) -> Result<MidnightProofBundle> {
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

        MidnightProofBundle::from_vk(
            srs.verifier_params(),
            vk.vk().clone(),
            proof,
            vec![vec![instance]],
            MidnightBundleOptions::default(),
        )
    }

    fn collect_rust_verifier_challenges(bundle: &MidnightProofBundle) -> Result<Vec<U256>> {
        let dk = bundle.snark_deciding_key()?;
        let protocol = bundle.to_snark_protocol()?;
        let instances = bundle.full_instances_as_halo_fr()?;
        let committed_instances = bundle.committed_instances_as_halo_points()?;
        let committed_instances = (!committed_instances.is_empty()).then_some(committed_instances);
        let mut transcript = TracingNativeTranscript::new(bundle.proof.as_slice());

        MidnightProofBundle::run_snark_verifier_flow(
            &dk,
            &protocol,
            &instances,
            committed_instances.as_deref(),
            &mut transcript,
            "failed to parse Midnight proof with native EVM transcript",
            "failed to verify Midnight proof with native EVM transcript",
        )?;

        Ok(transcript.into_challenges())
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
        let bundle = build_poseidon_bundle::<REPEATS>(k, seed)?;
        let rust_challenges = collect_rust_verifier_challenges(&bundle)?;
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
