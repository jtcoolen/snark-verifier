use anyhow::{anyhow, bail, Result};
use halo2_base::halo2_proofs::halo2curves::bls12_381::{
    Bls12 as HaloBls12, Fr as HaloFr, G1Affine as HaloG1Affine, G2Affine as HaloG2Affine,
};
use itertools::Itertools;
use midnight_curves::{Bls12, Fq, G2Projective};
use midnight_proofs::{
    plonk::VerifyingKey,
    poly::kzg::{params::ParamsVerifierKZG, KZGCommitmentScheme},
    utils::{helpers::ProcessedSerdeObject, SerdeFormat},
};
use snark_verifier::{
    loader::Loader,
    pcs::{
        kzg::{KzgDecidingKey, KzgSuccinctVerifyingKey, LimbsEncoding},
        AccumulationScheme, AccumulatorEncoding, PolynomialCommitmentScheme,
    },
    util::transcript::TranscriptRead as SvTranscriptRead,
    verifier::{
        plonk::{PlonkProof, PlonkProtocol},
        SnarkVerifier,
    },
};

use super::{
    conversions::{
        midnight_fq_to_halo_fr, midnight_g1_to_halo_affine, midnight_g2_to_halo_affine,
        normalize_committed_instances,
    },
    protocol_builder::{DummyCircuit, MidnightProtocolBuilder},
    HaloAs, MidnightCommitment,
};

/// Options controlling how a [`MidnightProofBundle`] is constructed.
#[derive(Clone, Debug, Default)]
pub struct MidnightBundleOptions {
    pub committed_instances: Vec<MidnightCommitment>,
}

/// Parsed Midnight artifacts plus helpers for EVM verifier generation.
#[derive(Clone, Debug)]
pub struct MidnightProofBundle {
    pub params: ParamsVerifierKZG<Bls12>,
    pub vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    pub committed_instances: Vec<MidnightCommitment>,
    pub instances: Vec<Vec<Fq>>, // outer = instance columns, inner = values
    pub proof: Vec<u8>,
}

impl MidnightProofBundle {
    fn build_with_options(
        params: ParamsVerifierKZG<Bls12>,
        vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        proof: Vec<u8>,
        instances: Vec<Vec<Fq>>,
        options: MidnightBundleOptions,
    ) -> Result<Self> {
        let committed_instances =
            normalize_committed_instances(&vk, options.committed_instances, instances.len())?;
        Ok(MidnightProofBundle { params, vk, committed_instances, instances, proof })
    }

    // Decode Midnight VK bytes with the same unchecked format used by existing adapters.
    fn decode_vk(vk_bytes: &[u8]) -> Result<VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>> {
        VerifyingKey::from_bytes::<DummyCircuit>(vk_bytes, SerdeFormat::RawBytesUnchecked, ())
            .map_err(Into::into)
    }

    // Shared byte-deserialization path used by public constructors.
    fn from_vk_bytes_inner(
        params: ParamsVerifierKZG<Bls12>,
        vk_bytes: &[u8],
        proof: Vec<u8>,
        instances: Vec<Vec<Fq>>,
        options: MidnightBundleOptions,
    ) -> Result<Self> {
        let vk = Self::decode_vk(vk_bytes)?;
        Self::build_with_options(params, vk, proof, instances, options)
    }

    /// Construct a bundle from already materialized params, VK, proof bytes, and instances.
    pub fn from_vk(
        params: ParamsVerifierKZG<Bls12>,
        vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        proof: Vec<u8>,
        instances: Vec<Vec<Fq>>,
        options: MidnightBundleOptions,
    ) -> Result<Self> {
        Self::build_with_options(params, vk, proof, instances, options)
    }

    /// Deserialize from VK bytes (encoded with RawBytesUnchecked) and construct a bundle.
    pub fn from_vk_bytes(
        params: ParamsVerifierKZG<Bls12>,
        vk_bytes: &[u8],
        proof: Vec<u8>,
        instances: Vec<Vec<Fq>>,
        options: MidnightBundleOptions,
    ) -> Result<Self> {
        Self::from_vk_bytes_inner(params, vk_bytes, proof, instances, options)
    }

    /// Build a `snark-verifier` deciding key from Midnight verifier params.
    pub(super) fn snark_deciding_key(&self) -> Result<KzgDecidingKey<HaloBls12>> {
        let s_g2 = self.decode_midnight_s_g2()?;
        Ok(KzgDecidingKey::new(
            HaloG1Affine::generator(),
            HaloG2Affine::generator(),
            midnight_g2_to_halo_affine(s_g2)?,
        ))
    }

    /// Convert non-committed instances into halo2-axiom `Fr`.
    fn instances_as_halo_fr(&self) -> Result<Vec<Vec<HaloFr>>> {
        self.instances
            .iter()
            .map(|column| column.iter().copied().map(midnight_fq_to_halo_fr).collect())
            .collect()
    }

    // Number of leading instance columns represented as commitments.
    pub(super) fn committed_instance_count(&self) -> usize {
        self.vk.cs().num_instance_columns().saturating_sub(self.instances.len())
    }

    // Expand non-committed instances into full layout by prefixing committed placeholder columns.
    pub(super) fn full_instances_as_halo_fr(&self) -> Result<Vec<Vec<HaloFr>>> {
        let committed_count = self.committed_instance_count();
        let mut full = vec![Vec::new(); committed_count];
        full.extend(self.instances_as_halo_fr()?);
        Ok(full)
    }

    // Convert committed-instance commitments into halo G1 points.
    pub(super) fn committed_instances_as_halo_points(&self) -> Result<Vec<HaloG1Affine>> {
        self.committed_instances.iter().cloned().map(midnight_g1_to_halo_affine).collect()
    }

    pub(super) fn to_snark_protocol(&self) -> Result<PlonkProtocol<HaloG1Affine>> {
        // The builder expects full instance-column layout, including committed placeholders.
        let committed_instance_count = self.committed_instance_count();
        let num_instance =
            self.full_instances_as_halo_fr()?.into_iter().map(|column| column.len()).collect_vec();
        let builder =
            MidnightProtocolBuilder::new(&self.vk, num_instance, committed_instance_count);
        builder.build()
    }

    // Shared snark-verifier proof parsing + verification flow used by EVM verifier generation.
    pub(super) fn run_snark_verifier_flow<L, T>(
        dk: &KzgDecidingKey<HaloBls12>,
        protocol: &PlonkProtocol<HaloG1Affine, L>,
        instances: &[Vec<L::LoadedScalar>],
        committed_instances: Option<&[L::LoadedEcPoint]>,
        transcript: &mut T,
        parse_error_context: &str,
        verify_error_context: &str,
    ) -> Result<()>
    where
        L: Loader<HaloG1Affine>,
        T: SvTranscriptRead<HaloG1Affine, L>,
        HaloAs: AccumulationScheme<HaloG1Affine, L>
            + PolynomialCommitmentScheme<
                HaloG1Affine,
                L,
                VerifyingKey = KzgSuccinctVerifyingKey<HaloG1Affine>,
                Output = <HaloAs as AccumulationScheme<HaloG1Affine, L>>::Accumulator,
            >,
        LimbsEncoding<{ crate::LIMBS }, { crate::BITS }>: AccumulatorEncoding<
            HaloG1Affine,
            L,
            Accumulator = <HaloAs as AccumulationScheme<HaloG1Affine, L>>::Accumulator,
        >,
        crate::PlonkVerifier<HaloAs>: SnarkVerifier<
            HaloG1Affine,
            L,
            VerifyingKey = KzgDecidingKey<HaloBls12>,
            Protocol = PlonkProtocol<HaloG1Affine, L>,
            Proof = PlonkProof<HaloG1Affine, L, HaloAs>,
            Output = (),
        >,
    {
        let svk = dk.svk();
        let proof = PlonkProof::<HaloG1Affine, L, HaloAs>::read_with_committed_instances::<
            _,
            LimbsEncoding<{ crate::LIMBS }, { crate::BITS }>,
        >(&svk, protocol, instances, committed_instances, transcript)
        .map_err(|e| anyhow!("{parse_error_context}: {e:?}"))?;

        <crate::PlonkVerifier<HaloAs> as SnarkVerifier<HaloG1Affine, L>>::verify(
            dk, protocol, instances, &proof,
        )
        .map_err(|e| anyhow!("{verify_error_context}: {e:?}"))?;

        Ok(())
    }

    pub(super) fn decode_midnight_s_g2(&self) -> Result<G2Projective> {
        let mut encoded = Vec::new();
        self.params.write(&mut encoded, SerdeFormat::Processed)?;
        let mut slice = encoded.as_slice();
        let s_g2 = G2Projective::read(&mut slice, SerdeFormat::Processed)?;
        if !slice.is_empty() {
            bail!("unexpected trailing bytes while decoding midnight verifier params");
        }
        Ok(s_g2)
    }
}
