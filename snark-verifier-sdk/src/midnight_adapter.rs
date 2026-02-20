//! Bridge helpers for Midnight (halo2 fork) artifacts.
//!
//! This module is feature-gated (`--features midnight`) so Midnight crates are
//! only pulled when explicitly requested.
//!
//! It exposes:
//! - Native Midnight proof verification (`verify`), and
//! - A bridge path (`verify_with_snark_decider`) that reuses Midnight parsing /
//!   algebraic checks and finalizes the KZG pairing check through
//!   `snark-verifier`'s decider.

#![cfg(feature = "midnight")]

use anyhow::{anyhow, bail, Result};
use blake2b_simd::State as Blake2bState;
use halo2_base::halo2_proofs::halo2curves::{
    bls12_381::{
        Bls12 as HaloBls12, Fq as HaloFq, Fq2 as HaloFq2, Fr as HaloFr, G1Affine as HaloG1Affine,
        G2Affine as HaloG2Affine,
    },
    ff::{Field, PrimeField},
    group::{prime::PrimeCurveAffine, Curve},
    CurveAffine as HaloCurveAffine,
};
use midnight_curves::{
    bls12_381::Fp2 as MidnightFp2, Bls12, CurveAffine as MidnightCurveAffine, Fp as MidnightFp, Fq,
    G1Affine as MidnightG1Affine, G1Projective, G2Projective,
};
use midnight_proofs::{
    plonk::{prepare, Any, Expression as MidnightExpression, FirstPhase, SecondPhase, ThirdPhase, VerifyingKey},
    poly::commitment::{Guard, PolynomialCommitmentScheme},
    poly::kzg::{params::ParamsVerifierKZG, KZGCommitmentScheme},
    transcript::{CircuitTranscript, Transcript as MidnightTranscript},
    utils::{helpers::ProcessedSerdeObject, SerdeFormat},
};
use snark_verifier::{
    loader::native::NativeLoader,
    pcs::{
        kzg::{Gwc19, KzgAccumulator, KzgAs, KzgDecidingKey, LimbsEncoding, Midnight},
        AccumulationDecider,
    },
    util::{
        arithmetic::{Domain, Rotation},
        transcript::{Transcript as SvTranscript, TranscriptRead as SvTranscriptRead},
    },
    verifier::{
        plonk::{
            CommonPolynomial, Expression, PlonkProof, PlonkProtocol, Query, QuotientChunkBase,
            QuotientPolynomial,
        },
        SnarkVerifier,
    },
    Error as SnarkVerifierError,
};
use itertools::Itertools;
use std::io;

type MidnightCommitment =
    <KZGCommitmentScheme<Bls12> as PolynomialCommitmentScheme<Fq>>::Commitment;
type MidnightGuard = midnight_proofs::poly::kzg::msm::DualMSM<Bls12>;
type HaloAs = KzgAs<HaloBls12, Midnight>;

/// Parsed Midnight artifacts plus a convenience verifier.
#[derive(Clone, Debug)]
pub struct MidnightProofBundle {
    pub params: ParamsVerifierKZG<Bls12>,
    pub vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    pub committed_instances: Vec<MidnightCommitment>,
    pub instances: Vec<Vec<Fq>>, // outer = instance columns, inner = values
    pub proof: Vec<u8>,
}

impl MidnightProofBundle {
    /// Construct a bundle from already materialized params, verifying key, proof bytes, and instances.
    /// Verification is performed eagerly; any failure returns an error.
    pub fn new(
        params: ParamsVerifierKZG<Bls12>,
        vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        proof: Vec<u8>,
        instances: Vec<Vec<Fq>>,
    ) -> Result<Self> {
        Self::new_with_committed_instances(params, vk, proof, vec![], instances)
    }

    /// Construct a bundle with committed and non-committed public instances.
    pub fn new_with_committed_instances(
        params: ParamsVerifierKZG<Bls12>,
        vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        proof: Vec<u8>,
        committed_instances: Vec<MidnightCommitment>,
        instances: Vec<Vec<Fq>>,
    ) -> Result<Self> {
        let committed_instances =
            normalize_committed_instances(&vk, committed_instances, instances.len())?;
        let bundle = MidnightProofBundle { params, vk, committed_instances, instances, proof };
        bundle.verify()?;
        Ok(bundle)
    }

    /// Deserialize from bytes (VK encoded with RawBytesUnchecked).
    pub fn from_bytes(
        params: ParamsVerifierKZG<Bls12>,
        vk_bytes: &[u8],
        proof: Vec<u8>,
        instances: Vec<Vec<Fq>>,
    ) -> Result<Self> {
        Self::from_bytes_with_committed_instances(params, vk_bytes, proof, vec![], instances)
    }

    /// Deserialize from bytes and include committed instance commitments.
    pub fn from_bytes_with_committed_instances(
        params: ParamsVerifierKZG<Bls12>,
        vk_bytes: &[u8],
        proof: Vec<u8>,
        committed_instances: Vec<MidnightCommitment>,
        instances: Vec<Vec<Fq>>,
    ) -> Result<Self> {
        let vk =
            VerifyingKey::from_bytes::<DummyCircuit>(vk_bytes, SerdeFormat::RawBytesUnchecked, ())?;
        Self::new_with_committed_instances(params, vk, proof, committed_instances, instances)
    }

    /// Parse proof and derive Midnight's KZG verification guard.
    pub fn prepare_guard(&self) -> Result<MidnightGuard> {
        let mut transcript = CircuitTranscript::<Blake2bState>::init_from_bytes(&self.proof);

        let committed_slices: Vec<&[MidnightCommitment]> =
            vec![self.committed_instances.as_slice()];
        let instance_refs: Vec<Vec<&[Fq]>> =
            vec![self.instances.iter().map(|col| col.as_slice()).collect()];
        let instance_slices: Vec<&[&[Fq]]> = instance_refs.iter().map(|v| v.as_slice()).collect();

        let guard = prepare(&self.vk, &committed_slices, &instance_slices, &mut transcript)?;
        Ok(guard)
    }

    /// Verify the proof using Midnight's native verifier.
    pub fn verify(&self) -> Result<()> {
        let guard = self.prepare_guard()?;
        guard.verify(&self.params).map_err(|e| anyhow!("{e:?}"))?;
        Ok(())
    }

    /// Return a `snark-verifier` native KZG accumulator derived from Midnight's guard.
    pub fn snark_accumulator(&self) -> Result<KzgAccumulator<HaloG1Affine, NativeLoader>> {
        let guard = self.prepare_guard()?;
        let (left_terms, right_terms) = guard.split();

        // Midnight checks e(left, s_g2) * e(right, -g2) == 1, while snark-verifier
        // decider checks e(lhs, g2) * e(rhs, -s_g2) == 1.
        // Map channels accordingly: lhs := right, rhs := left.
        let lhs = evaluate_midnight_msm(right_terms);
        let rhs = evaluate_midnight_msm(left_terms);

        Ok(KzgAccumulator::new(midnight_g1_to_halo_affine(lhs)?, midnight_g1_to_halo_affine(rhs)?))
    }

    /// Build a `snark-verifier` deciding key from Midnight verifier params.
    pub fn snark_deciding_key(&self) -> Result<KzgDecidingKey<HaloBls12>> {
        let s_g2 = self.decode_midnight_s_g2()?;
        Ok(KzgDecidingKey::new(
            HaloG1Affine::generator(),
            HaloG2Affine::generator(),
            midnight_g2_to_halo_affine(s_g2)?,
        ))
    }

    /// Verify the final KZG accumulator using `snark-verifier`'s native decider.
    ///
    /// This path reuses Midnight parsing and algebraic constraints, then delegates
    /// the pairing check to `snark-verifier`.
    pub fn verify_with_snark_decider(&self) -> Result<()> {
        let accumulator = self.snark_accumulator()?;
        let dk = self.snark_deciding_key()?;

        <KzgAs<HaloBls12, Gwc19> as AccumulationDecider<HaloG1Affine, NativeLoader>>::decide_all(
            &dk,
            vec![accumulator],
        )
        .map_err(|e| anyhow!("snark-verifier deciding check failed: {e:?}"))?;
        Ok(())
    }

    /// Fully verify through snark-verifier (protocol + proof + PCS + decider).
    /// Convert non-committed instances into halo2-axiom `Fr`.
    ///
    /// This is useful for the remaining protocol/proof-level adapter work.
    pub fn instances_as_halo_fr(&self) -> Result<Vec<Vec<HaloFr>>> {
        self.instances
            .iter()
            .map(|column| column.iter().copied().map(midnight_fq_to_halo_fr).collect())
            .collect()
    }

    fn committed_instance_count(&self) -> usize {
        self.vk
            .cs()
            .num_instance_columns()
            .saturating_sub(self.instances.len())
    }

    fn full_instances_as_halo_fr(&self) -> Result<Vec<Vec<HaloFr>>> {
        let committed_count = self.committed_instance_count();
        let mut full = vec![Vec::new(); committed_count];
        full.extend(self.instances_as_halo_fr()?);
        Ok(full)
    }

    fn committed_instances_as_halo_points(&self) -> Result<Vec<HaloG1Affine>> {
        self.committed_instances
            .iter()
            .cloned()
            .map(midnight_g1_to_halo_affine)
            .collect()
    }

    fn decode_midnight_s_g2(&self) -> Result<G2Projective> {
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

fn evaluate_midnight_msm(terms: Vec<(&Fq, &G1Projective)>) -> G1Projective {
    terms.into_iter().fold(G1Projective::default(), |mut acc, (scalar, base)| {
        acc += *base * *scalar;
        acc
    })
}

fn normalize_committed_instances(
    vk: &VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    mut committed_instances: Vec<MidnightCommitment>,
    num_uncommitted_instances: usize,
) -> Result<Vec<MidnightCommitment>> {
    let total_instance_columns = vk.cs().num_instance_columns();
    if num_uncommitted_instances > total_instance_columns {
        bail!(
            "too many non-committed instance columns: got {num_uncommitted_instances}, max {total_instance_columns}"
        );
    }

    let expected_committed = total_instance_columns - num_uncommitted_instances;
    if committed_instances.is_empty() && expected_committed > 0 {
        committed_instances = vec![MidnightCommitment::default(); expected_committed];
    }
    if committed_instances.len() != expected_committed {
        bail!(
            "committed instance column mismatch: expected {expected_committed}, got {}",
            committed_instances.len()
        );
    }
    Ok(committed_instances)
}

fn midnight_fq_to_halo_fr(value: Fq) -> Result<HaloFr> {
    let source = value.to_repr();
    let source_bytes: &[u8] = source.as_ref();
    let mut target = <HaloFr as PrimeField>::Repr::default();
    let target_bytes = target.as_mut();
    if source_bytes.len() != target_bytes.len() {
        bail!(
            "scalar encoding length mismatch (midnight={}, halo={})",
            source_bytes.len(),
            target_bytes.len()
        );
    }
    target_bytes.copy_from_slice(source_bytes);
    Option::from(HaloFr::from_repr(target))
        .ok_or_else(|| anyhow!("invalid scalar encoding when converting midnight::Fq -> halo::Fr"))
}

fn midnight_g1_to_halo_affine(point: G1Projective) -> Result<HaloG1Affine> {
    let affine = point.to_affine();
    if bool::from(affine.is_identity()) {
        return Ok(HaloG1Affine::identity());
    }

    let coordinates = affine.coordinates().unwrap();
    let x = midnight_fp_to_halo_fq(*coordinates.x())?;
    let y = midnight_fp_to_halo_fq(*coordinates.y())?;
    Option::from(HaloG1Affine::from_xy(x, y))
        .ok_or_else(|| anyhow!("failed to map midnight G1 coordinates into halo G1"))
}

fn midnight_g2_to_halo_affine(point: G2Projective) -> Result<HaloG2Affine> {
    let affine = point.to_affine();
    if bool::from(affine.is_identity()) {
        return Ok(HaloG2Affine::identity());
    }

    let coordinates = affine.coordinates().unwrap();
    let x = midnight_fp2_to_halo_fq2(*coordinates.x())?;
    let y = midnight_fp2_to_halo_fq2(*coordinates.y())?;
    Option::from(HaloG2Affine::from_xy(x, y))
        .ok_or_else(|| anyhow!("failed to map midnight G2 coordinates into halo G2"))
}

fn midnight_fp_to_halo_fq(value: MidnightFp) -> Result<HaloFq> {
    let source = value.to_repr();
    let source_bytes: &[u8] = source.as_ref();
    let mut target = <HaloFq as PrimeField>::Repr::default();
    let target_bytes = target.as_mut();
    if source_bytes.len() != target_bytes.len() {
        bail!(
            "base-field encoding length mismatch (midnight={}, halo={})",
            source_bytes.len(),
            target_bytes.len()
        );
    }
    target_bytes.copy_from_slice(source_bytes);
    Option::from(HaloFq::from_repr(target))
        .ok_or_else(|| anyhow!("invalid base-field encoding during midnight->halo conversion"))
}

fn midnight_fp2_to_halo_fq2(value: MidnightFp2) -> Result<HaloFq2> {
    Ok(HaloFq2 { c0: midnight_fp_to_halo_fq(value.c0())?, c1: midnight_fp_to_halo_fq(value.c1())? })
}

fn halo_fr_to_midnight_fq(value: HaloFr) -> Result<Fq> {
    let source = value.to_repr();
    let source_bytes: &[u8] = source.as_ref();
    let mut target = <Fq as PrimeField>::Repr::default();
    let target_bytes = target.as_mut();
    if source_bytes.len() != target_bytes.len() {
        bail!(
            "scalar encoding length mismatch (halo={}, midnight={})",
            source_bytes.len(),
            target_bytes.len()
        );
    }
    target_bytes.copy_from_slice(source_bytes);
    Option::from(Fq::from_repr(target))
        .ok_or_else(|| anyhow!("invalid scalar encoding when converting halo::Fr -> midnight::Fq"))
}

fn halo_fq_to_midnight_fp(value: HaloFq) -> Result<MidnightFp> {
    let source = value.to_repr();
    let source_bytes: &[u8] = source.as_ref();
    let mut target = <MidnightFp as PrimeField>::Repr::default();
    let target_bytes = target.as_mut();
    if source_bytes.len() != target_bytes.len() {
        bail!(
            "base-field encoding length mismatch (halo={}, midnight={})",
            source_bytes.len(),
            target_bytes.len()
        );
    }
    target_bytes.copy_from_slice(source_bytes);
    Option::from(MidnightFp::from_repr(target))
        .ok_or_else(|| anyhow!("invalid base-field encoding during halo->midnight conversion"))
}

fn halo_g1_to_midnight_projective(point: HaloG1Affine) -> Result<G1Projective> {
    if bool::from(point.is_identity()) {
        return Ok(G1Projective::default());
    }

    let coordinates = point.coordinates().unwrap();
    let x = halo_fq_to_midnight_fp(*coordinates.x())?;
    let y = halo_fq_to_midnight_fp(*coordinates.y())?;
    let affine: MidnightG1Affine = Option::from(MidnightG1Affine::from_xy(x, y))
        .ok_or_else(|| anyhow!("failed to map halo G1 coordinates into midnight G1"))?;
    Ok(affine.to_curve())
}
#[derive(Clone, Debug)]
struct MidnightSnarkTranscript {
    inner: CircuitTranscript<Blake2bState>,
    read_ec_points: usize,
    read_scalars: usize,
}

impl MidnightSnarkTranscript {
    fn init_from_bytes(bytes: &[u8]) -> Self {
        Self {
            inner: CircuitTranscript::<Blake2bState>::init_from_bytes(bytes),
            read_ec_points: 0,
            read_scalars: 0,
        }
    }

    fn map_io_error(err: io::Error) -> SnarkVerifierError {
        SnarkVerifierError::Transcript(err.kind(), err.to_string())
    }

    fn map_conversion_error(err: anyhow::Error) -> SnarkVerifierError {
        SnarkVerifierError::Transcript(io::ErrorKind::InvalidData, err.to_string())
    }
}

impl SvTranscript<HaloG1Affine, NativeLoader> for MidnightSnarkTranscript {
    fn loader(&self) -> &NativeLoader {
        &snark_verifier::loader::native::LOADER
    }

    fn squeeze_challenge(&mut self) -> HaloFr {
        let challenge: Fq = self.inner.squeeze_challenge();
        midnight_fq_to_halo_fr(challenge).expect("midnight challenge must map to halo scalar")
    }

    fn common_ec_point(&mut self, ec_point: &HaloG1Affine) -> Result<(), SnarkVerifierError> {
        let point =
            halo_g1_to_midnight_projective(*ec_point).map_err(Self::map_conversion_error)?;
        self.inner.common(&point).map_err(Self::map_io_error)
    }

    fn common_scalar(&mut self, scalar: &HaloFr) -> Result<(), SnarkVerifierError> {
        let scalar = halo_fr_to_midnight_fq(*scalar).map_err(Self::map_conversion_error)?;
        self.inner.common(&scalar).map_err(Self::map_io_error)
    }
}

impl SvTranscriptRead<HaloG1Affine, NativeLoader> for MidnightSnarkTranscript {
    fn read_scalar(&mut self) -> Result<HaloFr, SnarkVerifierError> {
        let value: Fq = self.inner.read().map_err(|err| {
            SnarkVerifierError::Transcript(
                err.kind(),
                format!("scalar read #{} failed: {}", self.read_scalars, err),
            )
        })?;
        self.read_scalars += 1;
        midnight_fq_to_halo_fr(value).map_err(Self::map_conversion_error)
    }

    fn read_ec_point(&mut self) -> Result<HaloG1Affine, SnarkVerifierError> {
        let value: G1Projective = self.inner.read().map_err(|err| {
            SnarkVerifierError::Transcript(
                err.kind(),
                format!("ec-point read #{} failed: {}", self.read_ec_points, err),
            )
        })?;
        self.read_ec_points += 1;
        midnight_g1_to_halo_affine(value).map_err(Self::map_conversion_error)
    }
}
/// Dummy circuit type to satisfy VK deserialization. We don't use params.
#[derive(Clone, Debug)]
struct DummyCircuit;

impl midnight_proofs::plonk::Circuit<Fq> for DummyCircuit {
    type Config = ();
    type FloorPlanner = midnight_proofs::circuit::SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        DummyCircuit
    }

    fn configure(_: &mut midnight_proofs::plonk::ConstraintSystem<Fq>) -> Self::Config {}

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl midnight_proofs::circuit::Layouter<Fq>,
    ) -> Result<(), midnight_proofs::plonk::Error> {
        Ok(())
    }
}
