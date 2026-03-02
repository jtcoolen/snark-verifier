use anyhow::{anyhow, bail, Result};
use halo2_base::halo2_proofs::halo2curves::{
    bls12_381::{
        Fq as HaloFq, Fq2 as HaloFq2, Fr as HaloFr, G1Affine as HaloG1Affine,
        G2Affine as HaloG2Affine,
    },
    ff::PrimeField,
    group::{prime::PrimeCurveAffine, Curve},
    CurveAffine as HaloCurveAffine,
};
use midnight_curves::{
    bls12_381::Fp2 as MidnightFp2, Bls12, CurveAffine as MidnightCurveAffine, Fp as MidnightFp, Fq,
    G1Projective, G2Projective,
};
use midnight_proofs::{plonk::VerifyingKey, poly::kzg::KZGCommitmentScheme};

use super::MidnightCommitment;

fn convert_field_repr<S, D>(
    value: S,
    source_label: &str,
    target_label: &str,
    kind: &str,
    invalid_msg: &str,
) -> Result<D>
where
    S: PrimeField,
    D: PrimeField,
{
    let source = value.to_repr();
    let source_bytes: &[u8] = source.as_ref();
    let mut target = <D as PrimeField>::Repr::default();
    let target_bytes = target.as_mut();
    if source_bytes.len() != target_bytes.len() {
        bail!(
            "{kind} encoding length mismatch ({source_label}={}, {target_label}={})",
            source_bytes.len(),
            target_bytes.len()
        );
    }
    target_bytes.copy_from_slice(source_bytes);
    Option::from(D::from_repr(target)).ok_or_else(|| anyhow!("{invalid_msg}"))
}

pub(super) fn normalize_committed_instances(
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

pub(super) fn midnight_fq_to_halo_fr(value: Fq) -> Result<HaloFr> {
    convert_field_repr(
        value,
        "midnight",
        "halo",
        "scalar",
        "invalid scalar encoding when converting midnight::Fq -> halo::Fr",
    )
}

pub(super) fn midnight_g1_to_halo_affine(point: G1Projective) -> Result<HaloG1Affine> {
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

pub(super) fn midnight_g2_to_halo_affine(point: G2Projective) -> Result<HaloG2Affine> {
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

pub(super) fn midnight_fp_to_halo_fq(value: MidnightFp) -> Result<HaloFq> {
    convert_field_repr(
        value,
        "midnight",
        "halo",
        "base-field",
        "invalid base-field encoding during midnight->halo conversion",
    )
}

pub(super) fn midnight_fp2_to_halo_fq2(value: MidnightFp2) -> Result<HaloFq2> {
    Ok(HaloFq2 { c0: midnight_fp_to_halo_fq(value.c0())?, c1: midnight_fp_to_halo_fq(value.c1())? })
}
