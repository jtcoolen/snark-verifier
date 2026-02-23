#[cfg(feature = "loader_evm")]
use crate::loader::evm::{EcPoint, EvmLoader, Scalar};
use crate::loader::native::NativeLoader;
use crate::{
    cost::{Cost, CostEstimation},
    loader::{LoadedScalar, Loader, ScalarLoader},
    pcs::{
        kzg::{KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey},
        PolynomialCommitmentScheme, Query,
    },
    util::{
        arithmetic::{CurveAffine, MultiMillerLoop, PrimeField, Rotation},
        msm::Msm,
        transcript::TranscriptRead,
        Itertools,
    },
    Error,
};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "loader_evm")]
use std::rc::Rc;

fn truncate_scalar_to_half_bytes<F: PrimeField>(scalar: F) -> F {
    let mut repr = scalar.to_repr();
    let nb_bytes = F::NUM_BITS.div_ceil(8).div_ceil(2) as usize;
    for byte in repr.as_mut().iter_mut().skip(nb_bytes) {
        *byte = 0;
    }
    Option::from(F::from_repr(repr)).expect("truncated scalar must be canonical")
}

trait MidnightTruncatedChallengeOps<C: CurveAffine>: Loader<C> {
    fn truncate_challenge_128(&self, value: &Self::LoadedScalar) -> Self::LoadedScalar;

    fn powers_with_challenge_policy(
        &self,
        base: &Self::LoadedScalar,
        n: usize,
    ) -> Vec<Self::LoadedScalar> {
        #[cfg(not(feature = "truncated-challenges"))]
        {
            return base.powers(n);
        }

        #[cfg(feature = "truncated-challenges")]
        {
        let mut powers = Vec::with_capacity(n);
        let mut power = self.load_one();
        for _ in 0..n {
            powers.push(self.truncate_challenge_128(&power));
            power = power * base;
        }
        powers
        }
    }
}

impl<C> MidnightTruncatedChallengeOps<C> for NativeLoader
where
    C: CurveAffine,
    C::ScalarExt: PrimeField,
{
    fn truncate_challenge_128(&self, value: &Self::LoadedScalar) -> Self::LoadedScalar {
        #[cfg(feature = "truncated-challenges")]
        {
        truncate_scalar_to_half_bytes(*value)
        }
        #[cfg(not(feature = "truncated-challenges"))]
        {
            value.clone()
        }
    }
}

#[cfg(feature = "loader_evm")]
impl<C> MidnightTruncatedChallengeOps<C> for Rc<EvmLoader>
where
    C: CurveAffine,
    C::ScalarExt: PrimeField<Repr = [u8; 32]>,
{
    fn truncate_challenge_128(&self, value: &Self::LoadedScalar) -> Self::LoadedScalar {
        #[cfg(feature = "truncated-challenges")]
        {
        self.truncate_scalar_to_128(value)
        }
        #[cfg(not(feature = "truncated-challenges"))]
        {
            value.clone()
        }
    }
}

/// Verifier of Midnight's KZG multi-open proof format.
///
/// This format differs from halo2's GWC/BDFG encodings and follows the
/// `f_com`, `q_eval_on_x3...`, `pi` layout used in Midnight proofs.
#[derive(Clone, Debug)]
pub struct Midnight;

/// Structured proof of Midnight's KZG multi-open.
#[derive(Clone, Debug)]
pub struct MidnightProof<S, P> {
    x1: S,
    x2: S,
    f_com: P,
    x3: S,
    q_evals_on_x3: Vec<S>,
    x4: S,
    pi: P,
}

impl<M> PolynomialCommitmentScheme<M::G1Affine, NativeLoader> for KzgAs<M, Midnight>
where
    M: MultiMillerLoop,
    M::G1Affine: CurveAffine<ScalarExt = M::Fr, CurveExt = M::G1>,
    M::Fr: PrimeField + Ord,
{
    type VerifyingKey = KzgSuccinctVerifyingKey<M::G1Affine>;
    type Proof = MidnightProof<M::Fr, M::G1Affine>;
    type Output = KzgAccumulator<M::G1Affine, NativeLoader>;

    fn read_proof<T>(
        _: &Self::VerifyingKey,
        queries: &[Query<Rotation>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<M::G1Affine, NativeLoader>,
    {
        read_midnight_proof(queries, transcript)
    }

    fn verify(
        svk: &Self::VerifyingKey,
        commitments: &[Msm<M::G1Affine, NativeLoader>],
        z: &M::Fr,
        queries: &[Query<Rotation, M::Fr>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error> {
        verify_midnight(svk, commitments, z, queries, proof)
    }
}

#[cfg(feature = "loader_evm")]
impl<M> PolynomialCommitmentScheme<M::G1Affine, Rc<EvmLoader>> for KzgAs<M, Midnight>
where
    M: MultiMillerLoop,
    M::G1Affine: CurveAffine<ScalarExt = M::Fr, CurveExt = M::G1>,
    M::Fr: PrimeField<Repr = [u8; 32]> + Ord,
{
    type VerifyingKey = KzgSuccinctVerifyingKey<M::G1Affine>;
    type Proof = MidnightProof<Scalar, EcPoint>;
    type Output = KzgAccumulator<M::G1Affine, Rc<EvmLoader>>;

    fn read_proof<T>(
        _: &Self::VerifyingKey,
        queries: &[Query<Rotation>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<M::G1Affine, Rc<EvmLoader>>,
    {
        read_midnight_proof(queries, transcript)
    }

    fn verify(
        svk: &Self::VerifyingKey,
        commitments: &[Msm<M::G1Affine, Rc<EvmLoader>>],
        z: &Scalar,
        queries: &[Query<Rotation, Scalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error> {
        verify_midnight(svk, commitments, z, queries, proof)
    }
}

fn read_midnight_proof<C, L, T>(
    queries: &[Query<Rotation>],
    transcript: &mut T,
) -> Result<MidnightProof<L::LoadedScalar, L::LoadedEcPoint>, Error>
where
    C: CurveAffine,
    L: Loader<C>,
    T: TranscriptRead<C, L>,
{
    let (_, point_sets) = construct_intermediate_sets(queries)?;
    let x1 = transcript.squeeze_challenge();
    let x2 = transcript.squeeze_challenge();
    let f_com = transcript.read_ec_point()?;
    let x3 = transcript.squeeze_challenge();
    let q_evals_on_x3 = transcript.read_n_scalars(point_sets.len())?;
    let x4 = transcript.squeeze_challenge();
    let pi = transcript.read_ec_point()?;
    Ok(MidnightProof { x1, x2, f_com, x3, q_evals_on_x3, x4, pi })
}

fn verify_midnight<C, L>(
    svk: &KzgSuccinctVerifyingKey<C>,
    commitments: &[Msm<C, L>],
    z: &L::LoadedScalar,
    queries: &[Query<Rotation, L::LoadedScalar>],
    proof: &MidnightProof<L::LoadedScalar, L::LoadedEcPoint>,
) -> Result<KzgAccumulator<C, L>, Error>
where
    C: CurveAffine,
    L: Loader<C> + MidnightTruncatedChallengeOps<C>,
{
    let (commitment_map, point_sets) = construct_intermediate_sets(queries)?;
    if point_sets.len() != proof.q_evals_on_x3.len() {
        return Err(Error::InvalidProtocol(format!(
            "midnight pcs point-set mismatch: expected {}, got {}",
            point_sets.len(),
            proof.q_evals_on_x3.len()
        )));
    }

    let loader = z.loader().clone();
    let shift_points =
        queries.iter().map(|query| (query.shift, z.clone() * &query.loaded_shift)).collect_vec();

    let mut q_coms: Vec<Vec<Msm<C, L>>> = vec![Vec::new(); point_sets.len()];
    let mut q_eval_sets: Vec<Vec<Vec<L::LoadedScalar>>> = vec![Vec::new(); point_sets.len()];
    for com_data in commitment_map.iter() {
        if com_data.poly >= commitments.len() {
            return Err(Error::InvalidProtocol(format!(
                "query references polynomial {}, but commitments has length {}",
                com_data.poly,
                commitments.len()
            )));
        }
        let shifts = &point_sets[com_data.set_index];
        let evals = shifts
            .iter()
            .map(|shift| {
                queries
                    .iter()
                    .find(|query| query.poly == com_data.poly && query.shift == *shift)
                    .map(|query| query.eval.clone())
                    .ok_or_else(|| {
                        Error::InvalidProtocol(format!(
                            "missing evaluation for (poly={}, shift={})",
                            com_data.poly, shift.0
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        q_coms[com_data.set_index].push(commitments[com_data.poly].clone());
        q_eval_sets[com_data.set_index].push(evals);
    }

    let num_x1_powers = q_coms.iter().map(|set| set.len()).max().unwrap_or_default();
    let powers_x1 = loader.powers_with_challenge_policy(&proof.x1, num_x1_powers);
    let q_coms = q_coms
        .into_iter()
        .map(|msms| {
            msms.into_iter()
                .zip(powers_x1.iter())
                .map(|(msm, scalar)| msm * scalar)
                .sum::<Msm<_, _>>()
        })
        .collect_vec();
    let q_eval_sets = q_eval_sets
        .into_iter()
        .map(|eval_set| evals_inner_product_loaded::<C, L>(&eval_set, &powers_x1, &loader))
        .collect_vec();

    // Reconstruct f(x3) from q-evals and point sets.
    // Batch all interpolation and final-round denominators into one inversion pass.
    #[cfg(feature = "truncated-challenges")]
    let x3 = loader.truncate_challenge_128(&proof.x3);
    #[cfg(not(feature = "truncated-challenges"))]
    let x3 = proof.x3.clone();

    struct InterpTerm<S> {
        proof_eval: S,
        evals: Vec<S>,
        den: S,
        lagrange_start: usize,
        diff_start: usize,
        has_lagrange: bool,
        den_idx: usize,
    }

    let mut f_eval_terms = Vec::<InterpTerm<L::LoadedScalar>>::with_capacity(point_sets.len());
    let mut den_pool = Vec::<L::LoadedScalar>::new();
    for ((shifts, evals), proof_eval) in
        point_sets.iter().zip(q_eval_sets.iter()).zip(proof.q_evals_on_x3.iter()).rev()
    {
        let points = shifts
            .iter()
            .map(|shift| {
                shift_points
                    .iter()
                    .find(|(candidate, _)| candidate == shift)
                    .map(|(_, point)| point.clone())
                    .ok_or_else(|| {
                        Error::InvalidProtocol(format!("missing query point for shift {}", shift.0))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if points.len() != evals.len() {
            return Err(Error::InvalidProtocol(format!(
                "lagrange interpolation size mismatch: points={}, evals={}",
                points.len(),
                evals.len()
            )));
        }

        let lagrange_start = den_pool.len();
        let has_lagrange = points.len() > 1;
        if has_lagrange {
            den_pool.extend((0..points.len()).map(|j| {
                points
                    .iter()
                    .enumerate()
                    .filter(|(k, _)| *k != j)
                    .fold(loader.load_one(), |acc, (_, x_k)| acc * &(points[j].clone() - x_k))
            }));
        }

        let diff_start = den_pool.len();
        let diffs = points.iter().map(|point| x3.clone() - point).collect_vec();
        den_pool.extend(diffs.iter().cloned());
        let den = diffs.into_iter().fold(loader.load_one(), |acc, diff| acc * &diff);

        let den_idx = den_pool.len();
        den_pool.push(den.clone());

        f_eval_terms.push(InterpTerm {
            proof_eval: proof_eval.clone(),
            evals: evals.clone(),
            den,
            lagrange_start,
            diff_start,
            has_lagrange,
            den_idx,
        });
    }

    if !den_pool.is_empty() {
        <L as ScalarLoader<C::ScalarExt>>::batch_invert(den_pool.iter_mut());
    }

    let mut f_eval = loader.load_zero();
    for term in f_eval_terms {
        let r_eval = if term.evals.is_empty() {
            loader.load_zero()
        } else {
            term.evals.iter().enumerate().fold(loader.load_zero(), |acc, (j, eval)| {
                let mut basis = term.den.clone() * &den_pool[term.diff_start + j];
                if term.has_lagrange {
                    basis *= &den_pool[term.lagrange_start + j];
                }
                acc + eval.clone() * &basis
            })
        };

        let eval = (term.proof_eval - r_eval) * &den_pool[term.den_idx];
        f_eval = f_eval * &proof.x2 + &eval;
    }

    let powers_x4 =
        loader.powers_with_challenge_policy(&proof.x4, proof.q_evals_on_x3.len() + 1);
    let final_com = q_coms
        .into_iter()
        .chain(std::iter::once(Msm::base(&proof.f_com)))
        .zip(powers_x4.iter())
        .map(|(msm, scalar)| msm * scalar)
        .sum::<Msm<_, _>>();
    let v = proof
        .q_evals_on_x3
        .iter()
        .cloned()
        .chain(std::iter::once(f_eval))
        .zip(powers_x4.into_iter())
        .fold(loader.load_zero(), |acc, (eval, pow)| acc + eval * &pow);

    // Midnight verifies: e(pi, s_g2) * e(final_com + x3*pi - v*g, -g2) == 1.
    // snark-verifier accumulator convention is:
    //   e(lhs, g2) * e(rhs, -s_g2) == 1
    // so map lhs <- right term, rhs <- left term.
    let rhs = Msm::base(&proof.pi);
    let lhs = final_com + rhs.clone() * &x3 - Msm::constant(v);
    Ok(KzgAccumulator::new(lhs.evaluate(Some(svk.g)), rhs.evaluate(Some(svk.g))))
}

#[derive(Clone, Debug)]
struct CommitmentData {
    poly: usize,
    set_index: usize,
    point_indices: Vec<usize>,
}

fn construct_intermediate_sets<T>(
    queries: &[Query<Rotation, T>],
) -> Result<(Vec<CommitmentData>, Vec<Vec<Rotation>>), Error> {
    let mut commitment_map: Vec<CommitmentData> = Vec::new();
    let mut points = Vec::<Rotation>::new();

    for query in queries {
        let point_idx =
            points.iter().position(|point| *point == query.shift).unwrap_or_else(|| {
                points.push(query.shift);
                points.len() - 1
            });

        if let Some(pos) = commitment_map.iter().position(|com| com.poly == query.poly) {
            if commitment_map[pos].point_indices.contains(&point_idx) {
                return Err(Error::InvalidProtocol(format!(
                    "duplicated query for poly {} at shift {}",
                    query.poly, query.shift.0
                )));
            }
            commitment_map[pos].point_indices.push(point_idx);
        } else {
            commitment_map.push(CommitmentData {
                poly: query.poly,
                set_index: 0,
                point_indices: vec![point_idx],
            });
        }
    }

    let mut point_idx_sets = BTreeMap::<BTreeSet<usize>, usize>::new();
    for com_data in commitment_map.iter_mut() {
        let point_set = BTreeSet::from_iter(com_data.point_indices.iter().copied());
        let num_sets = point_idx_sets.len();
        let set_index = *point_idx_sets.entry(point_set).or_insert(num_sets);
        com_data.set_index = set_index;
    }

    let mut point_sets = vec![Vec::new(); point_idx_sets.len()];
    for (point_set, set_index) in point_idx_sets.into_iter() {
        point_sets[set_index] = point_set.into_iter().map(|idx| points[idx]).collect();
    }

    Ok((commitment_map, point_sets))
}

fn evals_inner_product_loaded<C, L>(
    evals_set: &[Vec<L::LoadedScalar>],
    scalars: &[L::LoadedScalar],
    loader: &L,
) -> Vec<L::LoadedScalar>
where
    C: CurveAffine,
    L: Loader<C>,
{
    if evals_set.is_empty() {
        return Vec::new();
    }
    let mut result = vec![loader.load_zero(); evals_set[0].len()];
    for (poly_evals, scalar) in evals_set.iter().zip(scalars.iter()) {
        for (acc, eval) in result.iter_mut().zip(poly_evals.iter()) {
            *acc += &(eval.clone() * scalar);
        }
    }
    result
}

impl<M> CostEstimation<M::G1Affine> for KzgAs<M, Midnight>
where
    M: MultiMillerLoop,
{
    type Input = Vec<Query<Rotation>>;

    fn estimate_cost(queries: &Vec<Query<Rotation>>) -> Cost {
        let (_, point_sets) = construct_intermediate_sets(queries).unwrap_or_default();
        let num_commitment = point_sets.len() + 2; // f_com and pi are extra points in proof.
        Cost {
            num_commitment,
            num_evaluation: point_sets.len(),
            num_msm: point_sets.len() + 2,
            ..Default::default()
        }
    }
}
