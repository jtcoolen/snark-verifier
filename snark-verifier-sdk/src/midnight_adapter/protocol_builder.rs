//! Midnight-to-`snark-verifier` protocol adapter.
//!
//! Midnight proofs do not map 1:1 onto vanilla Halo2 protocol metadata. In
//! particular, Midnight extends transcript and layout semantics with:
//! - committed-instance prefixes,
//! - hashed instance lengths,
//! - trash columns/constraints,
//! - a `z^n / z` quotient chunk base and fixed quotient chunk count.
//!
//! [`MidnightProtocolBuilder`] translates a Midnight verifying key and
//! constraint system into a [`snark_verifier::verifier::plonk::PlonkProtocol`]
//! that preserves those semantics exactly, so the generic verifier and EVM
//! codegen paths parse/query commitments in the same order as Midnight's prover.
//!
//! The builder is intentionally strict: it validates instance-shape assumptions
//! up front to fail fast on layout mismatches.

use anyhow::{bail, Result};
use halo2_base::halo2_proofs::halo2curves::{
    bls12_381::{Fr as HaloFr, G1Affine as HaloG1Affine},
    ff::{Field, PrimeField},
};
use itertools::Itertools;
use midnight_curves::{Bls12, Fq};
use midnight_proofs::plonk::{
    Any, Expression as MidnightExpression, FirstPhase, SecondPhase, ThirdPhase, VerifyingKey,
};
use midnight_proofs::poly::kzg::KZGCommitmentScheme;
use snark_verifier::{
    system::halo2::{
        expression::{
            distribute_powers as halo2_distribute_powers, l_active as halo2_l_active,
            l_blind as halo2_l_blind, l_last as halo2_l_last, rotation_last as halo2_rotation_last,
        },
        layout::{permutation_chunk_count, remap_by_phase},
    },
    util::arithmetic::{Domain, Rotation},
    verifier::plonk::{
        CommonPolynomial, Expression, PlonkProtocol, Query, QuotientChunkBase, QuotientPolynomial,
    },
};

use super::conversions::{midnight_fq_to_halo_fr, midnight_g1_to_halo_affine};

/// Builds a `snark-verifier` PLONK protocol that mirrors Midnight layout rules.
///
/// This struct precomputes indexing/offset metadata so every generated query
/// lands on the same polynomial position Midnight expects during proof parsing.
/// The resulting protocol is consumed by:
/// - native proof parsing/verification paths, and
/// - EVM verifier generation (which replays the same query ordering).
#[derive(Clone, Debug)]
pub(super) struct MidnightProtocolBuilder<'a> {
    vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    cs: &'a midnight_proofs::plonk::ConstraintSystem<Fq>,
    num_instance: Vec<usize>,
    // Number of leading instance columns represented as commitments.
    committed_instance_count: usize,
    num_advice: Vec<usize>,
    num_challenge: Vec<usize>,
    advice_index: Vec<usize>,
    challenge_index: Vec<usize>,
    num_fixed: usize,
    num_permutation_fixed: usize,
    num_lookup_z: usize,
    // Number of trashcan constraints/columns in Midnight layout.
    num_trash: usize,
    permutation_chunk_size: usize,
    num_permutation_z: usize,
}

impl<'a> MidnightProtocolBuilder<'a> {
    /// Collect static layout metadata from Midnight VK/constraint-system.
    ///
    /// `num_instance` must include all instance columns (including committed
    /// placeholder columns). `committed_instance_count` specifies how many
    /// leading instance columns are represented by commitments instead of raw
    /// scalar vectors in the transcript.
    pub(super) fn new(
        vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        num_instance: Vec<usize>,
        committed_instance_count: usize,
    ) -> Self {
        let cs = vk.cs();

        let (num_advice, advice_index) = remap_by_phase(cs.advice_column_phase());
        let (num_challenge, challenge_index) = remap_by_phase(cs.challenge_phase());
        let num_permutation_fixed = cs.permutation().get_columns().len();
        let permutation_chunk_size = cs.degree() - 2;
        let num_permutation_z =
            permutation_chunk_count(num_permutation_fixed, permutation_chunk_size);

        Self {
            vk,
            cs,
            num_instance,
            committed_instance_count,
            num_advice,
            num_challenge,
            advice_index,
            challenge_index,
            num_fixed: cs.num_fixed_columns(),
            num_permutation_fixed,
            num_lookup_z: cs.lookups().len(),
            num_trash: cs.trashcans().len(),
            permutation_chunk_size,
            num_permutation_z,
        }
    }

    /// Build a `PlonkProtocol` with Midnight-specific transcript/layout semantics.
    ///
    /// Key guarantees of the produced protocol:
    /// - query/evaluation ordering matches Midnight transcript parsing order;
    /// - committed-instance prefix handling is explicit in protocol metadata;
    /// - trash witness columns and constraints are included in quotient logic;
    /// - quotient recombination uses `ZnMinusOne` with Midnight's fixed chunk count.
    pub(super) fn build(&self) -> Result<PlonkProtocol<HaloG1Affine>> {
        if self.num_instance.len() != self.cs.num_instance_columns() {
            bail!(
                "instance column mismatch: protocol has {}, provided {}",
                self.cs.num_instance_columns(),
                self.num_instance.len()
            );
        }
        if self.committed_instance_count > self.num_instance.len() {
            bail!(
                "committed instance count {} exceeds total instance columns {}",
                self.committed_instance_count,
                self.num_instance.len()
            );
        }
        let k = self.vk.get_domain().k() as usize;
        let gen = midnight_fq_to_halo_fr(self.vk.get_domain().get_omega())?;
        let domain = Domain::new(k, gen);

        let preprocessed = self
            .vk
            .fixed_commitments()
            .iter()
            .chain(self.vk.permutation().commitments().iter())
            .cloned()
            .map(midnight_g1_to_halo_affine)
            .collect::<Result<Vec<_>>>()?;
        // Committed instance columns are queried as commitments; remaining instance columns are scalar vectors.
        let committed_instance_queries = self.committed_instance_queries();
        let advice_queries = self.advice_queries()?;
        let fixed_queries = self.fixed_queries();

        let evaluations = self
            .committed_instance_queries()
            .into_iter()
            .chain(advice_queries.clone())
            .chain(fixed_queries.clone())
            .chain(self.random_query())
            .chain(self.permutation_fixed_queries())
            .chain(self.permutation_z_queries(true))
            .chain(self.lookup_queries(true))
            // Trash witness columns are read/evaluated like regular witness commitments.
            .chain(self.trash_queries())
            .collect_vec();

        let queries = committed_instance_queries
            .into_iter()
            .chain(advice_queries)
            .chain(self.permutation_z_queries(false))
            .chain(self.lookup_queries(false))
            // Include trash columns in verifier query ordering as well.
            .chain(self.trash_queries())
            .chain(fixed_queries)
            .chain(self.permutation_fixed_queries())
            .chain(Some(self.quotient_query()))
            .chain(self.random_query())
            .collect_vec();

        let quotient = self.quotient()?;

        Ok(PlonkProtocol {
            domain,
            domain_as_witness: None,
            preprocessed,
            num_instance: self.num_instance.clone(),
            num_witness: self.num_witness(),
            num_challenge: self.num_challenge_with_system(),
            // Enable committed-instance and hashed-instance-length transcript semantics.
            committed_instance_count: self.committed_instance_count,
            hash_instance_lengths: true,
            trailing_challenges: 0,
            extra_commitments: 0,
            evaluations,
            queries,
            quotient,
            transcript_initial_state: Some(midnight_fq_to_halo_fr(self.vk.transcript_repr())?),
            instance_committing_key: None,
            linearization: None,
            accumulator_indices: vec![],
        })
    }

    fn num_preprocessed(&self) -> usize {
        self.num_fixed + self.num_permutation_fixed
    }

    fn instance_offset(&self) -> usize {
        self.num_preprocessed()
    }

    fn witness_offset(&self) -> usize {
        self.instance_offset() + self.num_instance.len()
    }

    fn advice_offset(&self) -> usize {
        self.witness_offset()
    }

    fn lookup_permuted_offset(&self) -> usize {
        self.advice_offset() + self.num_advice.iter().sum::<usize>()
    }

    fn perm_lookup_offset(&self) -> usize {
        self.lookup_permuted_offset() + 2 * self.num_lookup_z
    }

    fn trash_random_offset(&self) -> usize {
        self.perm_lookup_offset() + self.num_permutation_z + self.num_lookup_z
    }

    // Random polynomial is placed after all trash witness columns.
    fn random_poly_index(&self) -> usize {
        self.trash_random_offset() + self.num_trash
    }

    fn num_witness(&self) -> Vec<usize> {
        self.num_advice
            .iter()
            .copied()
            .chain([
                2 * self.num_lookup_z,
                self.num_permutation_z + self.num_lookup_z,
                self.num_trash + 1,
            ])
            .collect()
    }

    fn num_challenge_with_system(&self) -> Vec<usize> {
        let mut phase_challenges = self.num_challenge.clone();
        *phase_challenges.last_mut().unwrap() += 1; // theta
                                                    // Add system challenges: beta, gamma, trash_challenge, alpha.
        phase_challenges.into_iter().chain([2, 1, 1]).collect()
    }

    fn system_challenge_offset(&self) -> usize {
        self.num_challenge.iter().sum()
    }

    fn theta(&self) -> Expression<HaloFr> {
        Expression::Challenge(self.system_challenge_offset())
    }

    fn beta(&self) -> Expression<HaloFr> {
            .chain(num_challenge)
            .chain([
                2, // beta, gamma
                1, // alpha
            ])
            .collect()
    }

    fn instance_offset(&self) -> usize {
        self.num_preprocessed()
    }

    fn witness_offset(&self) -> usize {
        self.instance_offset() + self.num_instance().len()
    }

    fn cs_witness_offset(&self) -> usize {
        self.witness_offset() + self.num_witness().iter().take(self.num_advice.len()).sum::<usize>()
    }

    fn query<C: Into<Any> + Copy, R: Into<Rotation>>(
        &self,
        column_type: C,
        mut column_index: usize,
        rotation: R,
        t: usize,
    ) -> Query {
        let offset = match column_type.into() {
            Any::Fixed => 0,
            Any::Instance => self.instance_offset() + t * self.num_instance.len(),
            Any::Advice(advice) => {
                column_index = self.advice_index[column_index];
                let phase_offset = self.num_proof
                    * self.num_advice[..advice.phase() as usize].iter().sum::<usize>();
                self.witness_offset() + phase_offset + t * self.num_advice[advice.phase() as usize]
            }
        };
        Query::new(offset + column_index, rotation.into())
    }

    fn instance_queries(&'a self, t: usize) -> impl IntoIterator<Item = Query> + 'a {
        self.query_instance
            .then(|| {
                self.cs.instance_queries().iter().map(move |(column, rotation)| {
                    self.query(*column.column_type(), column.index(), *rotation, t)
                })
            })
            .into_iter()
            .flatten()
    }

    fn advice_queries(&'a self, t: usize) -> impl IntoIterator<Item = Query> + 'a {
        self.cs.advice_queries().iter().map(move |(column, rotation)| {
            self.query(*column.column_type(), column.index(), *rotation, t)
        })
    }

    fn fixed_queries(&'a self) -> impl IntoIterator<Item = Query> + 'a {
        self.cs.fixed_queries().iter().map(move |(column, rotation)| {
            self.query(*column.column_type(), column.index(), *rotation, 0)
        })
    }

    fn permutation_fixed_queries(&'a self) -> impl IntoIterator<Item = Query> + 'a {
        (0..self.num_permutation_fixed).map(|i| Query::new(self.num_fixed + i, 0))
    }

    fn permutation_poly(&'a self, t: usize, i: usize) -> usize {
        let z_offset = self.cs_witness_offset() + self.num_witness()[self.num_advice.len()];
        z_offset + t * self.num_permutation_z + i
    }

    fn permutation_z_queries<const EVAL: bool>(
        &'a self,
        t: usize,
    ) -> impl IntoIterator<Item = Query> + 'a {
        match (self.zk, EVAL) {
            (true, true) => (0..self.num_permutation_z)
                .flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    iter::empty().chain([Query::new(z, 0), Query::new(z, 1)]).chain(
                        if i == self.num_permutation_z - 1 {
                            None
                        } else {
                            Some(Query::new(z, self.rotation_last()))
                        },
                    )
                })
                .collect_vec(),
            (true, false) => iter::empty()
                .chain((0..self.num_permutation_z).flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    [Query::new(z, 0), Query::new(z, 1)]
                }))
                .chain((0..self.num_permutation_z).rev().skip(1).map(move |i| {
                    let z = self.permutation_poly(t, i);
                    Query::new(z, self.rotation_last())
                }))
                .collect_vec(),
            (false, _) => (0..self.num_permutation_z)
                .flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    [Query::new(z, 0), Query::new(z, 1)]
                })
                .collect_vec(),
        }
    }

    fn lookup_poly(&'a self, t: usize, i: usize) -> (usize, usize, usize) {
        let permuted_offset = self.cs_witness_offset();
        let z_offset = permuted_offset
            + self.num_witness()[self.num_advice.len()]
            + self.num_proof * self.num_permutation_z;
        let z = z_offset + t * self.num_lookup_z + i;
        let permuted_input = permuted_offset + 2 * (t * self.num_lookup_z + i);
        let permuted_table = permuted_input + 1;
        (z, permuted_input, permuted_table)
    }

    fn lookup_queries<const EVAL: bool>(
        &'a self,
        t: usize,
    ) -> impl IntoIterator<Item = Query> + 'a {
        (0..self.num_lookup_z).flat_map(move |i| {
            let (z, permuted_input, permuted_table) = self.lookup_poly(t, i);
            if EVAL {
                [
                    Query::new(z, 0),
                    Query::new(z, 1),
                    Query::new(permuted_input, 0),
                    Query::new(permuted_input, -1),
                    Query::new(permuted_table, 0),
                ]
            } else {
                [
                    Query::new(z, 0),
                    Query::new(permuted_input, 0),
                    Query::new(permuted_table, 0),
                    Query::new(permuted_input, -1),
                    Query::new(z, 1),
                ]
            }
        })
    }

    fn quotient_query(&self) -> Query {
        Query::new(self.witness_offset() + self.num_witness().iter().sum::<usize>(), 0)
    }

    fn random_query(&self) -> Option<Query> {
        self.zk.then(|| {
            Query::new(self.witness_offset() + self.num_witness().iter().sum::<usize>() - 1, 0)
        })
    }

    fn convert(&self, expression: &plonk::Expression<F>, t: usize) -> Expression<F> {
        expression.evaluate(
            &|scalar| Expression::Constant(scalar),
            &|_| unreachable!(),
            &|query| self.query(Any::Fixed, query.column_index(), query.rotation(), t).into(),
            &|query| {
                self.query(
                    match query.phase() {
                        0 => Any::advice_in(FirstPhase),
                        1 => Any::advice_in(SecondPhase),
                        2 => Any::advice_in(ThirdPhase),
                        _ => unreachable!(),
                    },
                    query.column_index(),
                    query.rotation(),
                    t,
                )
                .into()
            },
            &|query| self.query(Any::Instance, query.column_index(), query.rotation(), t).into(),
            &|challenge| {
                let phase_offset =
                    self.num_challenge[..challenge.phase() as usize].iter().sum::<usize>();
                Expression::Challenge(phase_offset + self.challenge_index[challenge.index()])
            },
            &|a| -a,
            &|a, b| a + b,
            &|a, b| a * b,
            &|a, scalar| a * scalar,
        )
    }

    fn gate_constraints(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
        self.cs.gates().iter().flat_map(move |gate| {
            gate.polynomials().iter().map(move |expression| self.convert(expression, t))
        })
    }

    fn rotation_last(&self) -> Rotation {
        halo2_rotation_last(self.cs.blinding_factors())
    }

    fn l_last(&self) -> Expression<F> {
        if self.zk {
            halo2_l_last(self.rotation_last())
        } else {
            Expression::CommonPolynomial(CommonPolynomial::Lagrange(-1))
        }
    }

    fn l_blind(&self) -> Expression<F> {
        halo2_l_blind(self.rotation_last())
    }

    fn l_active(&self) -> Expression<F> {
        halo2_l_active(self.l_last(), self.l_blind())
    }

    fn system_challenge_offset(&self) -> usize {
        self.num_challenge.iter().sum()
    }

    fn theta(&self) -> Expression<F> {
        Expression::Challenge(self.system_challenge_offset())
    }

    fn beta(&self) -> Expression<F> {
        Expression::Challenge(self.system_challenge_offset() + 1)
    }

    fn gamma(&self) -> Expression<F> {
        Expression::Challenge(self.system_challenge_offset() + 2)
    }

    fn alpha(&self) -> Expression<F> {
        Expression::Challenge(self.system_challenge_offset() + 3)
    }

    fn permutation_constraints(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
        let one = &Expression::Constant(F::ONE);
        let l_0 = &Expression::<F>::CommonPolynomial(CommonPolynomial::Lagrange(0));
        let l_last = &self.l_last();
        let l_active = &self.l_active();
        let identity = &Expression::<F>::CommonPolynomial(CommonPolynomial::Identity);
        let beta = &self.beta();
        let gamma = &self.gamma();

        let polys = self
            .cs
            .permutation()
            .get_columns()
            .iter()
            .map(|column| self.query(*column.column_type(), column.index(), 0, t))
            .map(Expression::<F>::Polynomial)
            .collect_vec();
        let permutation_fixeds = (0..self.num_permutation_fixed)
            .map(|i| Query::new(self.num_fixed + i, 0))
            .map(Expression::<F>::Polynomial)
            .collect_vec();
        let zs = (0..self.num_permutation_z)
            .map(|i| {
                let z = self.permutation_poly(t, i);
                (
                    Expression::<F>::Polynomial(Query::new(z, 0)),
                    Expression::<F>::Polynomial(Query::new(z, 1)),
                    Expression::<F>::Polynomial(Query::new(z, self.rotation_last())),
                )
            })
            .collect_vec();

        iter::empty()
            .chain(zs.first().map(|(z_0, _, _)| l_0 * (one - z_0)))
            .chain(zs.last().and_then(|(z_l, _, _)| self.zk.then(|| l_last * (z_l * z_l - z_l))))
            .chain(if self.zk {
                zs.iter()
                    .skip(1)
                    .zip(zs.iter())
                    .map(|((z, _, _), (_, _, z_prev_last))| l_0 * (z - z_prev_last))
                    .collect_vec()
            } else {
                Vec::new()
            })
            .chain(
                zs.iter()
                    .zip(zs.iter().cycle().skip(1))
                    .zip(polys.chunks(self.permutation_chunk_size))
                    .zip(permutation_fixeds.chunks(self.permutation_chunk_size))
                    .enumerate()
                    .map(
                        |(
                            i,
                            ((((z, z_omega, _), (_, z_next_omega, _)), polys), permutation_fixeds),
                        )| {
                            let left = if self.zk || zs.len() == 1 {
                                z_omega.clone()
                            } else {
                                z_omega + l_last * (z_next_omega - z_omega)
                            } * polys
                                .iter()
                                .zip(permutation_fixeds.iter())
                                .map(|(poly, permutation_fixed)| {
                                    poly + beta * permutation_fixed + gamma
                                })
                                .reduce(|acc, expr| acc * expr)
                                .unwrap();
                            let right = z * polys
                                .iter()
                                .zip(
                                    iter::successors(
                                        Some(F::DELTA.pow_vartime([
                                            (i * self.permutation_chunk_size) as u64,
                                        ])),
                                        |delta| Some(F::DELTA * delta),
                                    )
                                    .map(Expression::Constant),
                                )
                                .map(|(poly, delta)| poly + beta * delta * identity + gamma)
                                .reduce(|acc, expr| acc * expr)
                                .unwrap();
                            if self.zk {
                                l_active * (left - right)
                            } else {
                                left - right
                            }
                        },
                    ),
            )
            .collect_vec()
    }

    fn lookup_constraints(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
        let one = &Expression::Constant(F::ONE);
        let l_0 = &Expression::<F>::CommonPolynomial(CommonPolynomial::Lagrange(0));
        let l_last = &self.l_last();
        let l_active = &self.l_active();
        let beta = &self.beta();
        let gamma = &self.gamma();

        let polys = (0..self.num_lookup_z)
            .map(|i| {
                let (z, permuted_input, permuted_table) = self.lookup_poly(t, i);
                (
                    Expression::<F>::Polynomial(Query::new(z, 0)),
                    Expression::<F>::Polynomial(Query::new(z, 1)),
                    Expression::<F>::Polynomial(Query::new(permuted_input, 0)),
                    Expression::<F>::Polynomial(Query::new(permuted_input, -1)),
                    Expression::<F>::Polynomial(Query::new(permuted_table, 0)),
                )
            })
            .collect_vec();

        let compress = |expressions: &'a [plonk::Expression<F>]| {
            halo2_distribute_powers(
                expressions.iter().map(|expression| self.convert(expression, t)).collect(),
                self.theta(),
            )
        };

        self.cs
            .lookups()
            .iter()
            .zip(polys.iter())
            .flat_map(
                |(
                    lookup,
                    (z, z_omega, permuted_input, permuted_input_omega_inv, permuted_table),
                )| {
                    let input = compress(lookup.input_expressions());
                    let table = compress(lookup.table_expressions());
                    iter::empty()
                        .chain(Some(l_0 * (one - z)))
                        .chain(self.zk.then(|| l_last * (z * z - z)))
                        .chain(Some(if self.zk {
                            l_active
                                * (z_omega * (permuted_input + beta) * (permuted_table + gamma)
                                    - z * (input + beta) * (table + gamma))
                        } else {
                            z_omega * (permuted_input + beta) * (permuted_table + gamma)
                                - z * (input + beta) * (table + gamma)
                        }))
                        .chain(self.zk.then(|| l_0 * (permuted_input - permuted_table)))
                        .chain(Some(if self.zk {
                            l_active
                                * (permuted_input - permuted_table)
                                * (permuted_input - permuted_input_omega_inv)
                        } else {
                            (permuted_input - permuted_table)
                                * (permuted_input - permuted_input_omega_inv)
                        }))
                },
            )
            .collect_vec()
    }

    fn quotient(&self) -> QuotientPolynomial<F> {
        let constraints = (0..self.num_proof)
            .flat_map(|t| {
                iter::empty()
                    .chain(self.gate_constraints(t))
                    .chain(self.permutation_constraints(t))
                    .chain(self.lookup_constraints(t))
            })
            .collect_vec();
        let numerator = halo2_distribute_powers(constraints, self.alpha());
        QuotientPolynomial {
            chunk_degree: 1,
            // Halo2's default split base is z^n unless protocol metadata overrides it later.
            chunk_base: crate::verifier::plonk::protocol::QuotientChunkBase::Zn,
            num_chunk_override: None,
            numerator,
        }
    }

    fn accumulator_indices(
        &self,
        accumulator_indices: Vec<(usize, usize)>,
    ) -> Vec<Vec<(usize, usize)>> {
        (0..self.num_proof)
            .map(|t| {
                accumulator_indices
                    .iter()
                    .cloned()
                    .map(|(poly, row)| (poly + t * self.num_instance.len(), row))
                    .collect()
            })
            .collect()
    }
}

struct MockChallenge;

impl<C: CurveAffine> EncodedChallenge<C> for MockChallenge {
    type Input = ();

    fn new(_: &Self::Input) -> Self {
        unreachable!()
    }

    fn get_scalar(&self) -> C::Scalar {
        unreachable!()
    }
}

#[derive(Default)]
struct MockTranscript<F: PrimeField>(F);

impl<C: CurveAffine> Transcript<C, MockChallenge> for MockTranscript<C::Scalar> {
    fn squeeze_challenge(&mut self) -> MockChallenge {
        unreachable!()
    }

    fn common_point(&mut self, _: C) -> io::Result<()> {
        unreachable!()
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.0 = scalar;
        Ok(())
    }
}

/// Returns the transcript initial state of the [VerifyingKey].
/// Roundabout way to do it because [VerifyingKey] doesn't expose the field.
pub fn transcript_initial_state<C: CurveAffine>(vk: &VerifyingKey<C>) -> C::Scalar {
    let mut transcript = MockTranscript::default();
    vk.hash_into(&mut transcript).unwrap();
    transcript.0
}

fn instance_committing_key<'a, C: CurveAffine, P: Params<'a, C>>(
    params: &P,
    len: usize,
) -> InstanceCommittingKey<C> {
    let buf = {
        let mut buf = Vec::new();
        params.write(&mut buf).unwrap();
        buf
    };

    let repr = C::Repr::default();
    let repr_len = repr.as_ref().len();
    let offset = size_of::<u32>() + (1 << params.k()) * repr_len;

    let bases = (offset..)
        .step_by(repr_len)
        .map(|offset| {
            let mut repr = C::Repr::default();
            repr.as_mut().copy_from_slice(&buf[offset..offset + repr_len]);
            C::from_bytes(&repr).unwrap()
        })
        .take(len)
        .collect();

    let w = {
        let offset = size_of::<u32>() + (2 << params.k()) * repr_len;
        let mut repr = C::Repr::default();
        repr.as_mut().copy_from_slice(&buf[offset..offset + repr_len]);
        C::from_bytes(&repr).unwrap()
    };

    InstanceCommittingKey { bases, constant: Some(w) }
}
