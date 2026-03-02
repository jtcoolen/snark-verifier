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
        Expression::Challenge(self.system_challenge_offset() + 1)
    }

    fn gamma(&self) -> Expression<HaloFr> {
        Expression::Challenge(self.system_challenge_offset() + 2)
    }

    // Challenge used to compress each trashcan's constraint vector.
    fn trash_challenge(&self) -> Expression<HaloFr> {
        Expression::Challenge(self.system_challenge_offset() + 3)
    }

    fn alpha(&self) -> Expression<HaloFr> {
        Expression::Challenge(self.system_challenge_offset() + 4)
    }

    fn rotation_last(&self) -> Rotation {
        halo2_rotation_last(self.cs.blinding_factors())
    }

    fn query(
        &self,
        column_type: Any,
        column_index: usize,
        rotation: midnight_proofs::poly::Rotation,
    ) -> Query {
        match column_type {
            Any::Fixed => Query::new(column_index, Rotation(rotation.0)),
            Any::Instance => {
                Query::new(self.instance_offset() + column_index, Rotation(rotation.0))
            }
            Any::Advice(advice) => {
                let phase = advice.phase() as usize;
                let phase_offset = self.num_advice[..phase].iter().sum::<usize>();
                Query::new(
                    self.witness_offset() + phase_offset + self.advice_index[column_index],
                    Rotation(rotation.0),
                )
            }
        }
    }

    fn advice_query_any(phase: u8) -> Result<Any> {
        match phase {
            0 => Ok(Any::advice_in(FirstPhase)),
            1 => Ok(Any::advice_in(SecondPhase)),
            2 => Ok(Any::advice_in(ThirdPhase)),
            _ => bail!("unsupported midnight advice phase {phase}"),
        }
    }

    fn convert_expression(
        &self,
        expression: &MidnightExpression<Fq>,
    ) -> Result<Expression<HaloFr>> {
        match expression {
            MidnightExpression::Constant(scalar) => {
                Ok(Expression::Constant(midnight_fq_to_halo_fr(*scalar)?))
            }
            MidnightExpression::Selector(_) => {
                bail!("unexpected selector in midnight expression (selectors should be fixed)")
            }
            MidnightExpression::Fixed(query) => {
                Ok(self.query(Any::Fixed, query.column_index(), query.rotation()).into())
            }
            MidnightExpression::Advice(query) => {
                let any = Self::advice_query_any(query.phase())?;
                Ok(self.query(any, query.column_index(), query.rotation()).into())
            }
            MidnightExpression::Instance(query) => {
                Ok(self.query(Any::Instance, query.column_index(), query.rotation()).into())
            }
            MidnightExpression::Challenge(challenge) => {
                let phase_offset =
                    self.num_challenge[..challenge.phase() as usize].iter().sum::<usize>();
                Ok(Expression::Challenge(phase_offset + self.challenge_index[challenge.index()]))
            }
            MidnightExpression::Negated(a) => Ok(-self.convert_expression(a)?),
            MidnightExpression::Sum(a, b) => {
                Ok(self.convert_expression(a)? + self.convert_expression(b)?)
            }
            MidnightExpression::Product(a, b) => {
                Ok(self.convert_expression(a)? * self.convert_expression(b)?)
            }
            MidnightExpression::Scaled(a, scalar) => {
                Ok(self.convert_expression(a)? * midnight_fq_to_halo_fr(*scalar)?)
            }
        }
    }

    // Only include instance queries for columns encoded as commitments.
    fn committed_instance_queries(&self) -> Vec<Query> {
        self.cs
            .instance_queries()
            .iter()
            .filter(|(column, _)| column.index() < self.committed_instance_count)
            .map(|(column, rotation)| self.query(Any::Instance, column.index(), *rotation))
            .collect()
    }

    fn advice_queries(&self) -> Result<Vec<Query>> {
        self.cs
            .advice_queries()
            .iter()
            .map(|(column, rotation)| {
                let any = Self::advice_query_any(column.column_type().phase())?;
                Ok(self.query(any, column.index(), *rotation))
            })
            .collect()
    }

    fn fixed_queries(&self) -> Vec<Query> {
        self.cs
            .fixed_queries()
            .iter()
            .map(|(column, rotation)| self.query(Any::Fixed, column.index(), *rotation))
            .collect()
    }

    fn permutation_fixed_queries(&self) -> Vec<Query> {
        (0..self.num_permutation_fixed)
            .map(|i| Query::new(self.num_fixed + i, Rotation(0)))
            .collect()
    }

    fn permutation_poly(&self, i: usize) -> usize {
        self.perm_lookup_offset() + i
    }

    fn permutation_z_queries(&self, eval: bool) -> Vec<Query> {
        if self.num_permutation_z == 0 {
            return vec![];
        }
        if eval {
            (0..self.num_permutation_z)
                .flat_map(|i| {
                    let z = self.permutation_poly(i);
                    let mut queries = vec![Query::new(z, Rotation(0)), Query::new(z, Rotation(1))];
                    if i != self.num_permutation_z - 1 {
                        queries.push(Query::new(z, self.rotation_last()));
                    }
                    queries
                })
                .collect()
        } else {
            (0..self.num_permutation_z)
                .flat_map(|i| {
                    let z = self.permutation_poly(i);
                    vec![Query::new(z, Rotation(0)), Query::new(z, Rotation(1))]
                })
                .chain((0..self.num_permutation_z).rev().skip(1).map(|i| {
                    let z = self.permutation_poly(i);
                    Query::new(z, self.rotation_last())
                }))
                .collect()
        }
    }

    fn lookup_poly(&self, i: usize) -> (usize, usize, usize) {
        let z = self.perm_lookup_offset() + self.num_permutation_z + i;
        let permuted_input = self.lookup_permuted_offset() + 2 * i;
        let permuted_table = permuted_input + 1;
        (z, permuted_input, permuted_table)
    }

    fn lookup_queries(&self, eval: bool) -> Vec<Query> {
        (0..self.num_lookup_z)
            .flat_map(|i| {
                let (z, permuted_input, permuted_table) = self.lookup_poly(i);
                if eval {
                    vec![
                        Query::new(z, Rotation(0)),
                        Query::new(z, Rotation(1)),
                        Query::new(permuted_input, Rotation(0)),
                        Query::new(permuted_input, Rotation(-1)),
                        Query::new(permuted_table, Rotation(0)),
                    ]
                } else {
                    vec![
                        Query::new(z, Rotation(0)),
                        Query::new(permuted_input, Rotation(0)),
                        Query::new(permuted_table, Rotation(0)),
                        Query::new(permuted_input, Rotation(-1)),
                        Query::new(z, Rotation(1)),
                    ]
                }
            })
            .collect()
    }

    fn trash_poly(&self, i: usize) -> usize {
        self.trash_random_offset() + i
    }

    // Query trash witness columns at rotation 0.
    fn trash_queries(&self) -> Vec<Query> {
        (0..self.num_trash).map(|i| Query::new(self.trash_poly(i), Rotation(0))).collect()
    }

    fn random_query(&self) -> Option<Query> {
        Some(Query::new(self.random_poly_index(), Rotation(0)))
    }

    fn quotient_query(&self) -> Query {
        Query::new(self.random_poly_index() + 1, Rotation(0))
    }

    fn l_last(&self) -> Expression<HaloFr> {
        halo2_l_last(self.rotation_last())
    }

    fn l_blind(&self) -> Expression<HaloFr> {
        halo2_l_blind(self.rotation_last())
    }

    fn l_active(&self) -> Expression<HaloFr> {
        halo2_l_active(self.l_last(), self.l_blind())
    }

    fn gate_constraints(&self) -> Result<Vec<Expression<HaloFr>>> {
        self.cs
            .gates()
            .iter()
            .flat_map(|gate| gate.polynomials().iter())
            .map(|expr| self.convert_expression(expr))
            .collect()
    }

    fn permutation_constraints(&self) -> Vec<Expression<HaloFr>> {
        let one = Expression::Constant(HaloFr::ONE);
        let l_0 = Expression::<HaloFr>::CommonPolynomial(CommonPolynomial::Lagrange(0));
        let l_last = self.l_last();
        let l_active = self.l_active();
        let identity = Expression::<HaloFr>::CommonPolynomial(CommonPolynomial::Identity);
        let beta = self.beta();
        let gamma = self.gamma();

        let polys = self
            .cs
            .permutation()
            .get_columns()
            .iter()
            .map(|column| {
                self.query(
                    *column.column_type(),
                    column.index(),
                    midnight_proofs::poly::Rotation(0),
                )
            })
            .map(Expression::<HaloFr>::Polynomial)
            .collect_vec();
        let permutation_fixeds = (0..self.num_permutation_fixed)
            .map(|i| Query::new(self.num_fixed + i, Rotation(0)))
            .map(Expression::<HaloFr>::Polynomial)
            .collect_vec();
        let zs = (0..self.num_permutation_z)
            .map(|i| {
                let z = self.permutation_poly(i);
                (
                    Expression::<HaloFr>::Polynomial(Query::new(z, Rotation(0))),
                    Expression::<HaloFr>::Polynomial(Query::new(z, Rotation(1))),
                    Expression::<HaloFr>::Polynomial(Query::new(z, self.rotation_last())),
                )
            })
            .collect_vec();

        let mut constraints = Vec::new();
        if let Some((z_0, _, _)) = zs.first() {
            constraints.push(&l_0 * (&one - z_0));
        }
        if let Some((z_l, _, _)) = zs.last() {
            constraints.push(&l_last * (z_l * z_l - z_l));
        }

        constraints.extend(
            zs.iter()
                .skip(1)
                .zip(zs.iter())
                .map(|((z, _, _), (_, _, z_prev_last))| &l_0 * (z - z_prev_last)),
        );

        constraints.extend(
            zs.iter()
                .zip(polys.chunks(self.permutation_chunk_size))
                .zip(permutation_fixeds.chunks(self.permutation_chunk_size))
                .enumerate()
                .map(|(i, (((z, z_omega, _), polys), permutation_fixeds))| {
                    let left = z_omega
                        * polys
                            .iter()
                            .zip(permutation_fixeds.iter())
                            .map(|(poly, permutation_fixed)| {
                                poly + &beta * permutation_fixed + &gamma
                            })
                            .reduce(|acc, expr| acc * expr)
                            .unwrap();
                    let right = z * polys
                        .iter()
                        .zip(
                            std::iter::successors(
                                Some(HaloFr::DELTA.pow_vartime(&[
                                    (i * self.permutation_chunk_size) as u64,
                                    0,
                                    0,
                                    0,
                                ])),
                                |delta| Some(HaloFr::DELTA * delta),
                            )
                            .map(Expression::Constant),
                        )
                        .map(|(poly, delta)| poly + &beta * &delta * &identity + &gamma)
                        .reduce(|acc, expr| acc * expr)
                        .unwrap();
                    &l_active * (left - right)
                }),
        );

        constraints
    }

    fn lookup_constraints(&self) -> Result<Vec<Expression<HaloFr>>> {
        let one = Expression::Constant(HaloFr::ONE);
        let l_0 = Expression::<HaloFr>::CommonPolynomial(CommonPolynomial::Lagrange(0));
        let l_last = self.l_last();
        let l_active = self.l_active();
        let beta = self.beta();
        let gamma = self.gamma();

        let polys = (0..self.num_lookup_z)
            .map(|i| {
                let (z, permuted_input, permuted_table) = self.lookup_poly(i);
                (
                    Expression::<HaloFr>::Polynomial(Query::new(z, Rotation(0))),
                    Expression::<HaloFr>::Polynomial(Query::new(z, Rotation(1))),
                    Expression::<HaloFr>::Polynomial(Query::new(permuted_input, Rotation(0))),
                    Expression::<HaloFr>::Polynomial(Query::new(permuted_input, Rotation(-1))),
                    Expression::<HaloFr>::Polynomial(Query::new(permuted_table, Rotation(0))),
                )
            })
            .collect_vec();

        let mut constraints = Vec::new();
        for (lookup, (z, z_omega, permuted_input, permuted_input_omega_inv, permuted_table)) in
            self.cs.lookups().iter().zip(polys.iter())
        {
            let input = self.distribute_powers(
                lookup
                    .input_expressions()
                    .iter()
                    .map(|expr| self.convert_expression(expr))
                    .collect::<Result<Vec<_>>>()?,
                self.theta(),
            );
            let table = self.distribute_powers(
                lookup
                    .table_expressions()
                    .iter()
                    .map(|expr| self.convert_expression(expr))
                    .collect::<Result<Vec<_>>>()?,
                self.theta(),
            );

            constraints.push(&l_0 * (&one - z));
            constraints.push(&l_last * (z * z - z));
            constraints.push(
                &l_active
                    * (z_omega * (permuted_input + &beta) * (permuted_table + &gamma)
                        - z * (input + &beta) * (table + &gamma)),
            );
            constraints.push(&l_0 * (permuted_input - permuted_table));
            constraints.push(
                &l_active
                    * (permuted_input - permuted_table)
                    * (permuted_input - permuted_input_omega_inv),
            );
        }
        Ok(constraints)
    }

    // Translate Midnight trashcan constraints into polynomial equalities.
    fn trash_constraints(&self) -> Result<Vec<Expression<HaloFr>>> {
        self.cs
            .trashcans()
            .iter()
            .enumerate()
            .map(|(i, trash)| {
                let selector = self.convert_expression(trash.selector())?;
                let compressed = self.distribute_powers(
                    trash
                        .constraint_expressions()
                        .iter()
                        .map(|expr| self.convert_expression(expr))
                        .collect::<Result<Vec<_>>>()?,
                    self.trash_challenge(),
                );
                let trash_eval =
                    Expression::Polynomial(Query::new(self.trash_poly(i), Rotation(0)));
                // Selector gates the constraint so it only applies on enabled rows.
                Ok(compressed - (Expression::Constant(HaloFr::ONE) - selector) * trash_eval)
            })
            .collect()
    }

    fn distribute_powers(
        &self,
        expressions: Vec<Expression<HaloFr>>,
        challenge: Expression<HaloFr>,
    ) -> Expression<HaloFr> {
        halo2_distribute_powers(expressions, challenge)
    }

    fn quotient(&self) -> Result<QuotientPolynomial<HaloFr>> {
        let constraints = self
            .gate_constraints()?
            .into_iter()
            .chain(self.permutation_constraints())
            .chain(self.lookup_constraints()?)
            .chain(self.trash_constraints()?)
            .collect_vec();

        Ok(QuotientPolynomial {
            chunk_degree: 1,
            chunk_base: QuotientChunkBase::ZnMinusOne,
            num_chunk_override: Some(self.vk.get_domain().get_quotient_poly_degree()),
            numerator: self.distribute_powers(constraints, self.alpha()),
        })
    }
}

/// Dummy circuit type to satisfy VK deserialization. We don't use params.
#[derive(Clone, Debug)]
pub(super) struct DummyCircuit;

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
