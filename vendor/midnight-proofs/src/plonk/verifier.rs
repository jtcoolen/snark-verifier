use std::{hash::Hash, iter};

use ff::{FromUniformBytes, WithSmallOrderMulGroup};

use super::{vanishing, Error, VerifyingKey};
use crate::{
    plonk::traces::VerifierTrace,
    poly::{commitment::PolynomialCommitmentScheme, VerifierQuery},
    transcript::{read_n, Hashable, Sampleable, Transcript},
    utils::arithmetic::compute_inner_product,
};

/// Given a plonk proof, this function parses it to extract the verifying trace.
/// This function computes all Fiat-Shamir challenges, with the exception of
/// `x`, which is computed in [verify_algebraic_constraints]
pub fn parse_trace<F, CS, T>(
    vk: &VerifyingKey<F, CS>,
    // Unlike the prover, the verifier gets their instances in two arguments:
    // committed and normal (non-committed). Note that the total number of
    // instance columns is expected to be the sum of committed instances and
    // normal instances for every proof. (Committed instances go first, that is,
    // the first instance columns are devoted to committed instances.)
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<VerifierTrace<F, CS>, Error>
where
    CS: PolynomialCommitmentScheme<F>,
    T: Transcript,
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Ord,
    CS::Commitment: Hashable<T::Hash>,
{
    #[cfg(not(feature = "committed-instances"))]
    let committed_instances: Vec<Vec<CS::Commitment>> = vec![vec![]; instances.len()];

    if committed_instances.is_empty() {
        return Err(Error::InvalidInstances);
    }

    let nb_committed_instances = committed_instances[0].len();
    for committed_instances in committed_instances.iter() {
        if committed_instances.len() != nb_committed_instances {
            return Err(Error::InvalidInstances);
        }
    }

    // Check that instances matches the expected number of instance columns
    for (committed_instances, instances) in committed_instances.iter().zip(instances.iter()) {
        if committed_instances.len() + instances.len() != vk.cs.num_instance_columns {
            return Err(Error::InvalidInstances);
        }
    }

    let num_proofs = instances.len();

    // Hash verification key into transcript
    vk.hash_into(transcript)?;

    for committed_instances in committed_instances.iter() {
        for commitment in committed_instances.iter() {
            transcript.common(commitment)?
        }
    }

    for instance in instances.iter() {
        for instance in instance.iter() {
            transcript.common(&F::from_u128(instance.len() as u128))?;
            for value in instance.iter() {
                transcript.common(value)?;
            }
        }
    }

    // Hash the prover's advice commitments into the transcript and squeeze
    // challenges
    let (advice_commitments, challenges) = {
        let mut advice_commitments =
            vec![vec![CS::Commitment::default(); vk.cs.num_advice_columns]; num_proofs];
        let mut challenges = vec![F::ZERO; vk.cs.num_challenges];

        for current_phase in vk.cs.phases() {
            for advice_commitments in advice_commitments.iter_mut() {
                for (phase, commitment) in
                    vk.cs.advice_column_phase.iter().zip(advice_commitments.iter_mut())
                {
                    if current_phase == *phase {
                        *commitment = transcript.read()?;
                    }
                }
            }
            for (phase, challenge) in vk.cs.challenge_phase.iter().zip(challenges.iter_mut()) {
                if current_phase == *phase {
                    *challenge = transcript.squeeze_challenge();
                }
            }
        }

        (advice_commitments, challenges)
    };

    // Sample theta challenge for keeping lookup columns linearly independent
    let theta: F = transcript.squeeze_challenge();

    let lookups_permuted = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> {
            // Hash each lookup permuted commitment
            vk.cs
                .lookups
                .iter()
                .map(|argument| argument.read_permuted_commitments(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sample beta challenge
    let beta: F = transcript.squeeze_challenge();

    // Sample gamma challenge
    let gamma: F = transcript.squeeze_challenge();

    let permutations_committed = (0..num_proofs)
        .map(|_| {
            // Hash each permutation product commitment
            vk.cs.permutation.read_product_commitments(vk, transcript)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let lookups_committed = lookups_permuted
        .into_iter()
        .map(|lookups| {
            // Hash each lookup product commitment
            lookups
                .into_iter()
                .map(|lookup| lookup.read_product_commitment(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let trash_challenge: F = transcript.squeeze_challenge();

    let trashcans_committed = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> {
            vk.cs
                .trashcans
                .iter()
                .map(|argument| argument.read_committed::<CS, _>(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let vanishing = vanishing::Argument::read_commitments_before_y(transcript)?;

    // Sample y challenge, which keeps the gates linearly independent.
    let y: F = transcript.squeeze_challenge();

    Ok(VerifierTrace {
        advice_commitments,
        vanishing,
        lookups: lookups_committed,
        trashcans: trashcans_committed,
        permutations: permutations_committed,
        challenges,
        beta,
        gamma,
        theta,
        trash_challenge,
        y,
    })
}

/// Given a VerifierTrace, this function computes the opening challenge, x,
/// and proceeds to verify the algebraic constraints with the claimed
/// evaluations. This function does not verify the PCS proof.
///
/// The verifier will error if there are trailing bits in the transcript.
pub fn verify_algebraic_constraints<F, CS: PolynomialCommitmentScheme<F>, T: Transcript>(
    vk: &VerifyingKey<F, CS>,
    trace: VerifierTrace<F, CS>,
    // Unlike the prover, the verifier gets their instances in two arguments:
    // committed and normal (non-committed). Note that the total number of
    // instance columns is expected to be the sum of committed instances and
    // normal instances for every proof. (Committed instances go first, that is,
    // the first instance columns are devoted to committed instances.)
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<CS::VerificationGuard, Error>
where
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Hash
        + Ord,
    CS::Commitment: Hashable<T::Hash>,
{
    #[cfg(not(feature = "committed-instances"))]
    let committed_instances: Vec<Vec<CS::Commitment>> = vec![vec![]; instances.len()];

    if committed_instances.is_empty() {
        return Err(Error::InvalidInstances);
    }

    let nb_committed_instances = committed_instances[0].len();
    let num_proofs = instances.len();

    let VerifierTrace {
        advice_commitments,
        vanishing,
        lookups,
        trashcans,
        permutations,
        challenges,
        beta,
        gamma,
        theta,
        trash_challenge,
        y,
    } = trace;

    let vanishing = vanishing.read_commitments_after_y(vk, transcript)?;

    // Sample x challenge, which is used to ensure the circuit is
    // satisfied with high probability.
    let x: F = transcript.squeeze_challenge();
    let xn = x.pow_vartime([vk.n()]);

    let instance_evals = {
        let (min_rotation, max_rotation) =
            vk.cs.instance_queries.iter().fold((0, 0), |(min, max), (_, rotation)| {
                if rotation.0 < min {
                    (rotation.0, max)
                } else if rotation.0 > max {
                    (min, rotation.0)
                } else {
                    (min, max)
                }
            });
        let max_instance_len = instances
            .iter()
            .flat_map(|instance| instance.iter().map(|instance| instance.len()))
            .max_by(Ord::cmp)
            .unwrap_or_default();
        let l_i_s = &vk.domain.l_i_range(
            x,
            xn,
            -max_rotation..max_instance_len as i32 + min_rotation.abs(),
        );
        instances
            .iter()
            .map(|instances| {
                vk.cs
                    .instance_queries
                    .iter()
                    .map(|(column, rotation)| {
                        if column.index() < nb_committed_instances {
                            transcript.read()
                        } else {
                            let instances = instances[column.index() - nb_committed_instances];
                            let offset = (max_rotation - rotation.0) as usize;
                            Ok(compute_inner_product(
                                instances,
                                &l_i_s[offset..offset + instances.len()],
                            ))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    let advice_evals = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> { read_n(transcript, vk.cs.advice_queries.len()) })
        .collect::<Result<Vec<_>, _>>()?;

    let fixed_evals = read_n(transcript, vk.cs.fixed_queries.len())?;
    let vanishing = vanishing.evaluate_after_x(transcript)?;

    let permutations_common = vk.permutation.evaluate(transcript)?;

    let permutations_evaluated = permutations
        .into_iter()
        .map(|permutation| permutation.evaluate(transcript))
        .collect::<Result<Vec<_>, _>>()?;

    let lookups_evaluated = lookups
        .into_iter()
        .map(|lookups| -> Result<Vec<_>, _> {
            lookups
                .into_iter()
                .map(|lookup| lookup.evaluate(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let trashcans_evaluated = trashcans
        .into_iter()
        .map(|trashcans| -> Result<Vec<_>, _> {
            trashcans
                .into_iter()
                .map(|trash| trash.evaluate(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // This check ensures the circuit is satisfied so long as the polynomial
    // commitments open to the correct values.
    let vanishing = {
        let blinding_factors = vk.cs.blinding_factors();
        let l_evals = vk.domain.l_i_range(x, xn, (-((blinding_factors + 1) as i32))..=0);
        assert_eq!(l_evals.len(), 2 + blinding_factors);
        let l_last = l_evals[0];
        let l_blind: F =
            l_evals[1..(1 + blinding_factors)].iter().fold(F::ZERO, |acc, eval| acc + eval);
        let l_0 = l_evals[1 + blinding_factors];

        // Compute the expected value of h(x)
        let expressions = advice_evals
            .iter()
            .zip(instance_evals.iter())
            .zip(permutations_evaluated.iter())
            .zip(lookups_evaluated.iter())
            .zip(trashcans_evaluated.iter())
            .flat_map(
                |((((advice_evals, instance_evals), permutation), lookups), trash)| {
                    let challenges = &challenges;
                    let fixed_evals = &fixed_evals;
                    iter::empty()
                        // Evaluate the circuit using the custom gates provided
                        .chain(vk.cs.gates.iter().flat_map(move |gate| {
                            gate.polynomials().iter().map(move |poly| {
                                poly.evaluate(
                                    &|scalar| scalar,
                                    &|_| {
                                        panic!("virtual selectors are removed during optimization")
                                    },
                                    &|query| fixed_evals[query.index.unwrap()],
                                    &|query| advice_evals[query.index.unwrap()],
                                    &|query| instance_evals[query.index.unwrap()],
                                    &|challenge| challenges[challenge.index()],
                                    &|a| -a,
                                    &|a, b| a + &b,
                                    &|a, b| a * &b,
                                    &|a, scalar| a * &scalar,
                                )
                            })
                        }))
                        .chain(permutation.expressions(
                            vk,
                            &vk.cs.permutation,
                            &permutations_common,
                            advice_evals,
                            fixed_evals,
                            instance_evals,
                            l_0,
                            l_last,
                            l_blind,
                            beta,
                            gamma,
                            x,
                        ))
                        .chain(lookups.iter().zip(vk.cs.lookups.iter()).flat_map(
                            move |(p, argument)| {
                                p.expressions(
                                    l_0,
                                    l_last,
                                    l_blind,
                                    argument,
                                    theta,
                                    beta,
                                    gamma,
                                    advice_evals,
                                    fixed_evals,
                                    instance_evals,
                                    challenges,
                                )
                            },
                        ))
                        .chain(trash.iter().zip(vk.cs.trashcans.iter()).flat_map(
                            move |(p, argument)| {
                                p.expressions(
                                    argument,
                                    trash_challenge,
                                    advice_evals,
                                    fixed_evals,
                                    instance_evals,
                                    challenges,
                                )
                            },
                        ))
                },
            );

        vanishing.verify(expressions, y, xn)
    };

    let queries = committed_instances
        .iter()
        .zip(instance_evals.iter())
        .zip(advice_commitments.iter())
        .zip(advice_evals.iter())
        .zip(permutations_evaluated.iter())
        .zip(lookups_evaluated.iter())
        .zip(trashcans_evaluated.iter())
        .flat_map(
            |(
                (
                    (
                        (((committed_instances, instance_evals), advice_commitments), advice_evals),
                        permutation,
                    ),
                    lookups,
                ),
                trash,
            )| {
                iter::empty()
                    .chain(vk.cs.instance_queries.iter().enumerate().filter_map(
                        move |(query_index, &(column, at))| {
                            if column.index() < nb_committed_instances {
                                Some(VerifierQuery::new(
                                    vk.domain.rotate_omega(x, at),
                                    &committed_instances[column.index()],
                                    instance_evals[query_index],
                                ))
                            } else {
                                None
                            }
                        },
                    ))
                    .chain(vk.cs.advice_queries.iter().enumerate().map(
                        move |(query_index, &(column, at))| {
                            VerifierQuery::new(
                                vk.domain.rotate_omega(x, at),
                                &advice_commitments[column.index()],
                                advice_evals[query_index],
                            )
                        },
                    ))
                    .chain(permutation.queries(vk, x))
                    .chain(lookups.iter().flat_map(move |p| p.queries(vk, x)))
                    .chain(trash.iter().flat_map(move |p| p.queries(x)))
            },
        )
        .chain(
            vk.cs.fixed_queries.iter().enumerate().map(|(query_index, &(column, at))| {
                VerifierQuery::new(
                    vk.domain.rotate_omega(x, at),
                    &vk.fixed_commitments[column.index()],
                    fixed_evals[query_index],
                )
            }),
        )
        .chain(permutations_common.queries(&vk.permutation, x))
        .chain(vanishing.queries(x, vk.n()))
        .collect::<Vec<_>>();

    // We are now convinced the circuit is satisfied so long as the
    // polynomial commitments open to the correct values.
    CS::multi_prepare(&queries, transcript).map_err(|_| Error::Opening)
}

#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct VerifierAlgebraicTrace<F: WithSmallOrderMulGroup<3>, CS: PolynomialCommitmentScheme<F>> {
    pub parsed_trace: VerifierTrace<F, CS>,
    pub nb_committed_instances: usize,
    pub instance_query_columns: Vec<usize>,
    pub vanishing_after_y: vanishing::verifier::Constructed<F, CS>,
    pub x: F,
    pub xn: F,
    pub instance_evals: Vec<Vec<F>>,
    pub advice_evals: Vec<Vec<F>>,
    pub fixed_evals: Vec<F>,
    pub vanishing_evaluated: vanishing::verifier::Evaluated<F, CS>,
    pub permutations_common: super::permutation::verifier::CommonEvaluated<F>,
    pub permutations_evaluated: Vec<super::permutation::verifier::Evaluated<F, CS>>,
    pub lookups_evaluated: Vec<Vec<super::lookup::verifier::Evaluated<F, CS>>>,
    pub trashcans_evaluated: Vec<Vec<super::trash::verifier::Evaluated<F, CS>>>,
    pub l_last: F,
    pub l_blind: F,
    pub l_0: F,
    pub query_count: usize,
}

/// Same as [`prepare`] but also returns the verifier's intermediate variables.
pub fn prepare_with_trace<F, CS: PolynomialCommitmentScheme<F>, T: Transcript>(
    vk: &VerifyingKey<F, CS>,
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<(CS::VerificationGuard, VerifierAlgebraicTrace<F, CS>), Error>
where
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Hash
        + Ord,
    CS::Commitment: Hashable<T::Hash> + Clone,
{
    let trace = parse_trace(
        vk,
        #[cfg(feature = "committed-instances")]
        committed_instances,
        instances,
        transcript,
    )?;

    verify_algebraic_constraints_with_trace(
        vk,
        trace,
        #[cfg(feature = "committed-instances")]
        committed_instances,
        instances,
        transcript,
    )
}

fn verify_algebraic_constraints_with_trace<F, CS: PolynomialCommitmentScheme<F>, T: Transcript>(
    vk: &VerifyingKey<F, CS>,
    trace: VerifierTrace<F, CS>,
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<(CS::VerificationGuard, VerifierAlgebraicTrace<F, CS>), Error>
where
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Hash
        + Ord,
    CS::Commitment: Hashable<T::Hash> + Clone,
{
    #[cfg(not(feature = "committed-instances"))]
    let committed_instances: Vec<Vec<CS::Commitment>> = vec![vec![]; instances.len()];

    if committed_instances.is_empty() {
        return Err(Error::InvalidInstances);
    }

    let nb_committed_instances = committed_instances[0].len();
    let num_proofs = instances.len();
    let parsed_trace = trace.clone();
    let instance_query_columns =
        vk.cs.instance_queries.iter().map(|(column, _)| column.index()).collect::<Vec<_>>();

    let VerifierTrace {
        advice_commitments,
        vanishing,
        lookups,
        trashcans,
        permutations,
        challenges,
        beta,
        gamma,
        theta,
        trash_challenge,
        y,
    } = trace;

    let vanishing_after_y = vanishing.read_commitments_after_y(vk, transcript)?;
    let vanishing_after_y_for_trace = vanishing_after_y.clone();

    let x: F = transcript.squeeze_challenge();
    let xn = x.pow_vartime([vk.n()]);

    let instance_evals = {
        let (min_rotation, max_rotation) =
            vk.cs.instance_queries.iter().fold((0, 0), |(min, max), (_, rotation)| {
                if rotation.0 < min {
                    (rotation.0, max)
                } else if rotation.0 > max {
                    (min, rotation.0)
                } else {
                    (min, max)
                }
            });
        let max_instance_len = instances
            .iter()
            .flat_map(|instance| instance.iter().map(|instance| instance.len()))
            .max_by(Ord::cmp)
            .unwrap_or_default();
        let l_i_s = &vk.domain.l_i_range(
            x,
            xn,
            -max_rotation..max_instance_len as i32 + min_rotation.abs(),
        );
        instances
            .iter()
            .map(|instances| {
                vk.cs
                    .instance_queries
                    .iter()
                    .map(|(column, rotation)| {
                        if column.index() < nb_committed_instances {
                            transcript.read()
                        } else {
                            let instances = instances[column.index() - nb_committed_instances];
                            let offset = (max_rotation - rotation.0) as usize;
                            Ok(compute_inner_product(
                                instances,
                                &l_i_s[offset..offset + instances.len()],
                            ))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    let advice_evals = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> { read_n(transcript, vk.cs.advice_queries.len()) })
        .collect::<Result<Vec<_>, _>>()?;

    let fixed_evals = read_n(transcript, vk.cs.fixed_queries.len())?;
    let vanishing = vanishing_after_y.evaluate_after_x(transcript)?;

    let permutations_common = vk.permutation.evaluate(transcript)?;
    let permutations_common_for_trace = permutations_common.clone();

    let permutations_evaluated = permutations
        .into_iter()
        .map(|permutation| permutation.evaluate(transcript))
        .collect::<Result<Vec<_>, _>>()?;
    let permutations_evaluated_for_trace = permutations_evaluated.clone();

    let lookups_evaluated = lookups
        .into_iter()
        .map(|lookups| -> Result<Vec<_>, _> {
            lookups
                .into_iter()
                .map(|lookup| lookup.evaluate(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let lookups_evaluated_for_trace = lookups_evaluated.clone();

    let trashcans_evaluated = trashcans
        .into_iter()
        .map(|trashcans| -> Result<Vec<_>, _> {
            trashcans
                .into_iter()
                .map(|trash| trash.evaluate(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trashcans_evaluated_for_trace = trashcans_evaluated.clone();

    let (vanishing, l_last, l_blind, l_0) = {
        let blinding_factors = vk.cs.blinding_factors();
        let l_evals = vk.domain.l_i_range(x, xn, (-((blinding_factors + 1) as i32))..=0);
        assert_eq!(l_evals.len(), 2 + blinding_factors);
        let l_last = l_evals[0];
        let l_blind: F =
            l_evals[1..(1 + blinding_factors)].iter().fold(F::ZERO, |acc, eval| acc + eval);
        let l_0 = l_evals[1 + blinding_factors];

        let expressions = advice_evals
            .iter()
            .zip(instance_evals.iter())
            .zip(permutations_evaluated.iter())
            .zip(lookups_evaluated.iter())
            .zip(trashcans_evaluated.iter())
            .flat_map(
                |((((advice_evals, instance_evals), permutation), lookups), trash)| {
                    let challenges = &challenges;
                    let fixed_evals = &fixed_evals;
                    iter::empty()
                        .chain(vk.cs.gates.iter().flat_map(move |gate| {
                            gate.polynomials().iter().map(move |poly| {
                                poly.evaluate(
                                    &|scalar| scalar,
                                    &|_| {
                                        panic!("virtual selectors are removed during optimization")
                                    },
                                    &|query| fixed_evals[query.index.unwrap()],
                                    &|query| advice_evals[query.index.unwrap()],
                                    &|query| instance_evals[query.index.unwrap()],
                                    &|challenge| challenges[challenge.index()],
                                    &|a| -a,
                                    &|a, b| a + &b,
                                    &|a, b| a * &b,
                                    &|a, scalar| a * &scalar,
                                )
                            })
                        }))
                        .chain(permutation.expressions(
                            vk,
                            &vk.cs.permutation,
                            &permutations_common,
                            advice_evals,
                            fixed_evals,
                            instance_evals,
                            l_0,
                            l_last,
                            l_blind,
                            beta,
                            gamma,
                            x,
                        ))
                        .chain(lookups.iter().zip(vk.cs.lookups.iter()).flat_map(
                            move |(p, argument)| {
                                p.expressions(
                                    l_0,
                                    l_last,
                                    l_blind,
                                    argument,
                                    theta,
                                    beta,
                                    gamma,
                                    advice_evals,
                                    fixed_evals,
                                    instance_evals,
                                    challenges,
                                )
                            },
                        ))
                        .chain(trash.iter().zip(vk.cs.trashcans.iter()).flat_map(
                            move |(p, argument)| {
                                p.expressions(
                                    argument,
                                    trash_challenge,
                                    advice_evals,
                                    fixed_evals,
                                    instance_evals,
                                    challenges,
                                )
                            },
                        ))
                },
            );

        (vanishing.verify(expressions, y, xn), l_last, l_blind, l_0)
    };
    let vanishing_for_trace = vanishing.clone();

    let queries = committed_instances
        .iter()
        .zip(instance_evals.iter())
        .zip(advice_commitments.iter())
        .zip(advice_evals.iter())
        .zip(permutations_evaluated.iter())
        .zip(lookups_evaluated.iter())
        .zip(trashcans_evaluated.iter())
        .flat_map(
            |(
                (
                    (
                        (((committed_instances, instance_evals), advice_commitments), advice_evals),
                        permutation,
                    ),
                    lookups,
                ),
                trash,
            )| {
                iter::empty()
                    .chain(vk.cs.instance_queries.iter().enumerate().filter_map(
                        move |(query_index, &(column, at))| {
                            if column.index() < nb_committed_instances {
                                Some(VerifierQuery::new(
                                    vk.domain.rotate_omega(x, at),
                                    &committed_instances[column.index()],
                                    instance_evals[query_index],
                                ))
                            } else {
                                None
                            }
                        },
                    ))
                    .chain(vk.cs.advice_queries.iter().enumerate().map(
                        move |(query_index, &(column, at))| {
                            VerifierQuery::new(
                                vk.domain.rotate_omega(x, at),
                                &advice_commitments[column.index()],
                                advice_evals[query_index],
                            )
                        },
                    ))
                    .chain(permutation.queries(vk, x))
                    .chain(lookups.iter().flat_map(move |p| p.queries(vk, x)))
                    .chain(trash.iter().flat_map(move |p| p.queries(x)))
            },
        )
        .chain(
            vk.cs.fixed_queries.iter().enumerate().map(|(query_index, &(column, at))| {
                VerifierQuery::new(
                    vk.domain.rotate_omega(x, at),
                    &vk.fixed_commitments[column.index()],
                    fixed_evals[query_index],
                )
            }),
        )
        .chain(permutations_common.queries(&vk.permutation, x))
        .chain(vanishing.queries(x, vk.n()))
        .collect::<Vec<_>>();
    let query_count = queries.len();

    let guard = CS::multi_prepare(&queries, transcript).map_err(|_| Error::Opening)?;
    let trace = VerifierAlgebraicTrace {
        parsed_trace,
        nb_committed_instances,
        instance_query_columns,
        vanishing_after_y: vanishing_after_y_for_trace,
        x,
        xn,
        instance_evals,
        advice_evals,
        fixed_evals,
        vanishing_evaluated: vanishing_for_trace,
        permutations_common: permutations_common_for_trace,
        permutations_evaluated: permutations_evaluated_for_trace,
        lookups_evaluated: lookups_evaluated_for_trace,
        trashcans_evaluated: trashcans_evaluated_for_trace,
        l_last,
        l_blind,
        l_0,
        query_count,
    };

    Ok((guard, trace))
}

/// Prepares a plonk proof into a PCS instance that can be finalized or
/// batched. It is responsibility of the verifier to check the validity of the
/// instance columns.
///
/// The verifier will error if there are trailing bytes in the transcript.
pub fn prepare<F, CS: PolynomialCommitmentScheme<F>, T: Transcript>(
    vk: &VerifyingKey<F, CS>,
    // Unlike the prover, the verifier gets their instances in two arguments:
    // committed and normal (non-committed). Note that the total number of
    // instance columns is expected to be the sum of committed instances and
    // normal instances for every proof. (Committed instances go first, that is,
    // the first instance columns are devoted to committed instances.)
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<CS::VerificationGuard, Error>
where
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Hash
        + Ord,
    CS::Commitment: Hashable<T::Hash>,
{
    let trace = parse_trace(
        vk,
        #[cfg(feature = "committed-instances")]
        committed_instances,
        instances,
        transcript,
    )?;

    verify_algebraic_constraints(
        vk,
        trace,
        #[cfg(feature = "committed-instances")]
        committed_instances,
        instances,
        transcript,
    )
}
