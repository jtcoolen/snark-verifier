//! Representation of a Trace for a batch of proofs that are being generated
//! simultaneously.

use ff::PrimeField;

use crate::{
    plonk::{lookup, permutation, trash, vanishing},
    poly::{commitment::PolynomialCommitmentScheme, Coeff, LagrangeCoeff, Polynomial},
};

/// Prover's trace of a set of proofs. This type guarantees that the size of the
/// outer vector of its fields has the same size.
#[derive(Debug)]
pub struct ProverTrace<F: PrimeField> {
    pub advice_polys: Vec<Vec<Polynomial<F, Coeff>>>,
    pub instance_polys: Vec<Vec<Polynomial<F, Coeff>>>,
    #[allow(dead_code)]
    // This field will be useful for split accumulation
    pub instance_values: Vec<Vec<Polynomial<F, LagrangeCoeff>>>,
    pub vanishing: vanishing::prover::Committed<F>,
    pub lookups: Vec<Vec<lookup::prover::Committed<F>>>,
    pub trashcans: Vec<Vec<trash::prover::Committed<F>>>,
    pub permutations: Vec<permutation::prover::Committed<F>>,
    pub challenges: Vec<F>,
    pub beta: F,
    pub gamma: F,
    pub theta: F,
    pub trash_challenge: F,
    pub y: F,
}

/// Verifier's trace of a set of proofs. This type guarantees that the size of
/// the outer vector of its fields has the same size.
#[derive(Debug, Clone)]
pub struct VerifierTrace<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> {
    pub advice_commitments: Vec<Vec<PCS::Commitment>>,
    pub vanishing: vanishing::verifier::Committed<F, PCS>,
    pub lookups: Vec<Vec<lookup::verifier::Committed<F, PCS>>>,
    pub trashcans: Vec<Vec<trash::verifier::Committed<F, PCS>>>,
    pub permutations: Vec<permutation::verifier::Committed<F, PCS>>,
    pub challenges: Vec<F>,
    pub beta: F,
    pub gamma: F,
    pub theta: F,
    pub trash_challenge: F,
    pub y: F,
}
