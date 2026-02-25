//! Shared expression helpers used by Halo2 protocol builders.

use crate::{
    util::arithmetic::{PrimeField, Rotation},
    verifier::plonk::protocol::{CommonPolynomial, Expression},
};

/// Rotation corresponding to the last unblinded row in the evaluation domain.
pub fn rotation_last(blinding_factors: usize) -> Rotation {
    Rotation(-((blinding_factors + 1) as i32))
}

/// Lagrange selector for the last active row.
pub fn l_last<F: PrimeField>(rotation_last: Rotation) -> Expression<F> {
    Expression::CommonPolynomial(CommonPolynomial::Lagrange(rotation_last.0))
}

/// Sum of Lagrange selectors over blinding rows.
pub fn l_blind<F: PrimeField>(rotation_last: Rotation) -> Expression<F> {
    (rotation_last.0 + 1..0).map(CommonPolynomial::Lagrange).map(Expression::CommonPolynomial).sum()
}

/// Selector for all active (non-last, non-blinding) rows.
pub fn l_active<F: PrimeField>(l_last: Expression<F>, l_blind: Expression<F>) -> Expression<F> {
    Expression::Constant(F::ONE) - l_last - l_blind
}

/// Compress a list of expressions with powers of a challenge.
pub fn distribute_powers<F: PrimeField>(
    expressions: Vec<Expression<F>>,
    challenge: Expression<F>,
) -> Expression<F> {
    if expressions.is_empty() {
        Expression::Constant(F::ZERO)
    } else if expressions.len() == 1 {
        expressions.into_iter().next().unwrap()
    } else {
        Expression::DistributePowers(expressions, challenge.into())
    }
}
