//! Bridge helpers for Midnight (halo2 fork) artifacts.
//!
//! This module is feature-gated (`--features midnight`) so Midnight crates are
//! only pulled when explicitly requested.
//!
//! It exposes:
//! - Solidity verifier generation (`generate_evm_verifier_solidity`),
//! - EVM deployment bytecode generation (`generate_evm_verifier_bytecode`), and
//! - Calldata encoding for the generated verifier (`encode_evm_calldata`).

mod bundle;
mod conversions;
#[cfg(feature = "loader_evm")]
mod evm;
mod protocol_builder;

use halo2_base::halo2_proofs::halo2curves::bls12_381::Bls12 as HaloBls12;
use midnight_curves::{Bls12, Fq};
use midnight_proofs::poly::{commitment::PolynomialCommitmentScheme, kzg::KZGCommitmentScheme};
use snark_verifier::pcs::kzg::{KzgAs, Midnight};

pub use bundle::{MidnightBundleOptions, MidnightProofBundle};

pub(super) type MidnightCommitment =
    <KZGCommitmentScheme<Bls12> as PolynomialCommitmentScheme<Fq>>::Commitment;
pub(super) type HaloAs = KzgAs<HaloBls12, Midnight>;
