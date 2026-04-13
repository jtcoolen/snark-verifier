#![cfg(all(feature = "midnight", feature = "loader_evm"))]

use halo2_base::halo2_proofs::halo2curves::{
    bls12_381::{Fr as HaloFr, G1Affine as HaloG1Affine},
    ff::PrimeField,
};
use midnight_curves::{Fq as MidnightFq, G1Projective as MidnightG1Projective};
use midnight_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use snark_verifier_sdk::snark_verifier::{
    loader::native::NativeLoader, system::halo2::transcript::evm::EvmTranscript,
    util::transcript::Transcript,
};

#[path = "../examples/support/midnight_evm_transcript.rs"]
mod midnight_evm_transcript;
use midnight_evm_transcript::MidnightEvmHash;

fn midnight_fq_to_halo_fr(value: MidnightFq) -> HaloFr {
    let source = value.to_repr();
    let source_bytes = source.as_ref();
    let mut target = <HaloFr as PrimeField>::Repr::default();
    let target_bytes = target.as_mut();
    assert_eq!(source_bytes.len(), target_bytes.len(), "field repr length mismatch");
    target_bytes.copy_from_slice(source_bytes);
    Option::from(HaloFr::from_repr(target)).expect("valid midnight scalar must map to halo scalar")
}

#[test]
fn keccak_transcript_challenges_match_midnight_for_evm_semantics() {
    let scalar_0 = MidnightFq::from(7u64);
    let scalar_1 = MidnightFq::from(42u64);
    let identity = MidnightG1Projective::default();

    // Midnight side (Keccak transcript hash with EVM-compatible encodings).
    let mut midnight_hash = MidnightEvmHash::init();
    midnight_hash.absorb(&<MidnightFq as Hashable<MidnightEvmHash>>::to_input(&scalar_0));
    let expected_challenge_0 =
        <MidnightFq as Sampleable<MidnightEvmHash>>::sample(midnight_hash.squeeze());
    midnight_hash.absorb(&<MidnightG1Projective as Hashable<MidnightEvmHash>>::to_input(&identity));
    midnight_hash.absorb(&<MidnightFq as Hashable<MidnightEvmHash>>::to_input(&scalar_1));
    let expected_challenge_1 =
        <MidnightFq as Sampleable<MidnightEvmHash>>::sample(midnight_hash.squeeze());

    // snark-verifier side (the exact EVM transcript logic used by generated Solidity verifier).
    let mut evm_transcript = EvmTranscript::<HaloG1Affine, NativeLoader, _, _>::new(());
    Transcript::common_scalar(&mut evm_transcript, &midnight_fq_to_halo_fr(scalar_0)).unwrap();
    let got_challenge_0 = Transcript::squeeze_challenge(&mut evm_transcript);
    Transcript::common_ec_point(&mut evm_transcript, &HaloG1Affine::identity()).unwrap();
    Transcript::common_scalar(&mut evm_transcript, &midnight_fq_to_halo_fr(scalar_1)).unwrap();
    let got_challenge_1 = Transcript::squeeze_challenge(&mut evm_transcript);

    assert_eq!(got_challenge_0, midnight_fq_to_halo_fr(expected_challenge_0));
    assert_eq!(got_challenge_1, midnight_fq_to_halo_fr(expected_challenge_1));
}
