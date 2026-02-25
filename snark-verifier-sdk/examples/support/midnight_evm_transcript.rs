use anyhow::{anyhow, Result};
use ff::{Field, PrimeField};
use midnight_curves::{
    CurveAffine as MidnightCurveAffine, Fp as MidnightFp, Fq, G1Affine as MidnightG1Affine,
    G1Projective,
};
use midnight_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use std::io::{self, Read};

const EVM_ENCODED_FP_BYTES: usize = 64;

/// Transcript hash compatible with snark-verifier's EVM transcript semantics.
#[derive(Clone, Debug, Default)]
pub struct MidnightEvmHash {
    state: Vec<u8>,
}

impl TranscriptHash for MidnightEvmHash {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn init() -> Self {
        Self { state: Vec::new() }
    }

    // Concatenate transcript inputs exactly as EVM transcript absorption does.
    fn absorb(&mut self, input: &Self::Input) {
        self.state.extend_from_slice(input);
    }

    // Squeeze with Keccak and apply the EVM transcript 32-byte domain-separation rule.
    fn squeeze(&mut self) -> Self::Output {
        let mut data = self.state.clone();
        if data.len() == 32 {
            data.push(1);
        }
        let digest = Keccak256::digest(data);
        self.state = digest.to_vec();
        digest.to_vec()
    }
}

impl Hashable<MidnightEvmHash> for Fq {
    fn to_input(&self) -> Vec<u8> {
        scalar_to_evm_bytes(self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        scalar_to_evm_bytes(self)
    }

    // Read canonical 32-byte big-endian scalar encoding used by EVM transcripts.
    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut be = [0u8; 32];
        buffer.read_exact(&mut be)?;
        scalar_from_evm_bytes(&be)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}

impl Sampleable<MidnightEvmHash> for Fq {
    // Reduce the hash output modulo the scalar field to derive a transcript challenge.
    fn sample(hash_output: Vec<u8>) -> Self {
        assert_eq!(hash_output.len(), 32, "MidnightEvmHash outputs 32 bytes");
        let value = BigUint::from_bytes_be(&hash_output);
        let modulus = BigUint::from_bytes_le((-Fq::ONE).to_repr().as_ref()) + BigUint::from(1u8);
        let reduced = value % modulus;
        let mut repr = <Fq as PrimeField>::Repr::default();
        let repr_len = repr.as_ref().len();
        let mut reduced_le = reduced.to_bytes_le();
        reduced_le.resize(repr_len, 0);
        repr.as_mut().copy_from_slice(&reduced_le[..repr_len]);
        Fq::from_repr(repr).unwrap()
    }
}

impl Hashable<MidnightEvmHash> for G1Projective {
    // Encode affine coordinates as 64-byte EVM words (or (0,0) for infinity).
    fn to_input(&self) -> Vec<u8> {
        let affine = MidnightG1Affine::from(self);
        let coordinates = match Option::<midnight_curves::Coordinates<MidnightG1Affine>>::from(
            affine.coordinates(),
        ) {
            Some(coordinates) => coordinates,
            None => {
                return vec![0u8; 2 * EVM_ENCODED_FP_BYTES];
            }
        };
        let mut bytes = Vec::with_capacity(2 * EVM_ENCODED_FP_BYTES);
        bytes.extend_from_slice(&fp_to_evm_word(coordinates.x()));
        bytes.extend_from_slice(&fp_to_evm_word(coordinates.y()));
        bytes
    }

    // Encode compact canonical point bytes used by Midnight proof serialization.
    fn to_bytes(&self) -> Vec<u8> {
        let affine = MidnightG1Affine::from(self);
        let coordinates = match Option::<midnight_curves::Coordinates<MidnightG1Affine>>::from(
            affine.coordinates(),
        ) {
            Some(coordinates) => coordinates,
            None => {
                return vec![0u8; 2 * midnight_fp_num_bytes()];
            }
        };
        let mut bytes = Vec::with_capacity(2 * midnight_fp_num_bytes());
        bytes.extend_from_slice(&fp_to_be_bytes(coordinates.x()));
        bytes.extend_from_slice(&fp_to_be_bytes(coordinates.y()));
        bytes
    }

    // Decode canonical point bytes from proof transcript encoding.
    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let coord_bytes = midnight_fp_num_bytes();
        let mut x_be = vec![0u8; coord_bytes];
        let mut y_be = vec![0u8; coord_bytes];
        buffer.read_exact(&mut x_be)?;
        buffer.read_exact(&mut y_be)?;

        let x = fp_from_be_bytes(&x_be)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        let y = fp_from_be_bytes(&y_be)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        // Keep `(0, 0)` as the explicit point-at-infinity sentinel for EVM-compatible proofs.
        if x == MidnightFp::ZERO && y == MidnightFp::ZERO {
            return Ok(G1Projective::default());
        }
        let affine: MidnightG1Affine =
            Option::from(MidnightG1Affine::from_xy(x, y)).ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "Invalid BLS12-381 point encoding in proof")
            })?;
        Ok(G1Projective::from(affine))
    }
}

// Number of bytes in Midnight base-field representation.
fn midnight_fp_num_bytes() -> usize {
    <MidnightFp as PrimeField>::Repr::default().as_ref().len()
}

// Convert scalar to big-endian bytes expected by EVM transcript hashing.
fn scalar_to_evm_bytes(value: &Fq) -> Vec<u8> {
    let mut bytes = value.to_repr().as_ref().to_vec();
    bytes.reverse();
    bytes
}

// Decode a big-endian scalar encoding used by EVM transcript hashing.
fn scalar_from_evm_bytes(bytes_be: &[u8]) -> Result<Fq> {
    let expected = <Fq as PrimeField>::Repr::default().as_ref().len();
    if bytes_be.len() != expected {
        return Err(anyhow!(
            "invalid scalar length: expected {expected} bytes, got {}",
            bytes_be.len()
        ));
    }
    let mut le = bytes_be.to_vec();
    le.reverse();
    let mut repr = <Fq as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&le);
    Option::from(Fq::from_repr(repr)).ok_or_else(|| anyhow!("invalid scalar encoding"))
}

// Convert Midnight base-field element to big-endian bytes.
fn fp_to_be_bytes(value: &MidnightFp) -> Vec<u8> {
    let mut bytes = value.to_repr().as_ref().to_vec();
    bytes.reverse();
    bytes
}

// Left-pad base-field bytes into one 64-byte EVM word.
fn fp_to_evm_word(value: &MidnightFp) -> [u8; EVM_ENCODED_FP_BYTES] {
    let be = fp_to_be_bytes(value);
    let mut out = [0u8; EVM_ENCODED_FP_BYTES];
    let offset = EVM_ENCODED_FP_BYTES - be.len();
    out[offset..].copy_from_slice(&be);
    out
}

// Decode big-endian base-field coordinate bytes.
fn fp_from_be_bytes(bytes_be: &[u8]) -> Result<MidnightFp> {
    let expected = midnight_fp_num_bytes();
    if bytes_be.len() != expected {
        return Err(anyhow!(
            "invalid base-field coordinate length: expected {expected} bytes, got {}",
            bytes_be.len()
        ));
    }
    let mut le = bytes_be.to_vec();
    le.reverse();
    let mut repr = <MidnightFp as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&le);
    Option::from(MidnightFp::from_repr(repr)).ok_or_else(|| anyhow!("invalid base-field encoding"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn evm_hash_applies_domain_separator_and_chains() {
        let mut hash = MidnightEvmHash::init();
        let first_input = vec![0x42; 32];
        hash.absorb(&first_input);

        let first = hash.squeeze();
        let expected_first = Keccak256::digest(
            first_input.into_iter().chain(std::iter::once(1u8)).collect::<Vec<_>>(),
        )
        .to_vec();
        assert_eq!(first, expected_first);

        let second = hash.squeeze();
        let expected_second = Keccak256::digest(
            expected_first.into_iter().chain(std::iter::once(1u8)).collect::<Vec<_>>(),
        )
        .to_vec();
        assert_eq!(second, expected_second);
    }

    #[test]
    fn scalar_roundtrip_uses_evm_big_endian_encoding() {
        let scalar = Fq::from(123_456u64);
        let bytes = <Fq as Hashable<MidnightEvmHash>>::to_bytes(&scalar);
        assert_eq!(bytes.len(), 32);
        assert_eq!(<Fq as Hashable<MidnightEvmHash>>::to_input(&scalar), bytes);

        let mut cursor = Cursor::new(bytes);
        let decoded = <Fq as Hashable<MidnightEvmHash>>::read(&mut cursor).unwrap();
        assert_eq!(decoded, scalar);
    }

    #[test]
    fn point_roundtrip_preserves_infinity_sentinel() {
        let point = G1Projective::default();
        assert_eq!(
            <G1Projective as Hashable<MidnightEvmHash>>::to_input(&point),
            vec![0u8; 2 * EVM_ENCODED_FP_BYTES]
        );

        let bytes = <G1Projective as Hashable<MidnightEvmHash>>::to_bytes(&point);
        assert_eq!(bytes, vec![0u8; 2 * midnight_fp_num_bytes()]);

        let mut cursor = Cursor::new(bytes);
        let decoded = <G1Projective as Hashable<MidnightEvmHash>>::read(&mut cursor).unwrap();
        assert_eq!(decoded, G1Projective::default());
    }
}
