#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MidnightVkArch {
    pub jubjub: bool,
    pub poseidon: bool,
    pub sha256: bool,
    pub sha512: bool,
    pub secp256k1: bool,
    pub bls12_381: bool,
    pub base64: bool,
    pub nr_pow2range_cols: u8,
    pub automaton: bool,
    pub verifier: bool,
}

impl MidnightVkArch {
    pub fn bridge_subset_supported(&self) -> bool {
        !self.jubjub
            && self.poseidon
            && !self.sha256
            && !self.sha512
            && !self.secp256k1
            && !self.bls12_381
            && !self.base64
            && !self.automaton
            && !self.verifier
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidnightVkHeader {
    pub zkstd_version: u32,
    pub arch: MidnightVkArch,
    pub max_bit_len: u8,
    pub nb_public_inputs: usize,
    pub inner_vk_version: u8,
    pub domain_k: u8,
    pub inner_vk_offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MidnightVkParseError {
    TooShort { got: usize, min: usize },
    UnsupportedZkStdVersion(u32),
}

impl std::fmt::Display for MidnightVkParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MidnightVkParseError::TooShort { got, min } => {
                write!(f, "vk.bin too short: got {got} bytes, expected at least {min}")
            }
            MidnightVkParseError::UnsupportedZkStdVersion(v) => {
                write!(f, "unsupported Midnight ZKStd version in vk.bin: {v}")
            }
        }
    }
}

impl std::error::Error for MidnightVkParseError {}

const ZKSTD_VERSION: u32 = 1;
const HEADER_LEN: usize = 4 + 10 + 1 + 4;
const INNER_VK_PREFIX_LEN: usize = 2;

pub fn parse_midnight_vk_header(bytes: &[u8]) -> Result<MidnightVkHeader, MidnightVkParseError> {
    if bytes.len() < HEADER_LEN + INNER_VK_PREFIX_LEN {
        return Err(MidnightVkParseError::TooShort {
            got: bytes.len(),
            min: HEADER_LEN + INNER_VK_PREFIX_LEN,
        });
    }

    let zkstd_version = u32::from_le_bytes(
        bytes[0..4].try_into().expect("slice length already checked above"),
    );
    if zkstd_version != ZKSTD_VERSION {
        return Err(MidnightVkParseError::UnsupportedZkStdVersion(zkstd_version));
    }

    let arch = MidnightVkArch {
        jubjub: bytes[4] != 0,
        poseidon: bytes[5] != 0,
        sha256: bytes[6] != 0,
        sha512: bytes[7] != 0,
        secp256k1: bytes[8] != 0,
        bls12_381: bytes[9] != 0,
        base64: bytes[10] != 0,
        nr_pow2range_cols: bytes[11],
        automaton: bytes[12] != 0,
        verifier: bytes[13] != 0,
    };

    let max_bit_len = bytes[14];
    let nb_public_inputs = u32::from_le_bytes(
        bytes[15..19].try_into().expect("slice length already checked above"),
    ) as usize;
    let inner_vk_version = bytes[19];
    let domain_k = bytes[20];

    Ok(MidnightVkHeader {
        zkstd_version,
        arch,
        max_bit_len,
        nb_public_inputs,
        inner_vk_version,
        domain_k,
        inner_vk_offset: HEADER_LEN,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_midnight_vk_header, MidnightVkArch, MidnightVkParseError};

    #[test]
    fn parses_poseidon_header_layout() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // zkstd version
        bytes.extend_from_slice(&[
            0, // jubjub
            1, // poseidon
            0, // sha256
            0, // sha512
            0, // secp256k1
            0, // bls12_381
            0, // base64
            1, // nr_pow2range_cols
            0, // automaton
            0, // verifier
        ]);
        bytes.push(8); // max_bit_len
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nb_public_inputs
        bytes.push(3); // inner vk version
        bytes.push(6); // domain k

        let parsed = parse_midnight_vk_header(&bytes).expect("header should parse");
        assert_eq!(parsed.zkstd_version, 1);
        assert_eq!(
            parsed.arch,
            MidnightVkArch {
                jubjub: false,
                poseidon: true,
                sha256: false,
                sha512: false,
                secp256k1: false,
                bls12_381: false,
                base64: false,
                nr_pow2range_cols: 1,
                automaton: false,
                verifier: false,
            }
        );
        assert_eq!(parsed.max_bit_len, 8);
        assert_eq!(parsed.nb_public_inputs, 1);
        assert_eq!(parsed.inner_vk_version, 3);
        assert_eq!(parsed.domain_k, 6);
        assert_eq!(parsed.inner_vk_offset, 19);
    }

    #[test]
    fn rejects_short_header() {
        let err = parse_midnight_vk_header(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, MidnightVkParseError::TooShort { .. }));
    }
}
