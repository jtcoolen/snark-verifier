use crate::midnight_vk::{parse_midnight_vk_header, MidnightVkHeader, MidnightVkParseError};
use sha2::{Digest, Sha256};

const G1_COMMITMENT_BYTES: usize = 96;

/// Parsed prefix of the serialized Midnight inner VK payload.
///
/// The inner payload currently starts with:
/// - version byte
/// - domain k byte
/// - number of fixed commitments (u32 little-endian)
///
/// This prefix is stable enough to extract deterministic shape signals for
/// bridge prechecks without yet parsing the full VK internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidnightVkPayloadPrefix {
    pub inner_vk_version: u8,
    pub domain_k: u8,
    pub num_fixed_commitments: u32,
    pub fixed_commitments_offset: usize,
    pub fixed_commitments_len_bytes: usize,
    pub fixed_commitments_sha256: String,
    pub inner_payload_len_bytes: usize,
    pub inner_payload_sha256: String,
    pub trailing_payload_offset: usize,
    pub trailing_payload_len_bytes: usize,
    pub trailing_payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MidnightVkPayloadParseError {
    Header(MidnightVkParseError),
    TooShort { got: usize, min: usize },
    FixedCommitmentsSectionOverflow {
        got: usize,
        start: usize,
        len: usize,
    },
}

impl std::fmt::Display for MidnightVkPayloadParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MidnightVkPayloadParseError::Header(e) => write!(f, "{e}"),
            MidnightVkPayloadParseError::TooShort { got, min } => {
                write!(f, "vk.bin too short for inner payload prefix: got {got}, need at least {min}")
            }
            MidnightVkPayloadParseError::FixedCommitmentsSectionOverflow { got, start, len } => {
                write!(
                    f,
                    "vk.bin fixed-commitments section out of bounds: file={got}, start={start}, len={len}"
                )
            }
        }
    }
}

impl std::error::Error for MidnightVkPayloadParseError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidnightVkPayloadView {
    pub header: MidnightVkHeader,
    pub prefix: MidnightVkPayloadPrefix,
    pub fixed_commitments: Vec<[u8; G1_COMMITMENT_BYTES]>,
}

pub fn parse_midnight_vk_payload_view(
    bytes: &[u8],
) -> Result<MidnightVkPayloadView, MidnightVkPayloadParseError> {
    let header =
        parse_midnight_vk_header(bytes).map_err(MidnightVkPayloadParseError::Header)?;
    let min = header.inner_vk_offset + 6;
    if bytes.len() < min {
        return Err(MidnightVkPayloadParseError::TooShort { got: bytes.len(), min });
    }

    let o = header.inner_vk_offset;
    let inner_vk_version = bytes[o];
    let domain_k = bytes[o + 1];
    let num_fixed_commitments = u32::from_le_bytes(
        bytes[o + 2..o + 6].try_into().expect("slice length already checked"),
    );
    let fixed_commitments_offset = o + 6;
    let fixed_commitments_len_bytes = num_fixed_commitments as usize * G1_COMMITMENT_BYTES;
    let fixed_commitments_end = fixed_commitments_offset.saturating_add(fixed_commitments_len_bytes);
    if fixed_commitments_end > bytes.len() {
        return Err(MidnightVkPayloadParseError::FixedCommitmentsSectionOverflow {
            got: bytes.len(),
            start: fixed_commitments_offset,
            len: fixed_commitments_len_bytes,
        });
    }
    let fixed_commitments_sha256 =
        format!("0x{}", hex::encode(Sha256::digest(&bytes[fixed_commitments_offset..fixed_commitments_end])));
    let mut fixed_commitments = Vec::with_capacity(num_fixed_commitments as usize);
    for idx in 0..num_fixed_commitments as usize {
        let start = fixed_commitments_offset + idx * G1_COMMITMENT_BYTES;
        let end = start + G1_COMMITMENT_BYTES;
        let mut chunk = [0u8; G1_COMMITMENT_BYTES];
        chunk.copy_from_slice(&bytes[start..end]);
        fixed_commitments.push(chunk);
    }

    let inner_payload_len_bytes = bytes.len() - o;
    let inner_payload_sha256 = format!("0x{}", hex::encode(Sha256::digest(&bytes[o..])));
    let trailing_payload_offset = fixed_commitments_end;
    let trailing_payload_len_bytes = bytes.len() - trailing_payload_offset;
    let trailing_payload_sha256 =
        format!("0x{}", hex::encode(Sha256::digest(&bytes[trailing_payload_offset..])));

    let prefix = MidnightVkPayloadPrefix {
        inner_vk_version,
        domain_k,
        num_fixed_commitments,
        fixed_commitments_offset,
        fixed_commitments_len_bytes,
        fixed_commitments_sha256,
        inner_payload_len_bytes,
        inner_payload_sha256,
        trailing_payload_offset,
        trailing_payload_len_bytes,
        trailing_payload_sha256,
    };

    Ok(MidnightVkPayloadView { header, prefix, fixed_commitments })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MidnightProtocolAdapterError {
    Parse(MidnightVkPayloadParseError),
    Unsupported(String),
}

impl std::fmt::Display for MidnightProtocolAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MidnightProtocolAdapterError::Parse(e) => write!(f, "{e}"),
            MidnightProtocolAdapterError::Unsupported(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for MidnightProtocolAdapterError {}

/// Phase 1B adapter skeleton.
///
/// This validates and extracts deterministic VK payload metadata and returns a
/// typed "unsupported" error for the yet-unimplemented full protocol mapping.
pub fn ensure_midnight_adapter_ready(bytes: &[u8]) -> Result<MidnightVkPayloadView, MidnightProtocolAdapterError> {
    let view = parse_midnight_vk_payload_view(bytes).map_err(MidnightProtocolAdapterError::Parse)?;

    // We currently only support inner VK format version 3 in this repo's bridge path.
    if view.prefix.inner_vk_version != 3 {
        return Err(MidnightProtocolAdapterError::Unsupported(format!(
            "unsupported midnight inner vk version {} (expected 3)",
            view.prefix.inner_vk_version
        )));
    }

    // Skeleton note: full mapping of Midnight VK internals to snark-verifier
    // PlonkProtocol is still pending; we expose parsed fields for now.
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::{ensure_midnight_adapter_ready, parse_midnight_vk_payload_view};

    #[test]
    fn parses_payload_prefix() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // zkstd version
        bytes.extend_from_slice(&[
            0, 1, 0, 0, 0, 0, 0, 1, 0, 0, // arch
        ]);
        bytes.push(8); // max_bit_len
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nb_public_inputs
        bytes.push(3); // inner vk version
        bytes.push(6); // k
        bytes.extend_from_slice(&19u32.to_le_bytes()); // num_fixed
        bytes.extend_from_slice(&[0u8; 1824 + 64]); // fixed commitments + payload body

        let view = parse_midnight_vk_payload_view(&bytes).expect("should parse");
        assert_eq!(view.prefix.inner_vk_version, 3);
        assert_eq!(view.prefix.domain_k, 6);
        assert_eq!(view.prefix.num_fixed_commitments, 19);
        assert_eq!(view.prefix.fixed_commitments_offset, 25);
        assert_eq!(view.prefix.fixed_commitments_len_bytes, 1824);
        assert!(view.prefix.fixed_commitments_sha256.starts_with("0x"));
        assert_eq!(view.prefix.inner_payload_len_bytes, 1894);
        assert!(view.prefix.inner_payload_sha256.starts_with("0x"));
        assert_eq!(view.prefix.trailing_payload_offset, 1849);
        assert_eq!(view.prefix.trailing_payload_len_bytes, 64);
        assert!(view.prefix.trailing_payload_sha256.starts_with("0x"));
        assert_eq!(view.fixed_commitments.len(), 19);
    }

    #[test]
    fn adapter_accepts_v3() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1, 0, 0]);
        bytes.push(8);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(3);
        bytes.push(6);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 96 + 16]);

        let view = ensure_midnight_adapter_ready(&bytes).expect("version 3 should be accepted");
        assert_eq!(view.prefix.inner_vk_version, 3);
    }
}
