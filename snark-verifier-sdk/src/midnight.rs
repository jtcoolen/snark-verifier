use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};

/// Immutable protocol/version fingerprint for a Midnight proof profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolProfile {
    pub profile_id: String,
    pub protocol_version: String,
    pub transcript: TranscriptProfile,
    pub pcs: PcsProfile,
    pub circuit: CircuitProfile,
    #[serde(default)]
    pub expected: ExpectedShape,
}

/// Transcript configuration that must match prover and verifier exactly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranscriptProfile {
    pub name: String,
    pub truncate_challenges: bool,
    #[serde(default)]
    pub challenge_bits: Option<u16>,
    #[serde(default)]
    pub domain_separator: Option<String>,
}

/// Polynomial commitment configuration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcsProfile {
    pub scheme: String,
    pub curve: String,
    pub srs_hash: String,
}

/// Circuit-level behavior toggles that can affect transcript/query shape.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitProfile {
    pub circuit_id: String,
    pub trash_mode: String,
    #[serde(default)]
    pub committed_instances: bool,
}

/// Optional expected shape guards derived from VK/protocol.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedShape {
    #[serde(default)]
    pub vk_hash: Option<String>,
    #[serde(default)]
    pub proof_len_bytes: Option<usize>,
    #[serde(default)]
    pub instance_column_lens: Option<Vec<usize>>,
    #[serde(default)]
    pub num_queries: Option<usize>,
    #[serde(default)]
    pub num_evaluations: Option<usize>,
    #[serde(default)]
    pub vk_inner_version: Option<u8>,
    #[serde(default)]
    pub vk_domain_k: Option<u8>,
    #[serde(default)]
    pub vk_num_fixed_commitments: Option<u32>,
    #[serde(default)]
    pub vk_fixed_commitments_sha256: Option<String>,
}

/// Runtime metadata of a concrete proof artifact to preflight before verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofMetadata {
    pub profile_id: String,
    pub protocol_version: String,
    pub transcript: ProofTranscriptMetadata,
    pub pcs: ProofPcsMetadata,
    pub circuit: ProofCircuitMetadata,
    pub proof_len_bytes: usize,
    pub instance_column_lens: Vec<usize>,
    #[serde(default)]
    pub num_queries: Option<usize>,
    #[serde(default)]
    pub num_evaluations: Option<usize>,
    #[serde(default)]
    pub proof_layout: Option<ProofLayoutDescriptor>,
    #[serde(default)]
    pub protocol_layout: Option<ProofProtocolLayoutDescriptor>,
}

/// Optional explicit proof byte layout descriptor used by protocol translation scaffolds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofLayoutDescriptor {
    #[serde(default)]
    pub commitments_offset: usize,
    pub num_commitments: usize,
    pub num_evaluations: usize,
    #[serde(default)]
    pub num_queries: Option<usize>,
}

/// Optional explicit protocol-layout descriptor used by translation scaffolds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofProtocolLayoutDescriptor {
    /// Digest/fingerprint that identifies the quotient expression payload.
    pub quotient_expression_sha256: String,
    /// Digest/fingerprint of canonical query->evaluation schedule mapping.
    #[serde(default)]
    pub query_schedule_sha256: Option<String>,
    /// Expected linearization strategy string (for scaffold diagnostics).
    pub linearization_strategy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofTranscriptMetadata {
    pub name: String,
    pub truncate_challenges: bool,
    #[serde(default)]
    pub challenge_bits: Option<u16>,
    #[serde(default)]
    pub domain_separator: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPcsMetadata {
    pub scheme: String,
    pub curve: String,
    pub srs_hash: String,
    pub vk_hash: String,
    #[serde(default)]
    pub vk_inner_version: Option<u8>,
    #[serde(default)]
    pub vk_domain_k: Option<u8>,
    #[serde(default)]
    pub vk_num_fixed_commitments: Option<u32>,
    #[serde(default)]
    pub vk_fixed_commitments_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofCircuitMetadata {
    pub circuit_id: String,
    pub trash_mode: String,
    #[serde(default)]
    pub committed_instances: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreflightError {
    Mismatch { field: &'static str, expected: String, got: String },
    MissingField { field: &'static str },
    InvalidField { field: &'static str, reason: String },
}

impl Display for PreflightError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PreflightError::Mismatch { field, expected, got } => {
                write!(f, "mismatch for {field}: expected={expected}, got={got}")
            }
            PreflightError::MissingField { field } => write!(f, "missing required field: {field}"),
            PreflightError::InvalidField { field, reason } => {
                write!(f, "invalid field {field}: {reason}")
            }
        }
    }
}

fn check_eq<T: Debug + PartialEq>(
    field: &'static str,
    expected: &T,
    got: &T,
) -> Result<(), PreflightError> {
    if expected != got {
        return Err(PreflightError::Mismatch {
            field,
            expected: format!("{expected:?}"),
            got: format!("{got:?}"),
        });
    }
    Ok(())
}

/// Validates that proof metadata is protocol-compatible before costly verification.
pub fn preflight_check(
    profile: &ProtocolProfile,
    proof: &ProofMetadata,
) -> Result<(), PreflightError> {
    check_eq("profile_id", &profile.profile_id, &proof.profile_id)?;
    check_eq("protocol_version", &profile.protocol_version, &proof.protocol_version)?;

    check_eq("transcript.name", &profile.transcript.name, &proof.transcript.name)?;
    check_eq(
        "transcript.truncate_challenges",
        &profile.transcript.truncate_challenges,
        &proof.transcript.truncate_challenges,
    )?;
    check_eq(
        "transcript.challenge_bits",
        &profile.transcript.challenge_bits,
        &proof.transcript.challenge_bits,
    )?;
    check_eq(
        "transcript.domain_separator",
        &profile.transcript.domain_separator,
        &proof.transcript.domain_separator,
    )?;

    check_eq("pcs.scheme", &profile.pcs.scheme, &proof.pcs.scheme)?;
    check_eq("pcs.curve", &profile.pcs.curve, &proof.pcs.curve)?;
    check_eq("pcs.srs_hash", &profile.pcs.srs_hash, &proof.pcs.srs_hash)?;

    check_eq("circuit.circuit_id", &profile.circuit.circuit_id, &proof.circuit.circuit_id)?;
    check_eq("circuit.trash_mode", &profile.circuit.trash_mode, &proof.circuit.trash_mode)?;
    check_eq(
        "circuit.committed_instances",
        &profile.circuit.committed_instances,
        &proof.circuit.committed_instances,
    )?;
    if proof.instance_column_lens.is_empty() {
        return Err(PreflightError::InvalidField {
            field: "instance_column_lens",
            reason: "must contain at least one instance column".to_string(),
        });
    }
    if proof.instance_column_lens.iter().any(|len| *len == 0) {
        return Err(PreflightError::InvalidField {
            field: "instance_column_lens",
            reason: "all instance columns must have non-zero length".to_string(),
        });
    }
    if let Some(layout) = proof.proof_layout.as_ref() {
        if layout.num_commitments == 0 {
            return Err(PreflightError::InvalidField {
                field: "proof_layout.num_commitments",
                reason: "must be greater than zero".to_string(),
            });
        }
        if let Some(num_evals) = proof.num_evaluations {
            check_eq("proof_layout.num_evaluations", &layout.num_evaluations, &num_evals)?;
        }
        if let Some(num_queries) = proof.num_queries {
            if let Some(layout_num_queries) = layout.num_queries {
                check_eq("proof_layout.num_queries", &layout_num_queries, &num_queries)?;
            }
        }
    }
    if let Some(protocol_layout) = proof.protocol_layout.as_ref() {
        if protocol_layout.quotient_expression_sha256.trim().is_empty() {
            return Err(PreflightError::InvalidField {
                field: "protocol_layout.quotient_expression_sha256",
                reason: "must be non-empty".to_string(),
            });
        }
        if let Some(query_schedule_sha256) = protocol_layout.query_schedule_sha256.as_ref() {
            if query_schedule_sha256.trim().is_empty() {
                return Err(PreflightError::InvalidField {
                    field: "protocol_layout.query_schedule_sha256",
                    reason: "must be non-empty when present".to_string(),
                });
            }
        }
        if protocol_layout.linearization_strategy.trim().is_empty() {
            return Err(PreflightError::InvalidField {
                field: "protocol_layout.linearization_strategy",
                reason: "must be non-empty".to_string(),
            });
        }
    }

    if profile.transcript.truncate_challenges && profile.transcript.challenge_bits.is_none() {
        return Err(PreflightError::MissingField { field: "transcript.challenge_bits" });
    }

    if let Some(expected_vk_hash) = &profile.expected.vk_hash {
        check_eq("expected.vk_hash", expected_vk_hash, &proof.pcs.vk_hash)?;
    }
    if let Some(expected_proof_len) = profile.expected.proof_len_bytes {
        check_eq("expected.proof_len_bytes", &expected_proof_len, &proof.proof_len_bytes)?;
    }
    if let Some(expected_lens) = &profile.expected.instance_column_lens {
        if expected_lens.is_empty() {
            return Err(PreflightError::InvalidField {
                field: "expected.instance_column_lens",
                reason: "must contain at least one instance column".to_string(),
            });
        }
        if expected_lens.iter().any(|len| *len == 0) {
            return Err(PreflightError::InvalidField {
                field: "expected.instance_column_lens",
                reason: "all expected instance columns must have non-zero length".to_string(),
            });
        }
        check_eq("expected.instance_column_lens", expected_lens, &proof.instance_column_lens)?;
    }
    if let Some(expected_queries) = profile.expected.num_queries {
        match proof.num_queries {
            Some(got_queries) => check_eq("expected.num_queries", &expected_queries, &got_queries)?,
            None => return Err(PreflightError::MissingField { field: "num_queries" }),
        }
    }
    if let Some(expected_evals) = profile.expected.num_evaluations {
        match proof.num_evaluations {
            Some(got_evals) => {
                check_eq("expected.num_evaluations", &expected_evals, &got_evals)?
            }
            None => return Err(PreflightError::MissingField { field: "num_evaluations" }),
        }
    }
    if let Some(expected_vk_inner_version) = profile.expected.vk_inner_version {
        match proof.pcs.vk_inner_version {
            Some(got_vk_inner_version) => {
                check_eq("expected.vk_inner_version", &expected_vk_inner_version, &got_vk_inner_version)?
            }
            None => return Err(PreflightError::MissingField { field: "pcs.vk_inner_version" }),
        }
    }
    if let Some(expected_vk_domain_k) = profile.expected.vk_domain_k {
        match proof.pcs.vk_domain_k {
            Some(got_vk_domain_k) => {
                check_eq("expected.vk_domain_k", &expected_vk_domain_k, &got_vk_domain_k)?
            }
            None => return Err(PreflightError::MissingField { field: "pcs.vk_domain_k" }),
        }
    }
    if let Some(expected_vk_num_fixed_commitments) = profile.expected.vk_num_fixed_commitments {
        match proof.pcs.vk_num_fixed_commitments {
            Some(got_vk_num_fixed_commitments) => {
                check_eq(
                    "expected.vk_num_fixed_commitments",
                    &expected_vk_num_fixed_commitments,
                    &got_vk_num_fixed_commitments,
                )?
            }
            None => {
                return Err(PreflightError::MissingField {
                    field: "pcs.vk_num_fixed_commitments",
                })
            }
        }
    }
    if let Some(expected_vk_fixed_commitments_sha256) = profile.expected.vk_fixed_commitments_sha256.as_ref()
    {
        match proof.pcs.vk_fixed_commitments_sha256.as_ref() {
            Some(got_vk_fixed_commitments_sha256) => {
                check_eq(
                    "expected.vk_fixed_commitments_sha256",
                    expected_vk_fixed_commitments_sha256,
                    got_vk_fixed_commitments_sha256,
                )?
            }
            None => {
                return Err(PreflightError::MissingField {
                    field: "pcs.vk_fixed_commitments_sha256",
                })
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> ProtocolProfile {
        ProtocolProfile {
            profile_id: "poseidon-v1".to_string(),
            protocol_version: "midnight-proofs-0.3".to_string(),
            transcript: TranscriptProfile {
                name: "Poseidon".to_string(),
                truncate_challenges: true,
                challenge_bits: Some(128),
                domain_separator: Some("midnight.poseidon.v1".to_string()),
            },
            pcs: PcsProfile {
                scheme: "KZG".to_string(),
                curve: "BLS12-381".to_string(),
                srs_hash: "srs:abc".to_string(),
            },
            circuit: CircuitProfile {
                circuit_id: "poseidon_example".to_string(),
                trash_mode: "additive_selectors_v1".to_string(),
                committed_instances: false,
            },
            expected: ExpectedShape {
                vk_hash: Some("vk:123".to_string()),
                proof_len_bytes: Some(864),
                instance_column_lens: Some(vec![1]),
                num_queries: Some(42),
                num_evaluations: Some(42),
                vk_inner_version: Some(3),
                vk_domain_k: Some(6),
                vk_num_fixed_commitments: Some(19),
                vk_fixed_commitments_sha256: Some("0xabc".to_string()),
            },
        }
    }

    fn sample_proof() -> ProofMetadata {
        ProofMetadata {
            profile_id: "poseidon-v1".to_string(),
            protocol_version: "midnight-proofs-0.3".to_string(),
            transcript: ProofTranscriptMetadata {
                name: "Poseidon".to_string(),
                truncate_challenges: true,
                challenge_bits: Some(128),
                domain_separator: Some("midnight.poseidon.v1".to_string()),
            },
            pcs: ProofPcsMetadata {
                scheme: "KZG".to_string(),
                curve: "BLS12-381".to_string(),
                srs_hash: "srs:abc".to_string(),
                vk_hash: "vk:123".to_string(),
                vk_inner_version: Some(3),
                vk_domain_k: Some(6),
                vk_num_fixed_commitments: Some(19),
                vk_fixed_commitments_sha256: Some("0xabc".to_string()),
            },
            circuit: ProofCircuitMetadata {
                circuit_id: "poseidon_example".to_string(),
                trash_mode: "additive_selectors_v1".to_string(),
                committed_instances: false,
            },
            proof_len_bytes: 864,
            instance_column_lens: vec![1],
            num_queries: Some(42),
            num_evaluations: Some(42),
            proof_layout: Some(ProofLayoutDescriptor {
                commitments_offset: 0,
                num_commitments: 9,
                num_evaluations: 42,
                num_queries: Some(42),
            }),
            protocol_layout: Some(ProofProtocolLayoutDescriptor {
                quotient_expression_sha256: "0xdef".to_string(),
                query_schedule_sha256: Some("0x123".to_string()),
                linearization_strategy: "MinusVanishingTimesQuotient".to_string(),
            }),
        }
    }

    #[test]
    fn preflight_ok() {
        preflight_check(&sample_profile(), &sample_proof()).unwrap();
    }

    #[test]
    fn preflight_mismatch_trash_mode() {
        let profile = sample_profile();
        let mut proof = sample_proof();
        proof.circuit.trash_mode = "additive_selectors_v2".to_string();
        let err = preflight_check(&profile, &proof).unwrap_err();
        assert!(matches!(err, PreflightError::Mismatch { field: "circuit.trash_mode", .. }));
    }

    #[test]
    fn preflight_rejects_invalid_instance_shape() {
        let profile = sample_profile();
        let mut proof = sample_proof();
        proof.instance_column_lens = vec![1, 0];
        let err = preflight_check(&profile, &proof).unwrap_err();
        assert!(matches!(
            err,
            PreflightError::InvalidField { field: "instance_column_lens", .. }
        ));
    }

    #[test]
    fn preflight_rejects_invalid_layout() {
        let profile = sample_profile();
        let mut proof = sample_proof();
        proof.proof_layout = Some(ProofLayoutDescriptor {
            commitments_offset: 0,
            num_commitments: 0,
            num_evaluations: 42,
            num_queries: Some(42),
        });
        let err = preflight_check(&profile, &proof).unwrap_err();
        assert!(matches!(
            err,
            PreflightError::InvalidField { field: "proof_layout.num_commitments", .. }
        ));
    }
}
