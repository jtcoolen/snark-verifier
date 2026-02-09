use crate::midnight::{ProofMetadata, ProtocolProfile};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeCompatibility {
    pub supported: bool,
    pub reasons: Vec<String>,
}

impl BridgeCompatibility {
    pub fn check(profile: &ProtocolProfile, proof: &ProofMetadata) -> Self {
        let mut reasons = Vec::new();

        if !profile.pcs.scheme.eq_ignore_ascii_case("KZG")
            || !proof.pcs.scheme.eq_ignore_ascii_case("KZG")
        {
            reasons.push("only KZG PCS is currently supported by the bridge".to_string());
        }

        if !profile.pcs.curve.eq_ignore_ascii_case("BLS12-381")
            || !proof.pcs.curve.eq_ignore_ascii_case("BLS12-381")
        {
            reasons.push("only BLS12-381 curve is currently supported by the bridge".to_string());
        }

        if !profile.transcript.name.eq_ignore_ascii_case("Keccak")
            || !proof.transcript.name.eq_ignore_ascii_case("Keccak")
        {
            reasons.push(
                "transcript must be Keccak on both profile and proof metadata".to_string(),
            );
        }

        if profile.transcript.truncate_challenges || proof.transcript.truncate_challenges {
            reasons.push(
                "truncated challenges are not yet supported by the Solidity bridge".to_string(),
            );
        }

        if profile.circuit.committed_instances || proof.circuit.committed_instances {
            reasons.push(
                "committed instances are not yet supported by the Solidity bridge".to_string(),
            );
        }

        // Current bridge backend does not encode Midnight's additive-selector trash argument.
        if !profile.circuit.trash_mode.eq_ignore_ascii_case("none")
            || !proof.circuit.trash_mode.eq_ignore_ascii_case("none")
        {
            reasons.push(
                "trash argument modes (additive selectors) are not yet supported by the Solidity bridge"
                    .to_string(),
            );
        }

        Self { supported: reasons.is_empty(), reasons }
    }
}

#[cfg(test)]
mod tests {
    use crate::midnight::{
        CircuitProfile, ExpectedShape, PcsProfile, ProofCircuitMetadata, ProofMetadata,
        ProofPcsMetadata, ProofTranscriptMetadata, ProtocolProfile, TranscriptProfile,
    };

    use super::BridgeCompatibility;

    fn profile() -> ProtocolProfile {
        ProtocolProfile {
            profile_id: "poseidon-v1".to_string(),
            protocol_version: "midnight-proofs-0.3".to_string(),
            transcript: TranscriptProfile {
                name: "Keccak".to_string(),
                truncate_challenges: false,
                challenge_bits: None,
                domain_separator: None,
            },
            pcs: PcsProfile {
                scheme: "KZG".to_string(),
                curve: "BLS12-381".to_string(),
                srs_hash: "srs:abc".to_string(),
            },
            circuit: CircuitProfile {
                circuit_id: "poseidon_example".to_string(),
                trash_mode: "none".to_string(),
                committed_instances: false,
            },
            expected: ExpectedShape::default(),
        }
    }

    fn proof() -> ProofMetadata {
        ProofMetadata {
            profile_id: "poseidon-v1".to_string(),
            protocol_version: "midnight-proofs-0.3".to_string(),
            transcript: ProofTranscriptMetadata {
                name: "Keccak".to_string(),
                truncate_challenges: false,
                challenge_bits: None,
                domain_separator: None,
            },
            pcs: ProofPcsMetadata {
                scheme: "KZG".to_string(),
                curve: "BLS12-381".to_string(),
                srs_hash: "srs:abc".to_string(),
                vk_hash: "vk:abc".to_string(),
                vk_inner_version: None,
                vk_domain_k: None,
                vk_num_fixed_commitments: None,
                vk_fixed_commitments_sha256: None,
            },
            circuit: ProofCircuitMetadata {
                circuit_id: "poseidon_example".to_string(),
                trash_mode: "none".to_string(),
                committed_instances: false,
            },
            proof_len_bytes: 864,
            instance_column_lens: vec![1],
            num_queries: None,
            num_evaluations: None,
            proof_layout: None,
            protocol_layout: None,
        }
    }

    #[test]
    fn compatibility_ok_for_current_subset() {
        let report = BridgeCompatibility::check(&profile(), &proof());
        assert!(report.supported);
        assert!(report.reasons.is_empty());
    }

    #[test]
    fn compatibility_rejects_trash_and_truncation() {
        let mut p = profile();
        let mut m = proof();
        p.circuit.trash_mode = "additive_selectors_v1".to_string();
        m.transcript.truncate_challenges = true;
        let report = BridgeCompatibility::check(&p, &m);
        assert!(!report.supported);
        assert!(report.reasons.iter().any(|r| r.contains("trash")));
        assert!(report.reasons.iter().any(|r| r.contains("truncated challenges")));
    }
}
