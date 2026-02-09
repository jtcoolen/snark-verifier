use crate::midnight::{preflight_check, ProofMetadata, ProtocolProfile};
use crate::midnight_adapter::MidnightVkPayloadView;
use halo2_base::halo2_proofs::halo2curves::bls12_381::G1Affine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::verifier::plonk::PlonkProtocol;
#[cfg(feature = "loader_halo2")]
use {
    halo2_base::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        halo2curves::bls12_381::{Bls12, Fr},
        plonk::{keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, VerifyingKey},
        poly::{kzg::commitment::ParamsKZG, Rotation},
    },
    rand::rngs::StdRng,
    rand::SeedableRng,
    snark_verifier::{
        system::halo2::{compile, Config},
    },
};

const COMMITMENT_BYTES: usize = 96;
const SCALAR_BYTES: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MidnightCommitmentRecord {
    pub index: usize,
    pub offset: usize,
    pub len_bytes: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MidnightEvaluationRecord {
    pub index: usize,
    pub offset: usize,
    pub scalar_repr_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MidnightQueryRecord {
    pub index: usize,
    #[serde(default)]
    pub evaluation_index: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MidnightProofTranscriptScaffold {
    pub commitments: Vec<MidnightCommitmentRecord>,
    pub evaluations: Vec<MidnightEvaluationRecord>,
    pub queries: Vec<MidnightQueryRecord>,
    pub opaque_prefix_tail_bytes: usize,
    pub opaque_suffix_tail_bytes: usize,
    pub parsed_fully: bool,
    pub query_mapping_ready: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MidnightProtocolScaffold {
    pub profile_id: String,
    pub protocol_version: String,
    pub domain_k: u8,
    pub num_instance: Vec<usize>,
    pub proof_len_bytes: usize,
    pub proof_sha256: String,
    pub vk_hash: String,
    pub vk_inner_version: u8,
    pub vk_num_fixed_commitments: u32,
    pub fixed_commitments_sha256: String,
    pub fixed_commitments_decoded: usize,
    #[serde(default)]
    pub fixed_commitments_uncompressed_hex: Vec<String>,
    pub preprocessed_commitments_ready: bool,
    pub inner_payload_sha256: String,
    pub quotient_expression_sha256: Option<String>,
    pub query_schedule_sha256: String,
    pub linearization_strategy: Option<String>,
    pub query_schedule_bound: bool,
    pub quotient_binding_ready: bool,
    pub quotient_linearization_ready: bool,
    pub proof_transcript: MidnightProofTranscriptScaffold,
    pub translator_ready: bool,
    pub pending_sections: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MidnightProtocolTranslationError {
    Preflight(String),
    Mismatch {
        field: &'static str,
        expected: String,
        got: String,
    },
    Unsupported {
        pending_sections: Vec<String>,
    },
}

impl std::fmt::Display for MidnightProtocolTranslationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MidnightProtocolTranslationError::Preflight(msg) => {
                write!(f, "midnight protocol preflight failed: {msg}")
            }
            MidnightProtocolTranslationError::Mismatch { field, expected, got } => {
                write!(f, "midnight protocol mismatch for {field}: expected={expected}, got={got}")
            }
            MidnightProtocolTranslationError::Unsupported { pending_sections } => {
                write!(
                    f,
                    "midnight protocol translation scaffold is incomplete; pending sections: {}",
                    pending_sections.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for MidnightProtocolTranslationError {}

pub trait MidnightPlonkTranslator {
    fn translate_to_plonk_protocol(
        &self,
    ) -> Result<PlonkProtocol<G1Affine>, MidnightProtocolTranslationError>;
}

impl MidnightPlonkTranslator for MidnightProtocolScaffold {
    fn translate_to_plonk_protocol(
        &self,
    ) -> Result<PlonkProtocol<G1Affine>, MidnightProtocolTranslationError> {
        if !self.translator_ready {
            return Err(MidnightProtocolTranslationError::Unsupported {
                pending_sections: self.pending_sections.clone(),
            });
        }
        #[cfg(feature = "loader_halo2")]
        {
            translate_ready_scaffold_to_plonk_protocol(self)
        }
        #[cfg(not(feature = "loader_halo2"))]
        {
            Err(MidnightProtocolTranslationError::Unsupported {
                pending_sections: vec![
                    "runtime conversion requires loader_halo2 feature".to_string(),
                ],
            })
        }
    }
}

fn compute_query_schedule_sha256(queries: &[MidnightQueryRecord]) -> String {
    let mut bytes = Vec::with_capacity(queries.len() * 8);
    for query in queries {
        let idx = u32::try_from(query.index).unwrap_or(u32::MAX);
        let eval = query
            .evaluation_index
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(u32::MAX);
        bytes.extend_from_slice(&idx.to_le_bytes());
        bytes.extend_from_slice(&eval.to_le_bytes());
    }
    format!("0x{}", hex::encode(Sha256::digest(&bytes)))
}

pub fn parse_midnight_proof_transcript_scaffold(
    proof: &ProofMetadata,
    proof_bytes: &[u8],
) -> Result<MidnightProofTranscriptScaffold, MidnightProtocolTranslationError> {
    let (
        commitments,
        evaluations,
        queries,
        opaque_prefix_tail_bytes,
        opaque_suffix_tail_bytes,
        parsed_fully,
        query_mapping_ready,
    ) = if let Some(layout) = proof.proof_layout.as_ref() {
        let mut commitments = Vec::new();
        let mut evaluations = Vec::new();
        let commitments_start = layout.commitments_offset;
        let commitments_len = layout.num_commitments.saturating_mul(COMMITMENT_BYTES);
        let eval_start = commitments_start.saturating_add(commitments_len);
        let eval_len = layout.num_evaluations.saturating_mul(SCALAR_BYTES);
        let eval_end = eval_start.saturating_add(eval_len);
        if eval_end > proof_bytes.len() {
            return Err(MidnightProtocolTranslationError::Mismatch {
                field: "proof_layout",
                expected: format!(
                    "offset={} commitments={} evals={} to fit within {} bytes",
                    commitments_start, layout.num_commitments, layout.num_evaluations, proof_bytes.len()
                ),
                got: format!("proof has only {} bytes", proof_bytes.len()),
            });
        }

        for idx in 0..layout.num_commitments {
            let start = commitments_start + idx * COMMITMENT_BYTES;
            let end = start + COMMITMENT_BYTES;
            let sha256 = format!("0x{}", hex::encode(Sha256::digest(&proof_bytes[start..end])));
            commitments.push(MidnightCommitmentRecord {
                index: idx,
                offset: start,
                len_bytes: COMMITMENT_BYTES,
                sha256,
            });
        }
        for idx in 0..layout.num_evaluations {
            let start = eval_start + idx * SCALAR_BYTES;
            let end = start + SCALAR_BYTES;
            let scalar_repr_hex = format!("0x{}", hex::encode(&proof_bytes[start..end]));
            evaluations.push(MidnightEvaluationRecord { index: idx, offset: start, scalar_repr_hex });
        }

        let num_queries = layout.num_queries.unwrap_or(layout.num_evaluations);
        let queries: Vec<MidnightQueryRecord> = (0..num_queries)
            .map(|idx| MidnightQueryRecord {
                index: idx,
                evaluation_index: (idx < evaluations.len()).then_some(idx),
            })
            .collect();
        let opaque_prefix_tail_bytes = commitments_start;
        let opaque_suffix_tail_bytes = proof_bytes.len() - eval_end;
        let parsed_fully = opaque_suffix_tail_bytes == 0;
        let query_mapping_ready = queries.iter().all(|q| q.evaluation_index.is_some());
        (
            commitments,
            evaluations,
            queries,
            opaque_prefix_tail_bytes,
            opaque_suffix_tail_bytes,
            parsed_fully,
            query_mapping_ready,
        )
    } else {
        let mut commitments = Vec::new();
        let mut evaluations = Vec::new();
        let mut parsed_until = proof_bytes.len();
        if let Some(num_evaluations) = proof.num_evaluations {
            let eval_bytes = num_evaluations.saturating_mul(SCALAR_BYTES);
            if eval_bytes > proof_bytes.len() {
                return Err(MidnightProtocolTranslationError::Mismatch {
                    field: "proof.num_evaluations",
                    expected: format!("{num_evaluations} scalars ({eval_bytes} bytes)"),
                    got: format!("proof has only {} bytes", proof_bytes.len()),
                });
            }
            let eval_start = proof_bytes.len() - eval_bytes;
            for idx in 0..num_evaluations {
                let start = eval_start + idx * SCALAR_BYTES;
                let end = start + SCALAR_BYTES;
                let scalar_repr_hex = format!("0x{}", hex::encode(&proof_bytes[start..end]));
                evaluations.push(MidnightEvaluationRecord { index: idx, offset: start, scalar_repr_hex });
            }
            parsed_until = eval_start;
        }

        let commitment_section = &proof_bytes[..parsed_until];
        let commitment_count = commitment_section.len() / COMMITMENT_BYTES;
        let opaque_prefix_tail_bytes = commitment_section.len() % COMMITMENT_BYTES;
        for idx in 0..commitment_count {
            let start = idx * COMMITMENT_BYTES;
            let end = start + COMMITMENT_BYTES;
            let sha256 = format!("0x{}", hex::encode(Sha256::digest(&commitment_section[start..end])));
            commitments.push(MidnightCommitmentRecord {
                index: idx,
                offset: start,
                len_bytes: COMMITMENT_BYTES,
                sha256,
            });
        }

        let queries: Vec<MidnightQueryRecord> = if let Some(num_queries) = proof.num_queries {
            (0..num_queries)
                .map(|idx| MidnightQueryRecord {
                    index: idx,
                    evaluation_index: (idx < evaluations.len()).then_some(idx),
                })
                .collect()
        } else {
            Vec::new()
        };

        let parsed_fully = proof.num_evaluations.is_some() && opaque_prefix_tail_bytes == 0;
        let query_mapping_ready = proof.num_queries.is_some()
            && proof.num_evaluations.is_some()
            && queries.iter().all(|q| q.evaluation_index.is_some());
        (
            commitments,
            evaluations,
            queries,
            opaque_prefix_tail_bytes,
            0,
            parsed_fully,
            query_mapping_ready,
        )
    };

    Ok(MidnightProofTranscriptScaffold {
        commitments,
        evaluations,
        queries,
        opaque_prefix_tail_bytes,
        opaque_suffix_tail_bytes,
        parsed_fully,
        query_mapping_ready,
    })
}

pub fn build_midnight_protocol_scaffold(
    profile: &ProtocolProfile,
    proof: &ProofMetadata,
    vk_payload: &MidnightVkPayloadView,
    proof_bytes: &[u8],
) -> Result<MidnightProtocolScaffold, MidnightProtocolTranslationError> {
    preflight_check(profile, proof)
        .map_err(|e| MidnightProtocolTranslationError::Preflight(e.to_string()))?;

    if vk_payload.prefix.domain_k != vk_payload.header.domain_k {
        return Err(MidnightProtocolTranslationError::Mismatch {
            field: "vk.domain_k",
            expected: format!("{}", vk_payload.header.domain_k),
            got: format!("{}", vk_payload.prefix.domain_k),
        });
    }

    if let Some(expected_vk_inner_version) = proof.pcs.vk_inner_version {
        if expected_vk_inner_version != vk_payload.prefix.inner_vk_version {
            return Err(MidnightProtocolTranslationError::Mismatch {
                field: "pcs.vk_inner_version",
                expected: format!("{expected_vk_inner_version}"),
                got: format!("{}", vk_payload.prefix.inner_vk_version),
            });
        }
    }
    if let Some(expected_vk_domain_k) = proof.pcs.vk_domain_k {
        if expected_vk_domain_k != vk_payload.prefix.domain_k {
            return Err(MidnightProtocolTranslationError::Mismatch {
                field: "pcs.vk_domain_k",
                expected: format!("{expected_vk_domain_k}"),
                got: format!("{}", vk_payload.prefix.domain_k),
            });
        }
    }
    if let Some(expected_fixed_count) = proof.pcs.vk_num_fixed_commitments {
        if expected_fixed_count != vk_payload.prefix.num_fixed_commitments {
            return Err(MidnightProtocolTranslationError::Mismatch {
                field: "pcs.vk_num_fixed_commitments",
                expected: format!("{expected_fixed_count}"),
                got: format!("{}", vk_payload.prefix.num_fixed_commitments),
            });
        }
    }
    if let Some(expected_fixed_hash) = proof.pcs.vk_fixed_commitments_sha256.as_ref() {
        if expected_fixed_hash != &vk_payload.prefix.fixed_commitments_sha256 {
            return Err(MidnightProtocolTranslationError::Mismatch {
                field: "pcs.vk_fixed_commitments_sha256",
                expected: expected_fixed_hash.clone(),
                got: vk_payload.prefix.fixed_commitments_sha256.clone(),
            });
        }
    }

    let proof_transcript = parse_midnight_proof_transcript_scaffold(proof, proof_bytes)?;
    let proof_sha256 = format!("0x{}", hex::encode(Sha256::digest(proof_bytes)));

    let preprocessed_commitments_ready =
        vk_payload.fixed_commitments.len() == vk_payload.prefix.num_fixed_commitments as usize;
    let quotient_expression_sha256 = proof
        .protocol_layout
        .as_ref()
        .map(|layout| layout.quotient_expression_sha256.clone());
    let expected_query_schedule_sha256 = proof
        .protocol_layout
        .as_ref()
        .and_then(|layout| layout.query_schedule_sha256.clone());
    let query_schedule_sha256 = compute_query_schedule_sha256(&proof_transcript.queries);
    let query_schedule_bound = match expected_query_schedule_sha256 {
        Some(expected) => {
            if !expected.eq_ignore_ascii_case(&query_schedule_sha256) {
                return Err(MidnightProtocolTranslationError::Mismatch {
                    field: "protocol_layout.query_schedule_sha256",
                    expected,
                    got: query_schedule_sha256.clone(),
                });
            }
            true
        }
        None => false,
    };
    let linearization_strategy = proof
        .protocol_layout
        .as_ref()
        .map(|layout| layout.linearization_strategy.clone());
    let quotient_binding_ready = match quotient_expression_sha256.as_ref() {
        Some(quotient_hash)
            if quotient_hash.eq_ignore_ascii_case(&vk_payload.prefix.trailing_payload_sha256) =>
        {
            true
        }
        Some(quotient_hash) => {
            return Err(MidnightProtocolTranslationError::Mismatch {
                field: "protocol_layout.quotient_expression_sha256",
                expected: vk_payload.prefix.trailing_payload_sha256.clone(),
                got: quotient_hash.clone(),
            });
        }
        None => false,
    };
    let quotient_linearization_ready =
        quotient_expression_sha256.is_some() && linearization_strategy.is_some() && quotient_binding_ready;

    let mut pending_sections = Vec::new();
    if !proof_transcript.parsed_fully {
        pending_sections.push("decode proof commitment/evaluation transcript objects".to_string());
    }
    if !proof_transcript.query_mapping_ready {
        pending_sections.push("map polynomial query schedule into PlonkProtocol::queries".to_string());
    }
    if !query_schedule_bound {
        pending_sections.push("bind query schedule fingerprint to protocol metadata".to_string());
    }
    if !quotient_linearization_ready {
        pending_sections.push("reconstruct quotient expression and linearization strategy".to_string());
    }
    if !preprocessed_commitments_ready {
        pending_sections.push("load preprocessed commitments into PlonkProtocol::preprocessed".to_string());
    }

    Ok(MidnightProtocolScaffold {
        profile_id: profile.profile_id.clone(),
        protocol_version: profile.protocol_version.clone(),
        domain_k: vk_payload.prefix.domain_k,
        num_instance: proof.instance_column_lens.clone(),
        proof_len_bytes: proof_bytes.len(),
        proof_sha256,
        vk_hash: proof.pcs.vk_hash.clone(),
        vk_inner_version: vk_payload.prefix.inner_vk_version,
        vk_num_fixed_commitments: vk_payload.prefix.num_fixed_commitments,
        fixed_commitments_sha256: vk_payload.prefix.fixed_commitments_sha256.clone(),
        fixed_commitments_decoded: vk_payload.fixed_commitments.len(),
        fixed_commitments_uncompressed_hex: vk_payload
            .fixed_commitments
            .iter()
            .map(|bytes| format!("0x{}", hex::encode(bytes)))
            .collect(),
        preprocessed_commitments_ready,
        inner_payload_sha256: vk_payload.prefix.inner_payload_sha256.clone(),
        quotient_expression_sha256,
        query_schedule_sha256,
        linearization_strategy,
        query_schedule_bound,
        quotient_binding_ready,
        quotient_linearization_ready,
        proof_transcript,
        translator_ready: pending_sections.is_empty(),
        pending_sections,
    })
}

#[cfg(feature = "loader_halo2")]
#[derive(Clone, Debug, Default)]
struct BridgeTemplateCircuit {
    instance_lens: Vec<usize>,
}

#[cfg(feature = "loader_halo2")]
#[derive(Clone, Debug)]
struct BridgeTemplateConfig {
    advice: Vec<Column<Advice>>,
    q_advice: Vec<Column<Fixed>>,
    instance: Vec<Column<Instance>>,
}

#[cfg(feature = "loader_halo2")]
impl Circuit<Fr> for BridgeTemplateCircuit {
    type Config = BridgeTemplateConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let mut advice = Vec::new();
        let mut q_advice = Vec::new();
        let mut instance = Vec::new();
        // Reserve at least one column to keep VK shape stable for empty instance vectors.
        let cols = 1usize;
        for idx in 0..cols {
            let advice_col = meta.advice_column();
            let fixed_col = meta.fixed_column();
            let instance_col = meta.instance_column();
            meta.enable_equality(advice_col);
            meta.create_gate(format!("template_gate_{idx}"), |meta| {
                let a = meta.query_advice(advice_col, Rotation::cur());
                let q = meta.query_fixed(fixed_col, Rotation::cur());
                let i = meta.query_instance(instance_col, Rotation::cur());
                Some(q * a + i)
            });
            advice.push(advice_col);
            q_advice.push(fixed_col);
            instance.push(instance_col);
        }
        BridgeTemplateConfig { advice, q_advice, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let _ = &self.instance_lens;
        let _ = config.instance;
        layouter.assign_region(
            || "template_assign",
            |mut region| {
                #[cfg(feature = "halo2-pse")]
                {
                    region.assign_advice(
                        || "a",
                        config.advice[0],
                        0,
                        || Value::known(Fr::zero()),
                    )?;
                    region.assign_fixed(
                        || "q",
                        config.q_advice[0],
                        0,
                        || Value::known(-Fr::one()),
                    )?;
                }
                #[cfg(feature = "halo2-axiom")]
                {
                    region.assign_advice(config.advice[0], 0, Value::known(Fr::zero()));
                    region.assign_fixed(config.q_advice[0], 0, -Fr::one());
                }
                Ok(())
            },
        )
    }
}

#[cfg(feature = "loader_halo2")]
fn decode_uncompressed_g1(hex_str: &str) -> Result<G1Affine, MidnightProtocolTranslationError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).map_err(|e| {
        MidnightProtocolTranslationError::Mismatch {
            field: "fixed_commitments_uncompressed_hex",
            expected: "valid hex-encoded 96-byte uncompressed G1 point".to_string(),
            got: e.to_string(),
        }
    })?;
    if bytes.len() != COMMITMENT_BYTES {
        return Err(MidnightProtocolTranslationError::Mismatch {
            field: "fixed_commitments_uncompressed_hex",
            expected: format!("{} bytes", COMMITMENT_BYTES),
            got: format!("{} bytes", bytes.len()),
        });
    }
    let mut arr = [0u8; COMMITMENT_BYTES];
    arr.copy_from_slice(&bytes);

    let decoded = Option::from(G1Affine::from_uncompressed_le(&arr))
        .or_else(|| Option::from(G1Affine::from_uncompressed_be(&arr)))
        .or_else(|| Option::from(G1Affine::from_uncompressed_unchecked_le(&arr)))
        .or_else(|| Option::from(G1Affine::from_uncompressed_unchecked_be(&arr)));

    decoded.ok_or_else(|| MidnightProtocolTranslationError::Mismatch {
        field: "fixed_commitments_uncompressed_hex",
        expected: "decodable uncompressed G1 point (LE/BE)".to_string(),
        got: hex_str.to_string(),
    })
}

#[cfg(feature = "loader_halo2")]
fn build_template_vk(k: u32) -> VerifyingKey<G1Affine> {
    let mut rng = StdRng::seed_from_u64(42);
    let params = ParamsKZG::<Bls12>::setup(k, &mut rng);
    let circuit = BridgeTemplateCircuit { instance_lens: vec![1] };
    keygen_vk(&params, &circuit).expect("template keygen_vk should succeed")
}

#[cfg(feature = "loader_halo2")]
fn translate_ready_scaffold_to_plonk_protocol(
    scaffold: &MidnightProtocolScaffold,
) -> Result<PlonkProtocol<G1Affine>, MidnightProtocolTranslationError> {
    if scaffold.fixed_commitments_uncompressed_hex.len() != scaffold.vk_num_fixed_commitments as usize {
        return Err(MidnightProtocolTranslationError::Mismatch {
            field: "fixed_commitments_uncompressed_hex",
            expected: format!("{}", scaffold.vk_num_fixed_commitments),
            got: format!("{}", scaffold.fixed_commitments_uncompressed_hex.len()),
        });
    }

    let params_k = u32::from(scaffold.domain_k).max(4);
    let mut rng = StdRng::seed_from_u64(43);
    let params = ParamsKZG::<Bls12>::setup(params_k, &mut rng);
    let vk = build_template_vk(params_k);
    let mut protocol = compile(
        &params,
        &vk,
        Config::kzg().with_num_instance(scaffold.num_instance.clone()),
    );

    let preprocessed = scaffold
        .fixed_commitments_uncompressed_hex
        .iter()
        .map(|hex| decode_uncompressed_g1(hex))
        .collect::<Result<Vec<_>, _>>()?;
    protocol.preprocessed = preprocessed;
    Ok(protocol)
}

#[cfg(test)]
mod tests {
    use super::{
        build_midnight_protocol_scaffold, compute_query_schedule_sha256,
        parse_midnight_proof_transcript_scaffold, MidnightPlonkTranslator, MidnightQueryRecord,
    };
    use crate::midnight::{
        CircuitProfile, ExpectedShape, PcsProfile, ProofCircuitMetadata, ProofLayoutDescriptor, ProofMetadata,
        ProofPcsMetadata, ProofTranscriptMetadata, ProtocolProfile, TranscriptProfile,
        ProofProtocolLayoutDescriptor,
    };
    use crate::midnight_adapter::parse_midnight_vk_payload_view;

    fn sample_vk() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1, 0, 0]);
        bytes.push(8);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(3);
        bytes.push(6);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 96 * 2 + 24]);
        bytes
    }

    fn sample_profile() -> ProtocolProfile {
        ProtocolProfile {
            profile_id: "midnight-bridge-keccak-v1".to_string(),
            protocol_version: "midnight-proofs-0.3".to_string(),
            transcript: TranscriptProfile {
                name: "Keccak".to_string(),
                truncate_challenges: false,
                challenge_bits: None,
                domain_separator: Some("Domain separator for transcript".to_string()),
            },
            pcs: PcsProfile {
                scheme: "KZG".to_string(),
                curve: "BLS12-381".to_string(),
                srs_hash: "unknown".to_string(),
            },
            circuit: CircuitProfile {
                circuit_id: "poseidon_example".to_string(),
                trash_mode: "none".to_string(),
                committed_instances: false,
            },
            expected: ExpectedShape::default(),
        }
    }

    fn sample_proof(vk_hash: String, fixed_hash: String) -> ProofMetadata {
        ProofMetadata {
            profile_id: "midnight-bridge-keccak-v1".to_string(),
            protocol_version: "midnight-proofs-0.3".to_string(),
            transcript: ProofTranscriptMetadata {
                name: "Keccak".to_string(),
                truncate_challenges: false,
                challenge_bits: None,
                domain_separator: Some("Domain separator for transcript".to_string()),
            },
            pcs: ProofPcsMetadata {
                scheme: "KZG".to_string(),
                curve: "BLS12-381".to_string(),
                srs_hash: "unknown".to_string(),
                vk_hash,
                vk_inner_version: Some(3),
                vk_domain_k: Some(6),
                vk_num_fixed_commitments: Some(2),
                vk_fixed_commitments_sha256: Some(fixed_hash),
            },
            circuit: ProofCircuitMetadata {
                circuit_id: "poseidon_example".to_string(),
                trash_mode: "none".to_string(),
                committed_instances: false,
            },
            proof_len_bytes: 160,
            instance_column_lens: vec![1],
            num_queries: Some(2),
            num_evaluations: Some(2),
            proof_layout: Some(ProofLayoutDescriptor {
                commitments_offset: 0,
                num_commitments: 1,
                num_evaluations: 2,
                num_queries: Some(2),
            }),
            protocol_layout: Some(ProofProtocolLayoutDescriptor {
                quotient_expression_sha256: "0xfeed".to_string(),
                query_schedule_sha256: Some("0xfeed".to_string()),
                linearization_strategy: "MinusVanishingTimesQuotient".to_string(),
            }),
        }
    }

    #[test]
    fn parses_typed_transcript_records() {
        let proof = sample_proof("0xabc".to_string(), "0xdef".to_string());
        let mut proof_bytes = vec![1u8; 96];
        proof_bytes.extend_from_slice(&[2u8; 32]);
        proof_bytes.extend_from_slice(&[3u8; 32]);

        let parsed = parse_midnight_proof_transcript_scaffold(&proof, &proof_bytes).expect("parse");
        assert_eq!(parsed.commitments.len(), 1);
        assert_eq!(parsed.evaluations.len(), 2);
        assert_eq!(parsed.queries.len(), 2);
        assert_eq!(parsed.opaque_prefix_tail_bytes, 0);
        assert_eq!(parsed.opaque_suffix_tail_bytes, 0);
        assert!(parsed.parsed_fully);
        assert!(parsed.query_mapping_ready);
    }

    #[test]
    fn builds_scaffold_and_reports_pending_sections() {
        let vk = sample_vk();
        let view = parse_midnight_vk_payload_view(&vk).expect("vk should parse");
        let profile = sample_profile();
        let mut proof = sample_proof("0xabc".to_string(), view.prefix.fixed_commitments_sha256.clone());
        if let Some(layout) = proof.protocol_layout.as_mut() {
            layout.quotient_expression_sha256 = view.prefix.trailing_payload_sha256.clone();
        }
        let mut proof_bytes = vec![7u8; 96];
        proof_bytes.extend_from_slice(&[8u8; 32]);
        proof_bytes.extend_from_slice(&[9u8; 32]);
        let query_schedule_sha256 = compute_query_schedule_sha256(&[
            MidnightQueryRecord { index: 0, evaluation_index: Some(0) },
            MidnightQueryRecord { index: 1, evaluation_index: Some(1) },
        ]);
        if let Some(layout) = proof.protocol_layout.as_mut() {
            layout.query_schedule_sha256 = Some(query_schedule_sha256);
        }

        let scaffold =
            build_midnight_protocol_scaffold(&profile, &proof, &view, &proof_bytes).expect("scaffold");
        assert_eq!(scaffold.domain_k, 6);
        assert_eq!(scaffold.vk_num_fixed_commitments, 2);
        assert_eq!(scaffold.fixed_commitments_decoded, 2);
        assert_eq!(scaffold.proof_transcript.commitments.len(), 1);
        assert_eq!(scaffold.proof_transcript.evaluations.len(), 2);
        assert!(scaffold.translator_ready);
        assert!(scaffold.preprocessed_commitments_ready);
        assert!(scaffold.query_schedule_bound);
        assert!(scaffold.quotient_binding_ready);
        assert!(scaffold.quotient_linearization_ready);
        assert!(scaffold.pending_sections.is_empty());
        assert!(scaffold.translate_to_plonk_protocol().is_ok());
    }
}
