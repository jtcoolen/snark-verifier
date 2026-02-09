use halo2_base::halo2_proofs::halo2curves::bls12_381::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField as CurvePrimeField;
use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};
use snark_verifier_sdk::evm::write_calldata;
use snark_verifier_sdk::midnight_adapter::ensure_midnight_adapter_ready;
use snark_verifier_sdk::midnight::{
    CircuitProfile, ExpectedShape, PcsProfile, ProofCircuitMetadata, ProofMetadata,
    ProofLayoutDescriptor, ProofPcsMetadata, ProofProtocolLayoutDescriptor, ProofTranscriptMetadata,
    ProtocolProfile,
    TranscriptProfile,
};
use snark_verifier_sdk::midnight_bridge_build::{build_from_metadata, BridgeBuildConfig};
use snark_verifier_sdk::midnight_protocol_bridge::{
    build_midnight_protocol_scaffold, MidnightPlonkTranslator,
};
use snark_verifier_sdk::midnight_vk::parse_midnight_vk_header;
use std::{env, fs, path::PathBuf, process::exit};

fn parse_bool_env(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "True"),
        Err(_) => default,
    }
}

fn parse_usize_env(key: &str) -> Option<usize> {
    env::var(key).ok().and_then(|v| v.parse::<usize>().ok())
}

fn derive_layout_descriptor(proof_len: usize, min_commitments: usize) -> ProofLayoutDescriptor {
    let max_evaluations = proof_len / 32;
    for num_evaluations in (0..=max_evaluations).rev() {
        let eval_bytes = num_evaluations * 32;
        if eval_bytes > proof_len {
            continue;
        }
        let remaining = proof_len - eval_bytes;
        let num_commitments = remaining / 96;
        let commitments_offset = remaining % 96;
        if num_commitments >= min_commitments {
            return ProofLayoutDescriptor {
                commitments_offset,
                num_commitments,
                num_evaluations,
                num_queries: Some(num_evaluations),
            };
        }
    }

    ProofLayoutDescriptor {
        commitments_offset: proof_len % 96,
        num_commitments: proof_len / 96,
        num_evaluations: 0,
        num_queries: Some(0),
    }
}

fn parse_scalar(s: &str) -> Result<Fr, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        let n = BigUint::from_str_radix(hex, 16)
            .map_err(|e| format!("invalid hex scalar '{s}': {e}"))?;
        let mut repr = <Fr as CurvePrimeField>::Repr::default();
        let le = n.to_bytes_le();
        if le.len() > repr.as_mut().len() {
            return Err(format!("hex scalar out of 32-byte range: {s}"));
        }
        repr.as_mut()[..le.len()].copy_from_slice(&le);
        let parsed = Option::from(Fr::from_repr(repr))
            .ok_or_else(|| format!("scalar not in field range: {s}"))?;
        return Ok(parsed);
    }

    let n = BigUint::from_str_radix(s, 10)
        .map_err(|e| format!("invalid decimal scalar '{s}': {e}"))?;
    let mut repr = <Fr as CurvePrimeField>::Repr::default();
    let le = n.to_bytes_le();
    if le.len() > repr.as_mut().len() {
        return Err(format!("decimal scalar out of 32-byte range: {s}"));
    }
    repr.as_mut()[..le.len()].copy_from_slice(&le);
    Option::from(Fr::from_repr(repr)).ok_or_else(|| format!("scalar not in field range: {s}"))
}

fn read_instances_json(path: &str) -> Result<Vec<Vec<Fr>>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed reading {path}: {e}"))?;
    let parsed: Vec<Vec<String>> =
        serde_json::from_str(&raw).map_err(|e| format!("failed parsing {path} as JSON: {e}"))?;
    parsed
        .into_iter()
        .map(|col| col.into_iter().map(|x| parse_scalar(&x)).collect())
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn derive_query_schedule_sha256(num_queries: usize, num_evaluations: usize) -> String {
    let mut bytes = Vec::with_capacity(num_queries * 8);
    for idx in 0..num_queries {
        let query_idx = u32::try_from(idx).unwrap_or(u32::MAX);
        let eval_idx = if idx < num_evaluations {
            u32::try_from(idx).unwrap_or(u32::MAX)
        } else {
            u32::MAX
        };
        bytes.extend_from_slice(&query_idx.to_le_bytes());
        bytes.extend_from_slice(&eval_idx.to_le_bytes());
    }
    format!("0x{}", hex::encode(Sha256::digest(&bytes)))
}

fn main() {
    let mut args = env::args().skip(1);
    let vk_path = match args.next() {
        Some(v) => v,
        None => {
            eprintln!(
                "usage: midnight_bridge_import <vk.bin> <proof.bin> <instances.json> [output_stem]"
            );
            exit(2);
        }
    };
    let proof_path = match args.next() {
        Some(v) => v,
        None => {
            eprintln!(
                "usage: midnight_bridge_import <vk.bin> <proof.bin> <instances.json> [output_stem]"
            );
            exit(2);
        }
    };
    let instances_path = match args.next() {
        Some(v) => v,
        None => {
            eprintln!(
                "usage: midnight_bridge_import <vk.bin> <proof.bin> <instances.json> [output_stem]"
            );
            exit(2);
        }
    };
    let output_stem =
        args.next().unwrap_or_else(|| "examples/midnight_bridge_poseidon_import".to_string());
    if args.next().is_some() {
        eprintln!("usage: midnight_bridge_import <vk.bin> <proof.bin> <instances.json> [output_stem]");
        exit(2);
    }

    let vk_bytes = match fs::read(&vk_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed reading vk bytes from {vk_path}: {e}");
            exit(2);
        }
    };
    let vk_header = match parse_midnight_vk_header(&vk_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed parsing midnight vk header from {vk_path}: {e}");
            exit(2);
        }
    };
    let vk_payload_view = match ensure_midnight_adapter_ready(&vk_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("midnight adapter precheck failed for {vk_path}: {e}");
            exit(2);
        }
    };
    if vk_header.domain_k != vk_payload_view.prefix.domain_k {
        eprintln!(
            "vk k mismatch: header domain_k={}, inner payload domain_k={}",
            vk_header.domain_k, vk_payload_view.prefix.domain_k
        );
        exit(1);
    }
    let proof_bytes = match fs::read(&proof_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed reading proof bytes from {proof_path}: {e}");
            exit(2);
        }
    };
    let explicit_layout = (
        parse_usize_env("MIDNIGHT_LAYOUT_COMMITMENTS_OFFSET"),
        parse_usize_env("MIDNIGHT_LAYOUT_NUM_COMMITMENTS"),
        parse_usize_env("MIDNIGHT_LAYOUT_NUM_EVALUATIONS"),
        parse_usize_env("MIDNIGHT_LAYOUT_NUM_QUERIES"),
    );
    let (layout_descriptor, layout_mode) = match explicit_layout {
        (Some(commitments_offset), Some(num_commitments), Some(num_evaluations), num_queries) => (
            ProofLayoutDescriptor {
                commitments_offset,
                num_commitments,
                num_evaluations,
                num_queries,
            },
            "explicit",
        ),
        (None, None, None, None) => (
            derive_layout_descriptor(
                proof_bytes.len(),
                vk_payload_view.prefix.num_fixed_commitments as usize,
            ),
            "derived",
        ),
        _ => {
            eprintln!(
                "invalid MIDNIGHT_LAYOUT_* override: set all of MIDNIGHT_LAYOUT_COMMITMENTS_OFFSET, MIDNIGHT_LAYOUT_NUM_COMMITMENTS, MIDNIGHT_LAYOUT_NUM_EVALUATIONS (MIDNIGHT_LAYOUT_NUM_QUERIES optional), or set none"
            );
            exit(2);
        }
    };
    let instances = match read_instances_json(&instances_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            exit(2);
        }
    };
    if instances.is_empty() {
        eprintln!("invalid instances shape: at least one instance column is required");
        exit(1);
    }
    if instances.iter().any(|col| col.is_empty()) {
        eprintln!("invalid instances shape: instance columns must be non-empty");
        exit(1);
    }
    let total_instances = instances.iter().map(Vec::len).sum::<usize>();
    if total_instances != vk_header.nb_public_inputs {
        eprintln!(
            "instance/public-input mismatch: instances.json has {total_instances} total scalars, vk.bin expects {}",
            vk_header.nb_public_inputs
        );
        exit(1);
    }
    if !vk_header.arch.bridge_subset_supported() {
        eprintln!(
            "vk architecture is outside current bridge subset: arch={:?}",
            vk_header.arch
        );
        eprintln!(
            "required subset: poseidon=true and all other chips/verifier=false (with committed instances disabled)"
        );
        exit(1);
    }
    let instance_lens = instances.iter().map(Vec::len).collect::<Vec<_>>();

    let profile = ProtocolProfile {
        profile_id: env::var("MIDNIGHT_PROFILE_ID")
            .unwrap_or_else(|_| "midnight-bridge-keccak-v1".to_string()),
        protocol_version: env::var("MIDNIGHT_PROTOCOL_VERSION")
            .unwrap_or_else(|_| "midnight-proofs-0.3".to_string()),
        transcript: TranscriptProfile {
            name: env::var("MIDNIGHT_TRANSCRIPT").unwrap_or_else(|_| "Keccak".to_string()),
            truncate_challenges: parse_bool_env("MIDNIGHT_TRUNCATE_CHALLENGES", false),
            challenge_bits: env::var("MIDNIGHT_CHALLENGE_BITS")
                .ok()
                .and_then(|v| v.parse::<u16>().ok()),
            domain_separator: env::var("MIDNIGHT_DOMAIN_SEPARATOR")
                .ok()
                .or(Some("Domain separator for transcript".to_string())),
        },
        pcs: PcsProfile {
            scheme: env::var("MIDNIGHT_PCS_SCHEME").unwrap_or_else(|_| "KZG".to_string()),
            curve: env::var("MIDNIGHT_PCS_CURVE").unwrap_or_else(|_| "BLS12-381".to_string()),
            srs_hash: env::var("MIDNIGHT_SRS_HASH").unwrap_or_else(|_| "unknown".to_string()),
        },
        circuit: CircuitProfile {
            circuit_id: env::var("MIDNIGHT_CIRCUIT_ID")
                .unwrap_or_else(|_| "poseidon_example".to_string()),
            trash_mode: env::var("MIDNIGHT_TRASH_MODE").unwrap_or_else(|_| "none".to_string()),
            committed_instances: parse_bool_env("MIDNIGHT_COMMITTED_INSTANCES", false),
        },
        expected: ExpectedShape {
            vk_hash: Some(sha256_hex(&vk_bytes)),
            proof_len_bytes: Some(proof_bytes.len()),
            instance_column_lens: Some(instance_lens.clone()),
            num_queries: layout_descriptor.num_queries,
            num_evaluations: Some(layout_descriptor.num_evaluations),
            vk_inner_version: Some(vk_payload_view.prefix.inner_vk_version),
            vk_domain_k: Some(vk_payload_view.prefix.domain_k),
            vk_num_fixed_commitments: Some(vk_payload_view.prefix.num_fixed_commitments),
            vk_fixed_commitments_sha256: Some(
                vk_payload_view.prefix.fixed_commitments_sha256.clone(),
            ),
        },
    };

    let proof = ProofMetadata {
        profile_id: profile.profile_id.clone(),
        protocol_version: profile.protocol_version.clone(),
        transcript: ProofTranscriptMetadata {
            name: profile.transcript.name.clone(),
            truncate_challenges: profile.transcript.truncate_challenges,
            challenge_bits: profile.transcript.challenge_bits,
            domain_separator: profile.transcript.domain_separator.clone(),
        },
        pcs: ProofPcsMetadata {
            scheme: profile.pcs.scheme.clone(),
            curve: profile.pcs.curve.clone(),
            srs_hash: profile.pcs.srs_hash.clone(),
            vk_hash: sha256_hex(&vk_bytes),
            vk_inner_version: Some(vk_payload_view.prefix.inner_vk_version),
            vk_domain_k: Some(vk_payload_view.prefix.domain_k),
            vk_num_fixed_commitments: Some(vk_payload_view.prefix.num_fixed_commitments),
            vk_fixed_commitments_sha256: Some(
                vk_payload_view.prefix.fixed_commitments_sha256.clone(),
            ),
        },
        circuit: ProofCircuitMetadata {
            circuit_id: profile.circuit.circuit_id.clone(),
            trash_mode: profile.circuit.trash_mode.clone(),
            committed_instances: profile.circuit.committed_instances,
        },
        proof_len_bytes: proof_bytes.len(),
        instance_column_lens: instance_lens.clone(),
        num_queries: layout_descriptor.num_queries,
        num_evaluations: Some(layout_descriptor.num_evaluations),
        proof_layout: Some(layout_descriptor.clone()),
        protocol_layout: Some(ProofProtocolLayoutDescriptor {
            quotient_expression_sha256: env::var("MIDNIGHT_QUOTIENT_EXPRESSION_SHA256")
                .unwrap_or_else(|_| vk_payload_view.prefix.trailing_payload_sha256.clone()),
            query_schedule_sha256: Some(
                env::var("MIDNIGHT_QUERY_SCHEDULE_SHA256").unwrap_or_else(|_| {
                    derive_query_schedule_sha256(
                        layout_descriptor
                            .num_queries
                            .unwrap_or(layout_descriptor.num_evaluations),
                        layout_descriptor.num_evaluations,
                    )
                }),
            ),
            linearization_strategy: env::var("MIDNIGHT_LINEARIZATION_STRATEGY")
                .unwrap_or_else(|_| "MinusVanishingTimesQuotient".to_string()),
        }),
    };

    let stem = PathBuf::from(&output_stem);
    let sol_path = stem.with_file_name("MidnightBridgeImportedVerifier.sol");
    let config = BridgeBuildConfig {
        output_stem: stem,
        solidity_path: sol_path,
        vk_k: Some(vk_header.domain_k as u32),
        instance_column_lens: Some(instance_lens.clone()),
    };
    let protocol_scaffold = match build_midnight_protocol_scaffold(
        &profile,
        &proof,
        &vk_payload_view,
        &proof_bytes,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("midnight protocol scaffold failed: {e}");
            exit(1);
        }
    };
    let translation_probe = protocol_scaffold.translate_to_plonk_protocol();

    match build_from_metadata(&profile, &proof, &config) {
        Ok(report) => {
            println!("preflight: {}", if report.preflight_ok { "ok" } else { "failed" });
            println!(
                "bridge_compatible: {}",
                if report.compatibility.supported { "yes" } else { "no" }
            );
            if let Some(artifacts) = report.artifact_report {
                let profile_json_path = PathBuf::from(format!("{output_stem}.protocol_profile.json"));
                let proof_json_path = PathBuf::from(format!("{output_stem}.proof_metadata.json"));
                let protocol_scaffold_json_path =
                    PathBuf::from(format!("{output_stem}.protocol_translation_scaffold.json"));
                let profile_json = match serde_json::to_vec_pretty(&profile) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("failed serializing derived protocol profile JSON: {e}");
                        exit(1);
                    }
                };
                let proof_json = match serde_json::to_vec_pretty(&proof) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("failed serializing derived proof metadata JSON: {e}");
                        exit(1);
                    }
                };
                let protocol_scaffold_json =
                    match serde_json::to_vec_pretty(&protocol_scaffold) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "failed serializing protocol translation scaffold JSON: {e}"
                            );
                            exit(1);
                        }
                    };
                if let Err(e) = fs::write(&profile_json_path, profile_json) {
                    eprintln!(
                        "failed writing derived protocol profile JSON to {}: {e}",
                        profile_json_path.display()
                    );
                    exit(1);
                }
                if let Err(e) = fs::write(&proof_json_path, proof_json) {
                    eprintln!(
                        "failed writing derived proof metadata JSON to {}: {e}",
                        proof_json_path.display()
                    );
                    exit(1);
                }
                if let Err(e) = fs::write(&protocol_scaffold_json_path, protocol_scaffold_json) {
                    eprintln!(
                        "failed writing protocol translation scaffold JSON to {}: {e}",
                        protocol_scaffold_json_path.display()
                    );
                    exit(1);
                }
                if let Err(e) = fs::write(&artifacts.proof_path, &proof_bytes) {
                    eprintln!(
                        "failed writing imported proof to {}: {e}",
                        artifacts.proof_path.display()
                    );
                    exit(1);
                }
                if let Err(e) = write_calldata(&instances, &proof_bytes, &artifacts.calldata_path) {
                    eprintln!(
                        "failed writing calldata to {}: {e}",
                        artifacts.calldata_path.display()
                    );
                    exit(1);
                }

                println!("vk_path: {}", vk_path);
                println!("vk_header.zkstd_version: {}", vk_header.zkstd_version);
                println!("vk_header.max_bit_len: {}", vk_header.max_bit_len);
                println!("vk_header.nb_public_inputs: {}", vk_header.nb_public_inputs);
                println!("vk_header.domain_k: {}", vk_header.domain_k);
                println!("vk_header.arch: {:?}", vk_header.arch);
                println!("vk_payload.inner_vk_version: {}", vk_payload_view.prefix.inner_vk_version);
                println!("vk_payload.num_fixed_commitments: {}", vk_payload_view.prefix.num_fixed_commitments);
                println!(
                    "vk_payload.fixed_commitments_decoded: {}",
                    vk_payload_view.fixed_commitments.len()
                );
                println!(
                    "vk_payload.fixed_commitments_len_bytes: {}",
                    vk_payload_view.prefix.fixed_commitments_len_bytes
                );
                println!(
                    "vk_payload.fixed_commitments_sha256: {}",
                    vk_payload_view.prefix.fixed_commitments_sha256
                );
                println!(
                    "vk_payload.inner_payload_len_bytes: {}",
                    vk_payload_view.prefix.inner_payload_len_bytes
                );
                println!(
                    "vk_payload.inner_payload_sha256: {}",
                    vk_payload_view.prefix.inner_payload_sha256
                );
                println!(
                    "vk_payload.trailing_payload_offset: {}",
                    vk_payload_view.prefix.trailing_payload_offset
                );
                println!(
                    "vk_payload.trailing_payload_len_bytes: {}",
                    vk_payload_view.prefix.trailing_payload_len_bytes
                );
                println!(
                    "vk_payload.trailing_payload_sha256: {}",
                    vk_payload_view.prefix.trailing_payload_sha256
                );
                println!(
                    "adapter_status: phase1b_payload_parsed (full protocol mapping pending)"
                );
                println!("proof_layout.mode: {}", layout_mode);
                println!(
                    "proof_layout.commitments_offset: {}",
                    layout_descriptor.commitments_offset
                );
                println!(
                    "proof_layout.num_commitments: {}",
                    layout_descriptor.num_commitments
                );
                println!(
                    "proof_layout.num_evaluations: {}",
                    layout_descriptor.num_evaluations
                );
                println!(
                    "proof_layout.num_queries: {}",
                    layout_descriptor.num_queries.unwrap_or(layout_descriptor.num_evaluations)
                );
                println!(
                    "protocol_translation.scaffold_ready: {}",
                    if protocol_scaffold.translator_ready {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "protocol_translation.commitments_decoded: {}",
                    protocol_scaffold.proof_transcript.commitments.len()
                );
                println!(
                    "protocol_translation.evaluations_decoded: {}",
                    protocol_scaffold.proof_transcript.evaluations.len()
                );
                println!(
                    "protocol_translation.queries_scaffolded: {}",
                    protocol_scaffold.proof_transcript.queries.len()
                );
                println!(
                    "protocol_translation.proof_parse_complete: {}",
                    if protocol_scaffold.proof_transcript.parsed_fully {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "protocol_translation.query_mapping_ready: {}",
                    if protocol_scaffold.proof_transcript.query_mapping_ready {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "protocol_translation.query_schedule_sha256: {}",
                    protocol_scaffold.query_schedule_sha256
                );
                println!(
                    "protocol_translation.query_schedule_bound: {}",
                    if protocol_scaffold.query_schedule_bound {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "protocol_translation.quotient_binding_ready: {}",
                    if protocol_scaffold.quotient_binding_ready {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "protocol_translation.preprocessed_commitments_ready: {}",
                    if protocol_scaffold.preprocessed_commitments_ready {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "protocol_translation.quotient_linearization_ready: {}",
                    if protocol_scaffold.quotient_linearization_ready {
                        "yes"
                    } else {
                        "no"
                    }
                );
                match translation_probe {
                    Ok(_) => println!("protocol_translation.status: translated"),
                    Err(err) => println!("protocol_translation.status: {err}"),
                }
                println!("proof_path_imported_from: {}", proof_path);
                println!("instances_path: {}", instances_path);
                println!("protocol_profile_json: {}", profile_json_path.display());
                println!("proof_metadata_json: {}", proof_json_path.display());
                println!(
                    "protocol_translation_scaffold_json: {}",
                    protocol_scaffold_json_path.display()
                );
                println!("solidity_verifier: {}", artifacts.sol_path.display());
                println!("bytecode_path: {}", artifacts.bytecode_path.display());
                println!("proof_path: {}", artifacts.proof_path.display());
                println!("calldata_path: {}", artifacts.calldata_path.display());
            }
        }
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    }
}
