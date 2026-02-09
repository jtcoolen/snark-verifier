use halo2_base::halo2_proofs::halo2curves::bls12_381::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField as CurvePrimeField;
use num_bigint::BigUint;
use num_traits::Num;
use snark_verifier_sdk::evm::write_calldata;
use snark_verifier_sdk::midnight::{ProofMetadata, ProtocolProfile};
use snark_verifier_sdk::midnight_bridge_build::{build_from_metadata, BridgeBuildConfig};
use std::{env, fs, path::PathBuf, process::exit};

fn read_json_file<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed reading {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("failed parsing {path} as JSON: {e}"))
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
    let raw: Vec<Vec<String>> = read_json_file(path)?;
    raw.into_iter()
        .map(|col| col.into_iter().map(|x| parse_scalar(&x)).collect())
        .collect()
}

fn main() {
    let mut args = env::args().skip(1);
    let profile_path = match args.next() {
        Some(v) => v,
        None => {
            eprintln!(
                "usage: midnight_bridge_build <protocol_profile.json> <proof_metadata.json> [output_stem] [instances_json] [proof_bin]"
            );
            exit(2);
        }
    };
    let proof_path = match args.next() {
        Some(v) => v,
        None => {
            eprintln!(
                "usage: midnight_bridge_build <protocol_profile.json> <proof_metadata.json> [output_stem] [instances_json] [proof_bin]"
            );
            exit(2);
        }
    };
    let output_stem = args.next().unwrap_or_else(|| "examples/midnight_bridge_poseidon".to_string());
    let instances_json_path = args.next();
    let proof_bin_path = args.next();
    if args.next().is_some() {
        eprintln!(
            "usage: midnight_bridge_build <protocol_profile.json> <proof_metadata.json> [output_stem] [instances_json] [proof_bin]"
        );
        exit(2);
    }

    if instances_json_path.is_some() ^ proof_bin_path.is_some() {
        eprintln!("error: provide both instances_json and proof_bin, or neither");
        exit(2);
    }

    let profile: ProtocolProfile = match read_json_file(&profile_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            exit(2);
        }
    };
    let proof: ProofMetadata = match read_json_file(&proof_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            exit(2);
        }
    };

    let stem = PathBuf::from(&output_stem);
    let sol_path = stem
        .with_file_name("MidnightBridgePoseidonVerifier.sol");
    let config = BridgeBuildConfig {
        output_stem: stem,
        solidity_path: sol_path,
        vk_k: None,
        instance_column_lens: None,
    };

    match build_from_metadata(&profile, &proof, &config) {
        Ok(report) => {
            println!("preflight: {}", if report.preflight_ok { "ok" } else { "failed" });
            println!(
                "bridge_compatible: {}",
                if report.compatibility.supported { "yes" } else { "no" }
            );
            if let Some(artifacts) = report.artifact_report {
                println!("proof_size_bytes: {}", artifacts.proof_size_bytes);
                println!("deployment_code_bytes: {}", artifacts.deployment_code_bytes);
                println!("solidity_verifier: {}", artifacts.sol_path.display());
                println!("bytecode_path: {}", artifacts.bytecode_path.display());
                println!("proof_path: {}", artifacts.proof_path.display());
                println!("calldata_path: {}", artifacts.calldata_path.display());

                if let (Some(instances_path), Some(proof_path)) =
                    (instances_json_path.as_deref(), proof_bin_path.as_deref())
                {
                    let instances = match read_instances_json(instances_path) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("{e}");
                            exit(2);
                        }
                    };
                    if instances.is_empty() {
                        eprintln!("error: invalid instances shape (at least one instance column is required)");
                        exit(1);
                    }
                    if instances.iter().any(|col| col.is_empty()) {
                        eprintln!("error: invalid instances shape (instance columns must be non-empty)");
                        exit(1);
                    }
                    let proof_bytes = match fs::read(proof_path) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("failed reading proof bytes from {proof_path}: {e}");
                            exit(2);
                        }
                    };

                    if proof.proof_len_bytes != 0 && proof.proof_len_bytes != proof_bytes.len() {
                        eprintln!(
                            "error: proof byte length mismatch (metadata={}, file={})",
                            proof.proof_len_bytes,
                            proof_bytes.len()
                        );
                        exit(1);
                    }
                    if !proof.instance_column_lens.is_empty() {
                        let lens = instances.iter().map(Vec::len).collect::<Vec<_>>();
                        if lens != proof.instance_column_lens {
                            eprintln!(
                                "error: instance column lens mismatch (metadata={:?}, file={:?})",
                                proof.instance_column_lens, lens
                            );
                            exit(1);
                        }
                    }

                    if let Err(e) = fs::write(&artifacts.proof_path, &proof_bytes) {
                        eprintln!(
                            "failed writing external proof to {}: {e}",
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
                    println!(
                        "external_proof_packed: yes (instances={}, proof={})",
                        instances_path, proof_path
                    );
                    println!("proof_path: {}", artifacts.proof_path.display());
                    println!("calldata_path: {}", artifacts.calldata_path.display());
                }
            }
        }
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    }
}
