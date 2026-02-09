use snark_verifier_sdk::midnight::{preflight_check, ProofMetadata, ProtocolProfile};
use snark_verifier_sdk::midnight_bridge::BridgeCompatibility;
use std::{env, fs, process::exit};

fn read_json_file<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed reading {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("failed parsing {path} as JSON: {e}"))
}

fn main() {
    let mut args = env::args().skip(1);
    let profile_path = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("usage: midnight_bridge_check <protocol_profile.json> <proof_metadata.json>");
            exit(2);
        }
    };
    let proof_path = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("usage: midnight_bridge_check <protocol_profile.json> <proof_metadata.json>");
            exit(2);
        }
    };
    if args.next().is_some() {
        eprintln!("usage: midnight_bridge_check <protocol_profile.json> <proof_metadata.json>");
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

    match preflight_check(&profile, &proof) {
        Ok(()) => {
            println!("preflight: ok");
        }
        Err(e) => {
            eprintln!("preflight: failed");
            eprintln!("{e}");
            exit(1);
        }
    }

    let report = BridgeCompatibility::check(&profile, &proof);
    println!(
        "bridge_compatible: {}",
        if report.supported { "yes" } else { "no" }
    );
    if !report.reasons.is_empty() {
        for reason in &report.reasons {
            println!("reason: {reason}");
        }
        exit(1);
    }
}
