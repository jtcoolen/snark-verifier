use snark_verifier_sdk::midnight::{preflight_check, ProofMetadata, ProtocolProfile};
use std::{env, fs, path::Path};

fn usage(bin: &str) {
    eprintln!("Usage: {bin} <protocol_profile.json> <proof_metadata.json>");
}

fn read_json<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned,
{
    let data = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display())
    });
    serde_json::from_str(&data).unwrap_or_else(|err| {
        panic!("failed to parse {} as json: {err}", path.display())
    })
}

fn main() {
    let mut args = env::args();
    let bin = args.next().unwrap_or_else(|| "midnight_preflight".to_string());
    let profile_path = if let Some(p) = args.next() {
        p
    } else {
        usage(&bin);
        std::process::exit(2);
    };
    let proof_path = if let Some(p) = args.next() {
        p
    } else {
        usage(&bin);
        std::process::exit(2);
    };

    let profile: ProtocolProfile = read_json(Path::new(&profile_path));
    let proof: ProofMetadata = read_json(Path::new(&proof_path));

    match preflight_check(&profile, &proof) {
        Ok(()) => {
            println!("preflight: ok");
            println!("profile_id: {}", profile.profile_id);
            println!("protocol_version: {}", profile.protocol_version);
        }
        Err(err) => {
            eprintln!("preflight: failed");
            eprintln!("reason: {err}");
            std::process::exit(1);
        }
    }
}
