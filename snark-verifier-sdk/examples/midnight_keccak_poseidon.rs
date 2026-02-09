use std::path::Path;

use snark_verifier_sdk::midnight_bridge_artifacts::generate_midnight_bridge_artifacts;

fn main() {
    let report = generate_midnight_bridge_artifacts(
        Path::new("examples/midnight_keccak_poseidon"),
        Path::new("examples/MidnightKeccakPoseidonVerifier.sol"),
    );

    println!("proof size: {}", report.proof_size_bytes);
    println!("deployment code len: {}", report.deployment_code_bytes);
    println!("wrote {}", report.sol_path.display());
    println!("wrote {}", report.bytecode_path.display());
    println!("wrote {}", report.proof_path.display());
    let calldata_hex_len = std::fs::read_to_string(&report.calldata_path)
        .map(|s| s.trim().len())
        .unwrap_or_default();
    println!(
        "wrote {} ({} hex chars)",
        report.calldata_path.display(),
        calldata_hex_len
    );
    println!(
        "note: proof/calldata are generated with snark-verifier EVM transcript format and match this verifier ABI"
    );
}
