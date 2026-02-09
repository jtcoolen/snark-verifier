use std::path::PathBuf;

use crate::midnight::{preflight_check, ProofMetadata, ProtocolProfile};
use crate::midnight_bridge::BridgeCompatibility;

#[derive(Clone, Debug)]
pub struct BridgeBuildConfig {
    pub output_stem: PathBuf,
    pub solidity_path: PathBuf,
    /// Optional VK-derived domain size (k). When not provided, defaults to 12.
    pub vk_k: Option<u32>,
    /// Optional instance column lengths for bridge artifact shape.
    pub instance_column_lens: Option<Vec<usize>>,
}

impl Default for BridgeBuildConfig {
    fn default() -> Self {
        Self {
            output_stem: PathBuf::from("examples/midnight_bridge_poseidon"),
            solidity_path: PathBuf::from("examples/MidnightBridgePoseidonVerifier.sol"),
            vk_k: None,
            instance_column_lens: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BridgeBuildReport {
    pub preflight_ok: bool,
    pub compatibility: BridgeCompatibility,
    pub artifact_report: Option<BridgeArtifactReportView>,
}

#[derive(Clone, Debug)]
pub struct BridgeArtifactReportView {
    pub proof_size_bytes: usize,
    pub deployment_code_bytes: usize,
    pub sol_path: PathBuf,
    pub bytecode_path: PathBuf,
    pub proof_path: PathBuf,
    pub calldata_path: PathBuf,
}

#[derive(Clone, Debug)]
pub enum BridgeBuildError {
    Preflight(String),
    Unsupported(Vec<String>),
    UnsupportedCircuit(String),
    UnsupportedInstanceShape(Vec<usize>),
    FeatureMissing(&'static str),
}

impl std::fmt::Display for BridgeBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeBuildError::Preflight(e) => write!(f, "preflight failed: {e}"),
            BridgeBuildError::Unsupported(reasons) => {
                write!(f, "bridge unsupported: {}", reasons.join("; "))
            }
            BridgeBuildError::UnsupportedCircuit(id) => write!(
                f,
                "unsupported circuit_id '{id}' for current bridge pass (expected poseidon_example)"
            ),
            BridgeBuildError::UnsupportedInstanceShape(lens) => write!(
                f,
                "unsupported instance column shape {:?}: expected a non-empty list of positive lengths",
                lens
            ),
            BridgeBuildError::FeatureMissing(msg) => write!(f, "{msg}"),
        }
    }
}

pub fn build_from_metadata(
    profile: &ProtocolProfile,
    proof: &ProofMetadata,
    config: &BridgeBuildConfig,
) -> Result<BridgeBuildReport, BridgeBuildError> {
    preflight_check(profile, proof).map_err(|e| BridgeBuildError::Preflight(e.to_string()))?;

    let compatibility = BridgeCompatibility::check(profile, proof);
    if !compatibility.supported {
        return Err(BridgeBuildError::Unsupported(compatibility.reasons.clone()));
    }

    if profile.circuit.circuit_id != "poseidon_example" || proof.circuit.circuit_id != "poseidon_example" {
        return Err(BridgeBuildError::UnsupportedCircuit(profile.circuit.circuit_id.clone()));
    }

    let artifact_report = generate_subset_artifacts(config)?;

    Ok(BridgeBuildReport {
        preflight_ok: true,
        compatibility,
        artifact_report: Some(artifact_report),
    })
}

#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
fn generate_subset_artifacts(
    config: &BridgeBuildConfig,
) -> Result<BridgeArtifactReportView, BridgeBuildError> {
    let instance_lens = config.instance_column_lens.clone().unwrap_or_else(|| vec![1]);
    if instance_lens.is_empty() || instance_lens.iter().any(|len| *len == 0) {
        return Err(BridgeBuildError::UnsupportedInstanceShape(instance_lens));
    }
    let report = crate::midnight_bridge_artifacts::generate_midnight_bridge_artifacts_with_shape(
        &config.output_stem,
        &config.solidity_path,
        config.vk_k.unwrap_or(12),
        &instance_lens,
    );
    Ok(BridgeArtifactReportView {
        proof_size_bytes: report.proof_size_bytes,
        deployment_code_bytes: report.deployment_code_bytes,
        sol_path: report.sol_path,
        bytecode_path: report.bytecode_path,
        proof_path: report.proof_path,
        calldata_path: report.calldata_path,
    })
}

#[cfg(not(all(feature = "loader_halo2", feature = "loader_evm")))]
fn generate_subset_artifacts(
    _config: &BridgeBuildConfig,
) -> Result<BridgeArtifactReportView, BridgeBuildError> {
    Err(BridgeBuildError::FeatureMissing(
        "midnight bridge build requires loader_halo2 and loader_evm features",
    ))
}
