#[cfg(feature = "revm")]
use anyhow::anyhow;
use anyhow::Result;
use halo2_base::halo2_proofs::halo2curves::bls12_381::{
    Fq as HaloFq, Fr as HaloFr, G1Affine as HaloG1Affine,
};
use itertools::Itertools;
use snark_verifier::{
    loader::{
        evm::{compile_solidity, encode_calldata, EvmLoader},
        EcPointLoader,
    },
    system::halo2::transcript::evm::EvmTranscript,
};
use std::rc::Rc;

use super::MidnightProofBundle;

impl MidnightProofBundle {
    /// Generate Solidity verifier source code for this Midnight proof protocol.
    ///
    /// The generated contract expects calldata encoded as: instances (32-byte
    /// big-endian words) followed by proof bytes produced in Midnight EVM transcript mode.
    pub fn generate_evm_verifier_solidity(&self) -> Result<String> {
        let loader = self.build_evm_verifier_loader()?;
        Ok(loader.solidity_code())
    }

    /// Generate deployment bytecode for the Midnight Solidity verifier.
    pub fn generate_evm_verifier_bytecode(&self) -> Result<Vec<u8>> {
        let solidity = self.generate_evm_verifier_solidity()?;
        Ok(compile_solidity(&solidity))
    }

    /// Encode calldata expected by the generated Solidity verifier.
    ///
    /// The proof bytes must be produced in Midnight EVM transcript mode.
    pub fn encode_evm_calldata(&self) -> Result<Vec<u8>> {
        let instances = self.full_instances_as_halo_fr()?;
        Ok(encode_calldata(&instances, &self.proof))
    }

    /// Deploy and call the generated verifier in local revm.
    ///
    /// Returns gas used by the verification call.
    #[cfg(feature = "revm")]
    pub fn verify_with_generated_solidity_revm(&self) -> Result<u64> {
        let bytecode = self.generate_evm_verifier_bytecode()?;
        let calldata = self.encode_evm_calldata()?;
        snark_verifier::loader::evm::deploy_and_call(bytecode, calldata)
            .map_err(|err| anyhow!("revm deployment/call failed: {err}"))
    }

    // Build an EVM loader by replaying proof parsing/verification over EVM transcript semantics.
    fn build_evm_verifier_loader(&self) -> Result<Rc<EvmLoader>> {
        let protocol = self.to_snark_protocol()?;
        let num_instance = protocol.num_instance.clone();
        let dk = self.snark_deciding_key()?;

        let loader = EvmLoader::new::<HaloFq, HaloFr>();
        let protocol = protocol.loaded(&loader);
        let mut transcript = EvmTranscript::<HaloG1Affine, Rc<EvmLoader>, _, _>::new(&loader);

        // Load committed-instance constants into EVM memory only when present.
        let committed_instances = self
            .committed_instances_as_halo_points()?
            .iter()
            .map(|point| loader.ec_point_load_const(point))
            .collect_vec();
        let committed_instances = (!committed_instances.is_empty()).then_some(committed_instances);
        let instances = transcript.load_instances(num_instance);

        // Drive the verifier once so the loader accumulates all runtime code.
        Self::run_snark_verifier_flow(
            &dk,
            &protocol,
            &instances,
            committed_instances.as_deref(),
            &mut transcript,
            "failed to parse Midnight proof with EVM transcript",
            "failed to build EVM verifier for Midnight protocol",
        )?;

        Ok(loader)
    }
}
