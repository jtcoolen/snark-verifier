#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
use std::path::{Path, PathBuf};

#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
use halo2_base::halo2_proofs;
#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
use halo2_proofs::halo2curves as halo2_curves;
#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
use halo2_proofs::{halo2curves::bls12_381::Bls12, poly::kzg::commitment::ParamsKZG};
#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
use rand::rngs::OsRng;

#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
use crate::evm::{gen_evm_proof_gwc, gen_evm_verifier_gwc, write_calldata};
#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
use crate::{gen_pk, CircuitExt};

#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
#[derive(Clone, Debug)]
pub struct BridgeArtifactReport {
    pub proof_size_bytes: usize,
    pub deployment_code_bytes: usize,
    pub sol_path: PathBuf,
    pub bytecode_path: PathBuf,
    pub proof_path: PathBuf,
    pub calldata_path: PathBuf,
}

#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
mod bridge_circuit {
    use super::halo2_curves::bls12_381::Fr;
    use super::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    };
    use rand::RngCore;
    use std::cell::RefCell;

    use crate::CircuitExt;

    thread_local! {
        static BRIDGE_INSTANCE_LENS: RefCell<Vec<usize>> = RefCell::new(vec![1]);
    }

    pub fn set_instance_lens(lens: &[usize]) {
        BRIDGE_INSTANCE_LENS.with(|current| {
            *current.borrow_mut() = lens.to_vec();
        });
    }

    fn instance_lens() -> Vec<usize> {
        BRIDGE_INSTANCE_LENS.with(|current| current.borrow().clone())
    }

    #[derive(Clone)]
    pub struct BridgeSmokeConfig {
        a: Vec<Column<Advice>>,
        q_a: Vec<Column<Fixed>>,
        instance: Vec<Column<Instance>>,
    }

    impl BridgeSmokeConfig {
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
            let lens = instance_lens();
            let mut a = Vec::with_capacity(lens.len());
            let mut q_a = Vec::with_capacity(lens.len());
            let mut instance = Vec::with_capacity(lens.len());

            for idx in 0..lens.len() {
                let advice_col = meta.advice_column();
                let fixed_col = meta.fixed_column();
                let instance_col = meta.instance_column();
                meta.enable_equality(advice_col);

                meta.create_gate(format!("q_a * a + instance = 0 [{idx}]"), |meta| {
                    let a = meta.query_advice(advice_col, Rotation::cur());
                    let q_a = meta.query_fixed(fixed_col, Rotation::cur());
                    let instance = meta.query_instance(instance_col, Rotation::cur());
                    Some(q_a * a + instance)
                });

                a.push(advice_col);
                q_a.push(fixed_col);
                instance.push(instance_col);
            }

            BridgeSmokeConfig { a, q_a, instance }
        }
    }

    #[derive(Clone, Default)]
    pub struct BridgeSmokeCircuit(Vec<Vec<Fr>>);

    impl BridgeSmokeCircuit {
        pub fn rand_with_instance_lens<R: RngCore>(mut rng: R, lens: &[usize]) -> Self {
            let values = lens
                .iter()
                .map(|len| {
                    let len = (*len).max(1);
                    (0..len).map(|_| Fr::from(rng.next_u32() as u64)).collect()
                })
                .collect();
            Self(values)
        }
    }

    impl CircuitExt<Fr> for BridgeSmokeCircuit {
        fn num_instance(&self) -> Vec<usize> {
            self.0.iter().map(Vec::len).collect()
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            self.0.clone()
        }
    }

    impl Circuit<Fr> for BridgeSmokeCircuit {
        type Config = BridgeSmokeConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self(self.0.iter().map(|col| vec![Fr::zero(); col.len().max(1)]).collect())
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            BridgeSmokeConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let _ = config.instance;
            layouter.assign_region(
                || "assign",
                |mut region| {
                    for idx in 0..self.0.len() {
                        #[cfg(feature = "halo2-pse")]
                        {
                            region.assign_advice(
                                || format!("a[{idx}]"),
                                config.a[idx],
                                0,
                                || Value::known(self.0[idx][0]),
                            )?;
                            region.assign_fixed(
                                || format!("q_a[{idx}]"),
                                config.q_a[idx],
                                0,
                                || Value::known(-Fr::one()),
                            )?;
                        }
                        #[cfg(feature = "halo2-axiom")]
                        {
                            region.assign_advice(config.a[idx], 0, Value::known(self.0[idx][0]));
                            region.assign_fixed(config.q_a[idx], 0, -Fr::one());
                        }
                    }
                    Ok(())
                },
            )
        }
    }

    pub use BridgeSmokeCircuit as CircuitType;
}

#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
pub fn generate_midnight_bridge_artifacts(
    output_stem: &Path,
    solidity_path: &Path,
) -> BridgeArtifactReport {
    generate_midnight_bridge_artifacts_with_shape(output_stem, solidity_path, 12, &[1])
}

#[cfg(all(feature = "loader_halo2", feature = "loader_evm"))]
pub fn generate_midnight_bridge_artifacts_with_shape(
    output_stem: &Path,
    solidity_path: &Path,
    k: u32,
    instance_lens: &[usize],
) -> BridgeArtifactReport {
    bridge_circuit::set_instance_lens(instance_lens);
    let params = ParamsKZG::<Bls12>::setup(k, OsRng);
    let circuit = bridge_circuit::CircuitType::rand_with_instance_lens(OsRng, instance_lens);
    let num_instance = circuit.num_instance();
    let instances = circuit.instances();

    let pk = gen_pk(&params, &circuit, None);
    let proof = gen_evm_proof_gwc(&params, &pk, circuit, instances.clone());
    let deployment_code =
        gen_evm_verifier_gwc::<bridge_circuit::CircuitType>(&params, pk.get_vk(), num_instance, Some(solidity_path));

    let bytecode_path = output_stem.with_extension("bytecode");
    let proof_path = output_stem.with_extension("proof");
    let calldata_path = output_stem.with_extension("calldata");

    if let Some(parent) = bytecode_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Some(parent) = proof_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Some(parent) = calldata_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let deployment_bytecode = format!("0x{}", hex::encode(&deployment_code));
    std::fs::write(&bytecode_path, &deployment_bytecode).unwrap();
    std::fs::write(&proof_path, &proof).unwrap();
    let _ = write_calldata(&instances, &proof, &calldata_path).unwrap();

    BridgeArtifactReport {
        proof_size_bytes: proof.len(),
        deployment_code_bytes: deployment_code.len(),
        sol_path: solidity_path.to_path_buf(),
        bytecode_path,
        proof_path,
        calldata_path,
    }
}
