pub enum Precompiled {
    BigModExp = 0x05,
    Bn254Add = 0x6,
    Bn254ScalarMul = 0x7,
    Bn254Pairing = 0x8,
}

#[derive(Clone, Debug)]
pub struct SolidityAssemblyCode {
    // runtime code area
    runtime: String,
}

impl SolidityAssemblyCode {
    pub fn new() -> Self {
        Self { runtime: String::new() }
    }

    pub fn code(&self, scalar_modulus: String) -> String {
        format!(
            "
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

contract Halo2Verifier {{
    fallback(bytes calldata) external returns (bytes memory) {{
        assembly (\"memory-safe\") {{
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {{
                revert(0, 0)
            }}

            let success := true
            let f_q := {scalar_modulus}
            {}
        }}
    }}
}}
        ",
            self.runtime
        )
    }

    pub fn runtime_append(&mut self, mut code: String) {
        code.push('\n');
        self.runtime.push_str(&code);
    }
}
