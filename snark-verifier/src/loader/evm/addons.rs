/// Emits a Solidity add-on contract implementing the final-accumulator pairing check.
///
/// The generated contract keeps the pairing logic separate from the core verifier function,
/// so callers can compose it only when needed.
pub fn final_accumulator_pairing_addon_solidity(
    contract_name: &str,
    pairing_g2_words: &[String],
    pairing_minus_tau_words: &[String],
) -> String {
    assert_eq!(pairing_g2_words.len(), 8, "pairing_g2_words must contain exactly 8 words");
    assert_eq!(
        pairing_minus_tau_words.len(),
        8,
        "pairing_minus_tau_words must contain exactly 8 words"
    );

    let pairing_g2_consts = pairing_g2_words
        .iter()
        .enumerate()
        .map(|(idx, value)| format!("    uint256 internal constant PAIRING_G2_{idx} = {value};"))
        .collect::<Vec<_>>()
        .join("\n");
    let pairing_minus_tau_consts = pairing_minus_tau_words
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            format!("    uint256 internal constant PAIRING_MINUS_TAU_{idx} = {value};")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let pairing_g2_assignments = (0..8usize)
        .map(|idx| format!("        pairingInput[{}] = PAIRING_G2_{idx};", 4 + idx))
        .collect::<Vec<_>>()
        .join("\n");
    let pairing_minus_tau_assignments = (0..8usize)
        .map(|idx| format!("        pairingInput[{}] = PAIRING_MINUS_TAU_{idx};", 16 + idx))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"
abstract contract {contract_name} {{
    error InvalidAccumulatorLimb(uint256 idx);

    uint256 internal constant LIMB_BITS = 56;
    uint256 internal constant LIMB_MASK = (1 << LIMB_BITS) - 1;
    uint256 internal constant LIMB4_LOW_MASK = (1 << 32) - 1;
    uint256 internal constant G1MSM_GAS_CAP = 5000000;
    uint256 internal constant PAIRING_GAS_CAP = 20000000;

{pairing_g2_consts}
{pairing_minus_tau_consts}

    function _checkLimbRange(uint256 limb, uint256 idx) internal pure {{
        if (limb > LIMB_MASK) revert InvalidAccumulatorLimb(idx);
    }}

    function _decodeFieldElementWords(
        uint256 l0,
        uint256 l1,
        uint256 l2,
        uint256 l3,
        uint256 l4,
        uint256 l5,
        uint256 l6
    ) internal pure returns (uint256 hi, uint256 lo) {{
        uint256 lowPart = l0
            | (l1 << 56)
            | (l2 << 112)
            | (l3 << 168)
            | ((l4 & LIMB4_LOW_MASK) << 224);
        uint256 highPart = (l4 >> 32) | (l5 << 24) | (l6 << 80);
        unchecked {{
            lowPart += 1;
            if (lowPart == 0) {{
                highPart += 1;
            }}
        }}
        return (highPart, lowPart);
    }}

    function _decodeWordsFromPi(
        uint256[28] calldata finalAccumulatorPi,
        uint256 start
    ) internal pure returns (uint256 hi, uint256 lo) {{
        uint256 l0 = finalAccumulatorPi[start];
        uint256 l1 = finalAccumulatorPi[start + 1];
        uint256 l2 = finalAccumulatorPi[start + 2];
        uint256 l3 = finalAccumulatorPi[start + 3];
        uint256 l4 = finalAccumulatorPi[start + 4];
        uint256 l5 = finalAccumulatorPi[start + 5];
        uint256 l6 = finalAccumulatorPi[start + 6];
        _checkLimbRange(l0, start);
        _checkLimbRange(l1, start + 1);
        _checkLimbRange(l2, start + 2);
        _checkLimbRange(l3, start + 3);
        _checkLimbRange(l4, start + 4);
        _checkLimbRange(l5, start + 5);
        _checkLimbRange(l6, start + 6);
        return _decodeFieldElementWords(l0, l1, l2, l3, l4, l5, l6);
    }}

    function _decodeXWordsFromPi(
        uint256[28] calldata finalAccumulatorPi,
        uint256 start
    ) internal pure returns (uint256 hi, uint256 lo, uint256 isId) {{
        uint256 l0raw = finalAccumulatorPi[start];
        isId = l0raw >> LIMB_BITS;
        if (isId > 1) revert InvalidAccumulatorLimb(start);
        uint256 l0 = l0raw & LIMB_MASK;
        uint256 l1 = finalAccumulatorPi[start + 1];
        uint256 l2 = finalAccumulatorPi[start + 2];
        uint256 l3 = finalAccumulatorPi[start + 3];
        uint256 l4 = finalAccumulatorPi[start + 4];
        uint256 l5 = finalAccumulatorPi[start + 5];
        uint256 l6 = finalAccumulatorPi[start + 6];
        _checkLimbRange(l1, start + 1);
        _checkLimbRange(l2, start + 2);
        _checkLimbRange(l3, start + 3);
        _checkLimbRange(l4, start + 4);
        _checkLimbRange(l5, start + 5);
        _checkLimbRange(l6, start + 6);
        (hi, lo) = _decodeFieldElementWords(l0, l1, l2, l3, l4, l5, l6);
    }}

    function _decodePoint(
        uint256[28] calldata finalAccumulatorPi,
        uint256 base
    ) internal pure returns (uint256 xHi, uint256 xLo, uint256 yHi, uint256 yLo) {{
        uint256 isId;
        (xHi, xLo, isId) = _decodeXWordsFromPi(finalAccumulatorPi, base);
        if (isId == 1) {{
            return (0, 0, 0, 0);
        }}
        (yHi, yLo) = _decodeWordsFromPi(finalAccumulatorPi, base + 7);
    }}

    function _normalizeG1Point(
        uint256 xHi,
        uint256 xLo,
        uint256 yHi,
        uint256 yLo
    ) internal view returns (bool ok, uint256 nxHi, uint256 nxLo, uint256 nyHi, uint256 nyLo) {{
        if (xHi == 0 && xLo == 0 && yHi == 0 && yLo == 0) {{
            return (true, 0, 0, 0, 0);
        }}

        uint256[5] memory msmInput;
        msmInput[4] = 1;

        // Try canonical [x_hi, x_lo, y_hi, y_lo] first.
        msmInput[0] = xHi;
        msmInput[1] = xLo;
        msmInput[2] = yHi;
        msmInput[3] = yLo;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        // Fallback: [x_lo, x_hi, y_lo, y_hi].
        msmInput[0] = xLo;
        msmInput[1] = xHi;
        msmInput[2] = yLo;
        msmInput[3] = yHi;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        // Fallback: [x_hi, x_lo, y_lo, y_hi].
        msmInput[0] = xHi;
        msmInput[1] = xLo;
        msmInput[2] = yLo;
        msmInput[3] = yHi;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        // Fallback: [x_lo, x_hi, y_hi, y_lo].
        msmInput[0] = xLo;
        msmInput[1] = xHi;
        msmInput[2] = yHi;
        msmInput[3] = yLo;
        assembly ("memory-safe") {{
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }}
        if (ok) {{
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }}

        return (false, 0, 0, 0, 0);
    }}

    function _checkFinalAccumulatorPairing(
        uint256[28] calldata finalAccumulatorPi
    ) internal view returns (bool callOk, uint256 resultWord) {{
        (uint256 lhsXHi, uint256 lhsXLo, uint256 lhsYHi, uint256 lhsYLo) =
            _decodePoint(finalAccumulatorPi, 0);
        (uint256 rhsXHi, uint256 rhsXLo, uint256 rhsYHi, uint256 rhsYLo) =
            _decodePoint(finalAccumulatorPi, 14);

        bool lhsNormOk;
        bool rhsNormOk;
        (lhsNormOk, lhsXHi, lhsXLo, lhsYHi, lhsYLo) =
            _normalizeG1Point(lhsXHi, lhsXLo, lhsYHi, lhsYLo);
        if (!lhsNormOk) {{
            return (false, 11);
        }}
        (rhsNormOk, rhsXHi, rhsXLo, rhsYHi, rhsYLo) =
            _normalizeG1Point(rhsXHi, rhsXLo, rhsYHi, rhsYLo);
        if (!rhsNormOk) {{
            return (false, 12);
        }}

        uint256[24] memory pairingInput;
        pairingInput[0] = rhsXHi;
        pairingInput[1] = rhsXLo;
        pairingInput[2] = rhsYHi;
        pairingInput[3] = rhsYLo;
{pairing_g2_assignments}
        pairingInput[12] = lhsXHi;
        pairingInput[13] = lhsXLo;
        pairingInput[14] = lhsYHi;
        pairingInput[15] = lhsYLo;
{pairing_minus_tau_assignments}

        assembly ("memory-safe") {{
            let ptr := pairingInput
            callOk := staticcall(PAIRING_GAS_CAP, 0x0f, ptr, 0x300, ptr, 0x20)
            resultWord := mload(ptr)
            if iszero(callOk) {{
                resultWord := 13
            }}
        }}
        return (callOk, resultWord);
    }}
}}
"#
    )
}

/// Emits a Solidity add-on contract implementing the hybrid UHF helper.
///
/// The generated helper intentionally stays independent from verifier internals.
pub fn uhf_addon_solidity(contract_name: &str) -> String {
    format!(
        r#"
abstract contract {contract_name} {{
    function _uhf(
        uint256 seed,
        uint256[] calldata values,
        uint256 modulus
    ) internal pure returns (uint256 acc) {{
        uint256 power = 1;
        for (uint256 i = 0; i < values.length; ++i) {{
            acc = addmod(acc, mulmod(power, values[i], modulus), modulus);
            power = mulmod(power, seed, modulus);
        }}
    }}
}}
"#
    )
}
