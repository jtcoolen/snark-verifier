#![allow(missing_docs)]

use super::{
    compact_ir::{
        CompactProgram, CompactProgramManifest, COMPACT_OPCODE_VERSION, COMPACT_PAGE_BYTES,
    },
    Address, U256,
};
use hex;

#[derive(Clone, Debug)]
pub struct CompactVerifierArtifacts {
    pub runtime_solidity: String,
    pub program_bytes: Vec<u8>,
    pub page_runtime_codes: Vec<Vec<u8>>,
    pub page_deployment_codes: Vec<Vec<u8>>,
    pub manifest: CompactProgramManifest,
}

pub fn build_compact_verifier_artifacts(
    scalar_modulus: U256,
    base_modulus_words: [U256; 2],
    base_sqrt_exp_words: [U256; 2],
    program: &CompactProgram,
    max_memory_ptr: usize,
) -> CompactVerifierArtifacts {
    let mut pages = program.paginate(COMPACT_PAGE_BYTES);
    pages.manifest.max_memory_ptr = max_memory_ptr;
    let page_runtime_codes = pages.pages;
    let page_deployment_codes = page_runtime_codes
        .iter()
        .map(|runtime| data_page_deployment_code(runtime))
        .collect::<Vec<_>>();
    let page_buffer_ptr = align_word(max_memory_ptr + 0x200);

    CompactVerifierArtifacts {
        runtime_solidity: compact_runtime_solidity(
            scalar_modulus,
            base_modulus_words,
            base_sqrt_exp_words,
            page_buffer_ptr,
        ),
        program_bytes: program.to_bytes(),
        page_runtime_codes,
        page_deployment_codes,
        manifest: pages.manifest,
    }
}

pub fn encode_compact_constructor_args(
    page_addresses: &[Address],
    program_words: usize,
) -> Vec<u8> {
    let mut encoded = Vec::new();

    // offset to the start of the dynamic array (`address[]`) from the start of constructor args
    encoded.extend(word_be(U256::from(0x40)));
    encoded.extend(word_be(U256::from(program_words)));
    encoded.extend(word_be(U256::from(page_addresses.len())));
    for address in page_addresses {
        encoded.extend(word_be(U256::from_be_bytes(pad_address(address))));
    }

    encoded
}

pub fn data_page_deployment_code(runtime_code: &[u8]) -> Vec<u8> {
    assert!(
        runtime_code.len() <= u16::MAX as usize,
        "data-page runtime exceeds u16 length for compact initcode helper"
    );

    let len = runtime_code.len() as u16;
    let mut init = vec![
        0x61,
        (len >> 8) as u8,
        (len & 0xff) as u8,
        0x60,
        0x0e,
        0x60,
        0x00,
        0x39,
        0x61,
        (len >> 8) as u8,
        (len & 0xff) as u8,
        0x60,
        0x00,
        0xf3,
    ];
    init.extend_from_slice(runtime_code);
    init
}

fn compact_runtime_solidity(
    scalar_modulus: U256,
    base_modulus_words: [U256; 2],
    base_sqrt_exp_words: [U256; 2],
    page_buffer_ptr: usize,
) -> String {
    let scalar_modulus = format!("0x{}", hex::encode(scalar_modulus.to_be_bytes::<32>()));
    let base_modulus_hi = format!("0x{}", hex::encode(base_modulus_words[0].to_be_bytes::<32>()));
    let base_modulus_lo = format!("0x{}", hex::encode(base_modulus_words[1].to_be_bytes::<32>()));
    let base_sqrt_exp_hi = format!("0x{}", hex::encode(base_sqrt_exp_words[0].to_be_bytes::<32>()));
    let base_sqrt_exp_lo = format!("0x{}", hex::encode(base_sqrt_exp_words[1].to_be_bytes::<32>()));
    format!(
        r#"
// SPDX-License-Identifier: MIT

pragma solidity >=0.8.19 <0.9.0;

contract Halo2Verifier {{
    // slot 0
    address[] private pages;
    // slot 1
    uint256 private programWords;

    constructor(address[] memory _pages, uint256 _programWords) {{
        require(_pages.length > 0, "no pages");
        require(_programWords > 1, "empty program");
        pages = _pages;
        programWords = _programWords;
    }}

    fallback(bytes calldata) external returns (bytes memory) {{
        assembly ("memory-safe") {{
            let data := mload(0x40)
            if lt(data, 0x80) {{
                mstore(0, 0x31)
                revert(0, 0x20)
            }}

            let pageCount := sload(0)
            let totalWords := sload(1)
            if or(iszero(pageCount), lt(totalWords, 2)) {{
                mstore(0, 0x32)
                revert(0, 0x20)
            }}

            let success := 1
            let f_q := {scalar_modulus}
            let b_p_hi := {base_modulus_hi}
            let b_p_lo := {base_modulus_lo}
            let b_sqrt_exp_hi := {base_sqrt_exp_hi}
            let b_sqrt_exp_lo := {base_sqrt_exp_lo}
            // Cache metadata in low scratch words.
            mstore(0x20, not(0)) // loaded page index
            mstore(0x40, 0)      // loaded page word count
            mstore(0x60, 0)      // loaded page base word

            function fail(code) {{
                mstore(0, code)
                revert(0, 0x20)
            }}

            mstore(0x00, 0)
            let pagesBase := keccak256(0x00, 0x20)

            function pageAddr(idx, pageCountArg, pagesBaseArg) -> addr {{
                if iszero(lt(idx, pageCountArg)) {{
                    fail(0x01)
                }}
                addr := and(
                    sload(add(pagesBaseArg, idx)),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
                if iszero(addr) {{
                    fail(0x02)
                }}
            }}

            function ensurePageLoaded(wordIndex, pageCountArg, pagesBaseArg) -> pageWordOff {{
                let pageIdx := div(wordIndex, {page_words})
                pageWordOff := mod(wordIndex, {page_words})

                if iszero(eq(pageIdx, mload(0x20))) {{
                    let addr := pageAddr(pageIdx, pageCountArg, pagesBaseArg)
                    let size := extcodesize(addr)
                    if iszero(eq(mod(size, 0x20), 0)) {{
                        fail(0x07)
                    }}
                    extcodecopy(addr, {page_buffer_ptr}, 0, size)
                    mstore(0x20, pageIdx)
                    mstore(0x40, div(size, 0x20))
                    mstore(0x60, mul(pageIdx, {page_words}))
                }}

                let loadedWords := mload(0x40)
                if iszero(lt(pageWordOff, loadedWords)) {{
                    fail(0x03)
                }}
            }}

            function wordAt(pageWordOff) -> word {{
                word := mload(add({page_buffer_ptr}, mul(pageWordOff, 0x20)))
            }}

            function loadWord(wordIndex, pageCountArg, pagesBaseArg) -> word {{
                word := wordAt(ensurePageLoaded(wordIndex, pageCountArg, pagesBaseArg))
            }}

            function readArg(argsStart, argIdx, samePage, ipArg, pageCountArg, pagesBaseArg) -> word {{
                if samePage {{
                    word := wordAt(add(argsStart, argIdx))
                }}
                if iszero(samePage) {{
                    word := loadWord(add(add(ipArg, 1), argIdx), pageCountArg, pagesBaseArg)
                }}
            }}

            function operandValue(tag, value) -> out {{
                switch tag
                case 0 {{
                    out := mload(value)
                }}
                case 1 {{
                    out := value
                }}
                default {{
                    fail(0x04)
                }}
            }}

            if iszero(eq(loadWord(0, pageCount, pagesBase), {opcode_version})) {{
                fail(0x05)
            }}

            for {{ let ip := 1 }} lt(ip, totalWords) {{}} {{
                let headerOff := ensurePageLoaded(ip, pageCount, pagesBase)
                let header := wordAt(headerOff)
                let opcode := byte(0, header)
                let len := byte(1, header)
                if or(iszero(len), gt(add(ip, len), totalWords)) {{
                    fail(0x06)
                }}
                let endIp := add(ip, len)
                let currentPage := div(ip, {page_words})
                let samePage := and(
                    eq(currentPage, div(sub(endIp, 1), {page_words})),
                    eq(currentPage, mload(0x20))
                )
                let argsStart := add(headerOff, 1)

                switch opcode
                // mstore(dst, value)
                case 1 {{
                    if iszero(eq(len, 3)) {{ fail(0x11) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let value := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, value)
                }}
                // mstore(dst, mload(src))
                case 2 {{
                    if iszero(eq(len, 3)) {{ fail(0x12) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mload(src))
                }}
                // mstore8(dst, value)
                case 3 {{
                    if iszero(eq(len, 3)) {{ fail(0x13) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let value := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore8(dst, and(value, 0xff))
                }}
                // mstore(dst, sub(f_q, operand))
                case 4 {{
                    if iszero(eq(len, 4)) {{ fail(0x14) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let tag := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let value := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let v := operandValue(tag, value)
                    mstore(dst, sub(f_q, v))
                }}
                // mstore(dst, addmod(lhs, rhs, f_q))
                case 5 {{
                    if iszero(eq(len, 6)) {{ fail(0x15) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhsTag := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let lhsValue := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let rhsTag := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    let rhsValue := readArg(argsStart, 4, samePage, ip, pageCount, pagesBase)
                    mstore(dst, addmod(operandValue(lhsTag, lhsValue), operandValue(rhsTag, rhsValue), f_q))
                }}
                // mstore(dst, mulmod(lhs, rhs, f_q))
                case 6 {{
                    if iszero(eq(len, 6)) {{ fail(0x16) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhsTag := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let lhsValue := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let rhsTag := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    let rhsValue := readArg(argsStart, 4, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mulmod(operandValue(lhsTag, lhsValue), operandValue(rhsTag, rhsValue), f_q))
                }}
                // mstore(dst, mod(calldataload(offset), f_q))
                case 7 {{
                    if iszero(eq(len, 3)) {{ fail(0x17) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let offset := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mod(calldataload(offset), f_q))
                }}
                // uncompressed proof point load: zero limbs then copy x/y from calldata with left padding.
                case 8 {{
                    if iszero(eq(len, 4)) {{ fail(0x18) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let offset := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let coordBytes := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let yPtr := add(dst, 0x40)
                    let pad := sub(0x40, coordBytes)

                    mstore(dst, 0)
                    mstore(add(dst, 0x20), 0)
                    mstore(yPtr, 0)
                    mstore(add(yPtr, 0x20), 0)
                    calldatacopy(add(dst, pad), offset, coordBytes)
                    calldatacopy(add(yPtr, pad), add(offset, coordBytes), coordBytes)
                }}
                // copy affine point (4 words)
                case 9 {{
                    if iszero(eq(len, 3)) {{ fail(0x19) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mload(src))
                    mstore(add(dst, 0x20), mload(add(src, 0x20)))
                    mstore(add(dst, 0x40), mload(add(src, 0x40)))
                    mstore(add(dst, 0x60), mload(add(src, 0x60)))
                }}
                // mstore(dst, keccak256(ptr, len))
                case 10 {{
                    if iszero(eq(len, 4)) {{ fail(0x1a) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let ptr := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let hashLen := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, keccak256(ptr, hashLen))
                }}
                // success := success && staticcall(precompile, cd_ptr, rd_ptr)
                case 11 {{
                    if iszero(eq(len, 4)) {{ fail(0x1b) }}
                    let precompile := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let cdPtr := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rdPtr := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let cdLen := 0
                    let rdLen := 0
                    switch precompile
                    case 0x05 {{
                        cdLen := 0xc0
                        rdLen := 0x20
                    }}
                    case 0x0b {{
                        cdLen := 0x100
                        rdLen := 0x80
                    }}
                    case 0x0c {{
                        cdLen := 0xa0
                        rdLen := 0x80
                    }}
                    case 0x0f {{
                        cdLen := 0x300
                        rdLen := 0x20
                    }}
                    default {{
                        fail(0x1c)
                    }}
                    success := and(success, eq(staticcall(gas(), precompile, cdPtr, cdLen, rdPtr, rdLen), 1))
                }}
                // success := success && (mload(ptr) == 1)
                case 12 {{
                    if iszero(eq(len, 2)) {{ fail(0x1d) }}
                    let ptr := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    success := and(success, eq(mload(ptr), 1))
                }}
                // decode affine point from limbs.
                case 13 {{
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let bits := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let limbCount := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let expectedLen := add(4, mul(4, limbCount))
                    if iszero(eq(len, expectedLen)) {{ fail(0x1e) }}

                    let cursor := add(ip, 4)
                    let xLo := 0
                    let xHi := 0
                    for {{ let i := 0 }} lt(i, limbCount) {{ i := add(i, 1) }} {{
                        let tag := loadWord(cursor, pageCount, pagesBase)
                        let value := loadWord(add(cursor, 1), pageCount, pagesBase)
                        let limb := operandValue(tag, value)
                        let shift := mul(i, bits)
                        if lt(shift, 256) {{
                            xLo := add(xLo, shl(shift, limb))
                        }}
                        if iszero(lt(shift, 256)) {{
                            xHi := add(xHi, shl(sub(shift, 256), limb))
                        }}
                        cursor := add(cursor, 2)
                    }}
                    mstore(dst, xHi)
                    mstore(add(dst, 0x20), xLo)

                    let yLo := 0
                    let yHi := 0
                    for {{ let j := 0 }} lt(j, limbCount) {{ j := add(j, 1) }} {{
                        let tag := loadWord(cursor, pageCount, pagesBase)
                        let value := loadWord(add(cursor, 1), pageCount, pagesBase)
                        let limb := operandValue(tag, value)
                        let shift := mul(j, bits)
                        if lt(shift, 256) {{
                            yLo := add(yLo, shl(shift, limb))
                        }}
                        if iszero(lt(shift, 256)) {{
                            yHi := add(yHi, shl(sub(shift, 256), limb))
                        }}
                        cursor := add(cursor, 2)
                    }}
                    mstore(add(dst, 0x40), yHi)
                    mstore(add(dst, 0x60), yLo)
                }}
                // mstore(dst, mod(mload(src), f_q))
                case 14 {{
                    if iszero(eq(len, 3)) {{ fail(0x1f) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mod(mload(src), f_q))
                }}
                // mstore(dst, sub(f_q, mload(src)))
                case 15 {{
                    if iszero(eq(len, 3)) {{ fail(0x22) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, sub(f_q, mload(src)))
                }}
                // mstore(dst, addmod(mload(lhs), mload(rhs), f_q))
                case 16 {{
                    if iszero(eq(len, 4)) {{ fail(0x23) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, addmod(mload(lhs), mload(rhs), f_q))
                }}
                // mstore(dst, mulmod(mload(lhs), mload(rhs), f_q))
                case 17 {{
                    if iszero(eq(len, 4)) {{ fail(0x24) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mulmod(mload(lhs), mload(rhs), f_q))
                }}
                // mstore(dst, addmod(mload(lhs), rhsConst, f_q))
                case 18 {{
                    if iszero(eq(len, 4)) {{ fail(0x25) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhsConst := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, addmod(mload(lhs), rhsConst, f_q))
                }}
                // mstore(dst, mulmod(mload(lhs), rhsConst, f_q))
                case 19 {{
                    if iszero(eq(len, 4)) {{ fail(0x26) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhsConst := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mulmod(mload(lhs), rhsConst, f_q))
                }}
                // mstore(dst, addmod(mulmod(mload(mul_lhs), mload(mul_rhs), f_q), mload(addend), f_q))
                case 20 {{
                    if iszero(eq(len, 5)) {{ fail(0x27) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let mulLhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let mulRhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let addend := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    mstore(
                        dst,
                        addmod(mulmod(mload(mulLhs), mload(mulRhs), f_q), mload(addend), f_q)
                    )
                }}
                // mstore(dst, addmod(mulmod(mload(mul_lhs), mload(mul_rhs), f_q), addendConst, f_q))
                case 21 {{
                    if iszero(eq(len, 5)) {{ fail(0x28) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let mulLhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let mulRhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let addendConst := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    mstore(
                        dst,
                        addmod(mulmod(mload(mulLhs), mload(mulRhs), f_q), addendConst, f_q)
                    )
                }}
                // compressed proof point load: [sign_byte || x_coordinate]
                case 22 {{
                    if iszero(eq(len, 4)) {{ fail(0x29) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let offset := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let coordBytes := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    if gt(coordBytes, 0x40) {{ fail(0x2a) }}

                    let xPtr := dst
                    let yPtr := add(dst, 0x40)
                    let pad := sub(0x40, coordBytes)
                    let xCdPtr := add(offset, 1)

                    let modexpInputPtr := 0x80
                    let rhsPtr := 0x1a0
                    let ySqPtr := 0x1e0

                    let flag := byte(0, calldataload(offset))
                    let yOdd := and(flag, 1)
                    let isInf := and(shr(1, flag), 1)
                    success := and(success, iszero(and(flag, 0xfc)))

                    // Zero-initialize x/y limbs then copy compact x.
                    mstore(xPtr, 0)
                    mstore(add(xPtr, 0x20), 0)
                    mstore(yPtr, 0)
                    mstore(add(yPtr, 0x20), 0)
                    calldatacopy(add(xPtr, pad), xCdPtr, coordBytes)

                    let xHi := mload(xPtr)
                    let xLo := mload(add(xPtr, 0x20))

                    if isInf {{
                        // Infinity must carry zero x and odd-flag unset.
                        success := and(eq(yOdd, 0), success)
                        success := and(eq(xHi, 0), success)
                        success := and(eq(xLo, 0), success)
                    }}

                    if iszero(isInf) {{
                        // Enforce x < p.
                        success := and(
                            or(lt(xHi, b_p_hi), and(eq(xHi, b_p_hi), lt(xLo, b_p_lo))),
                            success
                        )

                        // rhs <- x^3 mod p.
                        mstore(modexpInputPtr, 0x40)
                        mstore(add(modexpInputPtr, 0x20), 0x40)
                        mstore(add(modexpInputPtr, 0x40), 0x40)
                        mstore(add(modexpInputPtr, 0x60), xHi)
                        mstore(add(modexpInputPtr, 0x80), xLo)
                        mstore(add(modexpInputPtr, 0xa0), 0)
                        mstore(add(modexpInputPtr, 0xc0), 3)
                        mstore(add(modexpInputPtr, 0xe0), b_p_hi)
                        mstore(add(modexpInputPtr, 0x100), b_p_lo)
                        success := and(
                            eq(staticcall(gas(), 0x05, modexpInputPtr, 0x120, rhsPtr, 0x40), 1),
                            success
                        )

                        // rhs <- (x^3 + 4) mod p.
                        let rhsHi := mload(rhsPtr)
                        let rhsLo0 := mload(add(rhsPtr, 0x20))
                        let rhsLo := add(rhsLo0, 4)
                        let carry := lt(rhsLo, rhsLo0)
                        rhsHi := add(rhsHi, carry)
                        if or(gt(rhsHi, b_p_hi), and(eq(rhsHi, b_p_hi), iszero(lt(rhsLo, b_p_lo)))) {{
                            rhsHi := sub(rhsHi, b_p_hi)
                            let borrow := lt(rhsLo, b_p_lo)
                            rhsLo := sub(rhsLo, b_p_lo)
                            rhsHi := sub(rhsHi, borrow)
                        }}
                        mstore(rhsPtr, rhsHi)
                        mstore(add(rhsPtr, 0x20), rhsLo)

                        // y <- rhs^((p+1)/4) mod p.
                        mstore(modexpInputPtr, 0x40)
                        mstore(add(modexpInputPtr, 0x20), 0x40)
                        mstore(add(modexpInputPtr, 0x40), 0x40)
                        mstore(add(modexpInputPtr, 0x60), rhsHi)
                        mstore(add(modexpInputPtr, 0x80), rhsLo)
                        mstore(add(modexpInputPtr, 0xa0), b_sqrt_exp_hi)
                        mstore(add(modexpInputPtr, 0xc0), b_sqrt_exp_lo)
                        mstore(add(modexpInputPtr, 0xe0), b_p_hi)
                        mstore(add(modexpInputPtr, 0x100), b_p_lo)
                        success := and(
                            eq(staticcall(gas(), 0x05, modexpInputPtr, 0x120, yPtr, 0x40), 1),
                            success
                        )

                        // Validate square root: y^2 == rhs (mod p).
                        mstore(modexpInputPtr, 0x40)
                        mstore(add(modexpInputPtr, 0x20), 0x40)
                        mstore(add(modexpInputPtr, 0x40), 0x40)
                        mstore(add(modexpInputPtr, 0x60), mload(yPtr))
                        mstore(add(modexpInputPtr, 0x80), mload(add(yPtr, 0x20)))
                        mstore(add(modexpInputPtr, 0xa0), 0)
                        mstore(add(modexpInputPtr, 0xc0), 2)
                        mstore(add(modexpInputPtr, 0xe0), b_p_hi)
                        mstore(add(modexpInputPtr, 0x100), b_p_lo)
                        success := and(
                            eq(staticcall(gas(), 0x05, modexpInputPtr, 0x120, ySqPtr, 0x40), 1),
                            success
                        )
                        success := and(eq(mload(ySqPtr), mload(rhsPtr)), success)
                        success := and(eq(mload(add(ySqPtr, 0x20)), mload(add(rhsPtr, 0x20))), success)

                        // Select y root by oddness bit.
                        let yLo := mload(add(yPtr, 0x20))
                        let isOddY := and(yLo, 1)
                        if xor(isOddY, yOdd) {{
                            let negYLo := sub(b_p_lo, yLo)
                            let borrow := lt(b_p_lo, yLo)
                            let negYHi := sub(sub(b_p_hi, mload(yPtr)), borrow)
                            mstore(yPtr, negYHi)
                            mstore(add(yPtr, 0x20), negYLo)
                        }}
                    }}
                }}
                // success := success && staticcall(precompile, cd_ptr, cd_len, rd_ptr, rd_len)
                case 23 {{
                    if iszero(eq(len, 6)) {{ fail(0x2b) }}
                    let precompile := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let cdPtr := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let cdLen := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let rdPtr := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    let rdLen := readArg(argsStart, 4, samePage, ip, pageCount, pagesBase)
                    success := and(success, eq(staticcall(gas(), precompile, cdPtr, cdLen, rdPtr, rdLen), 1))
                }}
                // mstore(dst, addmod(mulmod(mload(mul_lhs), mul_rhs_const, f_q), mload(addend), f_q))
                case 24 {{
                    if iszero(eq(len, 5)) {{ fail(0x2c) }}
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let mulLhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let mulRhsConst := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let addend := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    mstore(
                        dst,
                        addmod(mulmod(mload(mulLhs), mulRhsConst, f_q), mload(addend), f_q)
                    )
                }}
                default {{
                    fail(0x20)
                }}

                ip := endIp
            }}

            if iszero(success) {{
                fail(0x21)
            }}
            return(0, 0)
        }}
    }}
}}
"#,
        page_words = COMPACT_PAGE_BYTES / 32,
        page_buffer_ptr = page_buffer_ptr,
        opcode_version = COMPACT_OPCODE_VERSION,
        base_modulus_hi = base_modulus_hi,
        base_modulus_lo = base_modulus_lo,
        base_sqrt_exp_hi = base_sqrt_exp_hi,
        base_sqrt_exp_lo = base_sqrt_exp_lo
    )
}

fn pad_address(address: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address.to_be_bytes::<20>());
    out
}

fn word_be(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn align_word(value: usize) -> usize {
    (value + 0x1f) & !0x1f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::evm::{
        compact_ir::{CompactInstruction, CompactProgramBuilder},
        compile_solidity_runtime_via_ir, compile_solidity_via_ir, U256,
    };

    #[test]
    fn compact_runtime_template_compiles() {
        let mut builder = CompactProgramBuilder::new();
        builder.push(CompactInstruction::MstoreConst { dst: 0x80, value: U256::from(1) });
        let program = builder.encode();
        let artifacts = build_compact_verifier_artifacts(
            U256::from(17),
            [U256::from(19), U256::from(23)],
            [U256::from(29), U256::from(31)],
            &program,
            0x400,
        );
        let deployment = compile_solidity_via_ir(&artifacts.runtime_solidity);
        let runtime = compile_solidity_runtime_via_ir(&artifacts.runtime_solidity);
        assert!(!deployment.is_empty());
        assert!(!runtime.is_empty());
    }

    #[cfg(feature = "revm")]
    #[test]
    fn compact_runtime_revm_smoke() {
        let mut builder = CompactProgramBuilder::new();
        builder.push(CompactInstruction::MstoreConst { dst: 0xa0, value: U256::from(42) });
        let program = builder.encode();
        let artifacts = build_compact_verifier_artifacts(
            U256::from(17),
            [U256::from(19), U256::from(23)],
            [U256::from(29), U256::from(31)],
            &program,
            0x400,
        );
        let runtime_deployment = compile_solidity_via_ir(&artifacts.runtime_solidity);
        let gas = crate::loader::evm::deploy_compact_and_call(
            artifacts.page_deployment_codes,
            runtime_deployment,
            artifacts.manifest.program_words,
            vec![],
        )
        .expect("compact runtime smoke deploy/call should succeed");
        assert!(gas > 0);
    }
}
