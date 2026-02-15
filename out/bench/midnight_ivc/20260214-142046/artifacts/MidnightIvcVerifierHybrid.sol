
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

contract Halo2Verifier {
    // slot 0
    address[] private pages;
    // slot 1
    uint256 private programWords;

    constructor(address[] memory _pages, uint256 _programWords) {
        require(_pages.length > 0, "no pages");
        require(_programWords > 1, "empty program");
        pages = _pages;
        programWords = _programWords;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            let data := mload(0x40)
            if lt(data, 0x80) {
                mstore(0, 0x31)
                revert(0, 0x20)
            }

            let pageCount := sload(0)
            let totalWords := sload(1)
            if or(iszero(pageCount), lt(totalWords, 2)) {
                mstore(0, 0x32)
                revert(0, 0x20)
            }

            let success := 1
            let f_q := 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
            let b_p_hi := 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7
            let b_p_lo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            let b_sqrt_exp_hi := 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35
            let b_sqrt_exp_lo := 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab
            // Cache metadata in low scratch words.
            mstore(0x20, not(0)) // loaded page index
            mstore(0x40, 0)      // loaded page word count
            mstore(0x60, 0)      // loaded page base word

            function fail(code) {
                mstore(0, code)
                revert(0, 0x20)
            }

            mstore(0x00, 0)
            let pagesBase := keccak256(0x00, 0x20)

            function pageAddr(idx, pageCountArg, pagesBaseArg) -> addr {
                if iszero(lt(idx, pageCountArg)) {
                    fail(0x01)
                }
                addr := and(
                    sload(add(pagesBaseArg, idx)),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
                if iszero(addr) {
                    fail(0x02)
                }
            }

            function ensurePageLoaded(wordIndex, pageCountArg, pagesBaseArg) -> pageWordOff {
                let pageIdx := div(wordIndex, 768)
                pageWordOff := mod(wordIndex, 768)

                if iszero(eq(pageIdx, mload(0x20))) {
                    let addr := pageAddr(pageIdx, pageCountArg, pagesBaseArg)
                    let size := extcodesize(addr)
                    if iszero(eq(mod(size, 0x20), 0)) {
                        fail(0x07)
                    }
                    extcodecopy(addr, 156320, 0, size)
                    mstore(0x20, pageIdx)
                    mstore(0x40, div(size, 0x20))
                    mstore(0x60, mul(pageIdx, 768))
                }

                let loadedWords := mload(0x40)
                if iszero(lt(pageWordOff, loadedWords)) {
                    fail(0x03)
                }
            }

            function wordAt(pageWordOff) -> word {
                word := mload(add(156320, mul(pageWordOff, 0x20)))
            }

            function loadWord(wordIndex, pageCountArg, pagesBaseArg) -> word {
                word := wordAt(ensurePageLoaded(wordIndex, pageCountArg, pagesBaseArg))
            }

            function readArg(argsStart, argIdx, samePage, ipArg, pageCountArg, pagesBaseArg) -> word {
                if samePage {
                    word := wordAt(add(argsStart, argIdx))
                }
                if iszero(samePage) {
                    word := loadWord(add(add(ipArg, 1), argIdx), pageCountArg, pagesBaseArg)
                }
            }

            function operandValue(tag, value) -> out {
                switch tag
                case 0 {
                    out := mload(value)
                }
                case 1 {
                    out := value
                }
                default {
                    fail(0x04)
                }
            }

            if iszero(eq(loadWord(0, pageCount, pagesBase), 2)) {
                fail(0x05)
            }

            for { let ip := 1 } lt(ip, totalWords) {} {
                let headerOff := ensurePageLoaded(ip, pageCount, pagesBase)
                let header := wordAt(headerOff)
                let opcode := byte(0, header)
                let len := byte(1, header)
                if or(iszero(len), gt(add(ip, len), totalWords)) {
                    fail(0x06)
                }
                let endIp := add(ip, len)
                let currentPage := div(ip, 768)
                let samePage := and(
                    eq(currentPage, div(sub(endIp, 1), 768)),
                    eq(currentPage, mload(0x20))
                )
                let argsStart := add(headerOff, 1)

                switch opcode
                // mstore(dst, value)
                case 1 {
                    if iszero(eq(len, 3)) { fail(0x11) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let value := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, value)
                }
                // mstore(dst, mload(src))
                case 2 {
                    if iszero(eq(len, 3)) { fail(0x12) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mload(src))
                }
                // mstore8(dst, value)
                case 3 {
                    if iszero(eq(len, 3)) { fail(0x13) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let value := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore8(dst, and(value, 0xff))
                }
                // mstore(dst, sub(f_q, operand))
                case 4 {
                    if iszero(eq(len, 4)) { fail(0x14) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let tag := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let value := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let v := operandValue(tag, value)
                    mstore(dst, sub(f_q, v))
                }
                // mstore(dst, addmod(lhs, rhs, f_q))
                case 5 {
                    if iszero(eq(len, 6)) { fail(0x15) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhsTag := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let lhsValue := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let rhsTag := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    let rhsValue := readArg(argsStart, 4, samePage, ip, pageCount, pagesBase)
                    mstore(dst, addmod(operandValue(lhsTag, lhsValue), operandValue(rhsTag, rhsValue), f_q))
                }
                // mstore(dst, mulmod(lhs, rhs, f_q))
                case 6 {
                    if iszero(eq(len, 6)) { fail(0x16) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhsTag := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let lhsValue := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let rhsTag := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    let rhsValue := readArg(argsStart, 4, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mulmod(operandValue(lhsTag, lhsValue), operandValue(rhsTag, rhsValue), f_q))
                }
                // mstore(dst, mod(calldataload(offset), f_q))
                case 7 {
                    if iszero(eq(len, 3)) { fail(0x17) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let offset := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mod(calldataload(offset), f_q))
                }
                // uncompressed proof point load: zero limbs then copy x/y from calldata with left padding.
                case 8 {
                    if iszero(eq(len, 4)) { fail(0x18) }
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
                }
                // copy affine point (4 words)
                case 9 {
                    if iszero(eq(len, 3)) { fail(0x19) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mload(src))
                    mstore(add(dst, 0x20), mload(add(src, 0x20)))
                    mstore(add(dst, 0x40), mload(add(src, 0x40)))
                    mstore(add(dst, 0x60), mload(add(src, 0x60)))
                }
                // mstore(dst, keccak256(ptr, len))
                case 10 {
                    if iszero(eq(len, 4)) { fail(0x1a) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let ptr := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let hashLen := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, keccak256(ptr, hashLen))
                }
                // success := success && staticcall(precompile, cd_ptr, rd_ptr)
                case 11 {
                    if iszero(eq(len, 4)) { fail(0x1b) }
                    let precompile := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let cdPtr := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rdPtr := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let cdLen := 0
                    let rdLen := 0
                    switch precompile
                    case 0x05 {
                        cdLen := 0xc0
                        rdLen := 0x20
                    }
                    case 0x0b {
                        cdLen := 0x100
                        rdLen := 0x80
                    }
                    case 0x0c {
                        cdLen := 0xa0
                        rdLen := 0x80
                    }
                    case 0x0f {
                        cdLen := 0x300
                        rdLen := 0x20
                    }
                    default {
                        fail(0x1c)
                    }
                    success := and(success, eq(staticcall(gas(), precompile, cdPtr, cdLen, rdPtr, rdLen), 1))
                }
                // success := success && (mload(ptr) == 1)
                case 12 {
                    if iszero(eq(len, 2)) { fail(0x1d) }
                    let ptr := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    success := and(success, eq(mload(ptr), 1))
                }
                // decode affine point from limbs.
                case 13 {
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let bits := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let limbCount := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let expectedLen := add(4, mul(4, limbCount))
                    if iszero(eq(len, expectedLen)) { fail(0x1e) }

                    let cursor := add(ip, 4)
                    let xLo := 0
                    let xHi := 0
                    for { let i := 0 } lt(i, limbCount) { i := add(i, 1) } {
                        let tag := loadWord(cursor, pageCount, pagesBase)
                        let value := loadWord(add(cursor, 1), pageCount, pagesBase)
                        let limb := operandValue(tag, value)
                        let shift := mul(i, bits)
                        if lt(shift, 256) {
                            xLo := add(xLo, shl(shift, limb))
                        }
                        if iszero(lt(shift, 256)) {
                            xHi := add(xHi, shl(sub(shift, 256), limb))
                        }
                        cursor := add(cursor, 2)
                    }
                    mstore(dst, xHi)
                    mstore(add(dst, 0x20), xLo)

                    let yLo := 0
                    let yHi := 0
                    for { let j := 0 } lt(j, limbCount) { j := add(j, 1) } {
                        let tag := loadWord(cursor, pageCount, pagesBase)
                        let value := loadWord(add(cursor, 1), pageCount, pagesBase)
                        let limb := operandValue(tag, value)
                        let shift := mul(j, bits)
                        if lt(shift, 256) {
                            yLo := add(yLo, shl(shift, limb))
                        }
                        if iszero(lt(shift, 256)) {
                            yHi := add(yHi, shl(sub(shift, 256), limb))
                        }
                        cursor := add(cursor, 2)
                    }
                    mstore(add(dst, 0x40), yHi)
                    mstore(add(dst, 0x60), yLo)
                }
                // mstore(dst, mod(mload(src), f_q))
                case 14 {
                    if iszero(eq(len, 3)) { fail(0x1f) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mod(mload(src), f_q))
                }
                // mstore(dst, sub(f_q, mload(src)))
                case 15 {
                    if iszero(eq(len, 3)) { fail(0x22) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let src := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    mstore(dst, sub(f_q, mload(src)))
                }
                // mstore(dst, addmod(mload(lhs), mload(rhs), f_q))
                case 16 {
                    if iszero(eq(len, 4)) { fail(0x23) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, addmod(mload(lhs), mload(rhs), f_q))
                }
                // mstore(dst, mulmod(mload(lhs), mload(rhs), f_q))
                case 17 {
                    if iszero(eq(len, 4)) { fail(0x24) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mulmod(mload(lhs), mload(rhs), f_q))
                }
                // mstore(dst, addmod(mload(lhs), rhsConst, f_q))
                case 18 {
                    if iszero(eq(len, 4)) { fail(0x25) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhsConst := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, addmod(mload(lhs), rhsConst, f_q))
                }
                // mstore(dst, mulmod(mload(lhs), rhsConst, f_q))
                case 19 {
                    if iszero(eq(len, 4)) { fail(0x26) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let lhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let rhsConst := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    mstore(dst, mulmod(mload(lhs), rhsConst, f_q))
                }
                // mstore(dst, addmod(mulmod(mload(mul_lhs), mload(mul_rhs), f_q), mload(addend), f_q))
                case 20 {
                    if iszero(eq(len, 5)) { fail(0x27) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let mulLhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let mulRhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let addend := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    mstore(
                        dst,
                        addmod(mulmod(mload(mulLhs), mload(mulRhs), f_q), mload(addend), f_q)
                    )
                }
                // mstore(dst, addmod(mulmod(mload(mul_lhs), mload(mul_rhs), f_q), addendConst, f_q))
                case 21 {
                    if iszero(eq(len, 5)) { fail(0x28) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let mulLhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let mulRhs := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let addendConst := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    mstore(
                        dst,
                        addmod(mulmod(mload(mulLhs), mload(mulRhs), f_q), addendConst, f_q)
                    )
                }
                // compressed proof point load: [sign_byte || x_coordinate]
                case 22 {
                    if iszero(eq(len, 4)) { fail(0x29) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let offset := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let coordBytes := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    if gt(coordBytes, 0x40) { fail(0x2a) }

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

                    if isInf {
                        // Infinity must carry zero x and odd-flag unset.
                        success := and(eq(yOdd, 0), success)
                        success := and(eq(xHi, 0), success)
                        success := and(eq(xLo, 0), success)
                    }

                    if iszero(isInf) {
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
                        if or(gt(rhsHi, b_p_hi), and(eq(rhsHi, b_p_hi), iszero(lt(rhsLo, b_p_lo)))) {
                            rhsHi := sub(rhsHi, b_p_hi)
                            let borrow := lt(rhsLo, b_p_lo)
                            rhsLo := sub(rhsLo, b_p_lo)
                            rhsHi := sub(rhsHi, borrow)
                        }
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
                        if xor(isOddY, yOdd) {
                            let negYLo := sub(b_p_lo, yLo)
                            let borrow := lt(b_p_lo, yLo)
                            let negYHi := sub(sub(b_p_hi, mload(yPtr)), borrow)
                            mstore(yPtr, negYHi)
                            mstore(add(yPtr, 0x20), negYLo)
                        }
                    }
                }
                // success := success && staticcall(precompile, cd_ptr, cd_len, rd_ptr, rd_len)
                case 23 {
                    if iszero(eq(len, 6)) { fail(0x2b) }
                    let precompile := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let cdPtr := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let cdLen := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let rdPtr := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    let rdLen := readArg(argsStart, 4, samePage, ip, pageCount, pagesBase)
                    success := and(success, eq(staticcall(gas(), precompile, cdPtr, cdLen, rdPtr, rdLen), 1))
                }
                // mstore(dst, addmod(mulmod(mload(mul_lhs), mul_rhs_const, f_q), mload(addend), f_q))
                case 24 {
                    if iszero(eq(len, 5)) { fail(0x2c) }
                    let dst := readArg(argsStart, 0, samePage, ip, pageCount, pagesBase)
                    let mulLhs := readArg(argsStart, 1, samePage, ip, pageCount, pagesBase)
                    let mulRhsConst := readArg(argsStart, 2, samePage, ip, pageCount, pagesBase)
                    let addend := readArg(argsStart, 3, samePage, ip, pageCount, pagesBase)
                    mstore(
                        dst,
                        addmod(mulmod(mload(mulLhs), mulRhsConst, f_q), mload(addend), f_q)
                    )
                }
                default {
                    fail(0x20)
                }

                ip := endIp
            }

            if iszero(success) {
                fail(0x21)
            }
            return(0, 0)
        }
    }
}
