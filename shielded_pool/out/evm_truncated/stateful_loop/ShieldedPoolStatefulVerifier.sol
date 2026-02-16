
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <0.9.0;

contract ShieldedPoolStatefulVerifier {
    error InvalidTransition(uint256 code);
    error VerifierCallFailed();
    error VerifierReturnedFalse();
    error InvalidAccumulatorLimb(uint256 idx);
    error InvalidAccumulatorPairing();
    error InvalidAccumulatorPairingCallFailed();
    error InvalidAccumulatorPairingResult(uint256 got);

    uint256 internal constant LIMB_BITS = 56;
    uint256 internal constant LIMB_MASK = (1 << LIMB_BITS) - 1;
    uint256 internal constant LIMB4_LOW_MASK = (1 << 32) - 1;
    uint256 internal constant FIELD_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    uint256 internal constant CLIENT_PUBLIC_ITEMS_WIDTH = 7;
    uint256 internal constant SUBROOT_PI_OFFSET = 0xc0;
    uint256 internal constant G1MSM_GAS_CAP = 5000000;
    uint256 internal constant PAIRING_GAS_CAP = 20000000;

    uint256 internal constant PAIRING_G2_0 = 0x00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051;
    uint256 internal constant PAIRING_G2_1 = 0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
    uint256 internal constant PAIRING_G2_2 = 0x0000000000000000000000000000000013e02b6052719f607dacd3a088274f65;
    uint256 internal constant PAIRING_G2_3 = 0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
    uint256 internal constant PAIRING_G2_4 = 0x000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a;
    uint256 internal constant PAIRING_G2_5 = 0xadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801;
    uint256 internal constant PAIRING_G2_6 = 0x000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99;
    uint256 internal constant PAIRING_G2_7 = 0xcb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be;
    uint256 internal constant PAIRING_MINUS_TAU_0 = 0x000000000000000000000000000000000e5b20bd8b497a839aee546ad82e898e;
    uint256 internal constant PAIRING_MINUS_TAU_1 = 0x0550d3725c0a37f9ffce8330e70432b550a379d7167b1c78c4a52b8c0b6d119a;
    uint256 internal constant PAIRING_MINUS_TAU_2 = 0x000000000000000000000000000000000a361c2d79c6b2f01c2ba292f1414282;
    uint256 internal constant PAIRING_MINUS_TAU_3 = 0x86daab9c6d22a5c7a452363df6e40eca522f6ad92ca57ce8f638267144dde2a9;
    uint256 internal constant PAIRING_MINUS_TAU_4 = 0x0000000000000000000000000000000014a349ddbf89c64ba50e86646edc1b92;
    uint256 internal constant PAIRING_MINUS_TAU_5 = 0xe2dfd5f1d60f88a06b8fdfc79b0e79df619f3413a304fb7d3c782ee50a020e3d;
    uint256 internal constant PAIRING_MINUS_TAU_6 = 0x00000000000000000000000000000000139cb35126f8a03b1c17ddd0bd10147b;
    uint256 internal constant PAIRING_MINUS_TAU_7 = 0xef592e19eb6fc02885f732e4623ec71f2d34a811f5021be42e9209a26ab42e11;

    address public immutable verifier;
    uint256 public commitmentRoot;
    uint256 public nullifierRoot;
    uint256 public rootsSetRoot;
    uint256 public blockHead;
    uint256 public lastSubroot;

    event ValidationApplied(
        string message,
        uint256 indexed l2BlockNumber,
        uint256 blkPre,
        uint256 blkPost,
        uint256 commitmentRoot,
        uint256 nullifierRoot,
        uint256 rootsSetRoot,
        uint256 subroot
    );

    constructor(
        address _verifier,
        uint256 _commitmentRoot,
        uint256 _nullifierRoot,
        uint256 _rootsSetRoot,
        uint256 _blockHead
    ) {
        verifier = _verifier;
        commitmentRoot = _commitmentRoot;
        nullifierRoot = _nullifierRoot;
        rootsSetRoot = _rootsSetRoot;
        blockHead = _blockHead;
    }

    /// Subroot is exposed as public input #6 in the final-wrap verifier calldata.
    function _extractSubrootFromProofPublicInputs(
        bytes calldata verifierCalldata
    ) private pure returns (uint256 subroot) {
        if (verifierCalldata.length < SUBROOT_PI_OFFSET + 0x20) revert InvalidTransition(6);
        assembly ("memory-safe") {
            subroot := calldataload(add(verifierCalldata.offset, SUBROOT_PI_OFFSET))
        }
    }

    function _sha256ToField(bytes32 digest) private pure returns (uint256) {
        return uint256(digest) % FIELD_MODULUS;
    }

    function _sha256HashPair(uint256 left, uint256 right) private pure returns (uint256) {
        return _sha256ToField(sha256(abi.encodePacked(left, right)));
    }

    function _sha256HashClientPublicItems(
        uint256[] calldata l2BlockMetadata,
        uint256 start
    ) private pure returns (uint256) {
        return _sha256ToField(
            sha256(
                abi.encodePacked(
                    l2BlockMetadata[start],
                    l2BlockMetadata[start + 1],
                    l2BlockMetadata[start + 2],
                    l2BlockMetadata[start + 3],
                    l2BlockMetadata[start + 4],
                    l2BlockMetadata[start + 5],
                    l2BlockMetadata[start + 6]
                )
            )
        );
    }

    function _recomputeSubrootFromMetadata(
        uint256[] calldata l2BlockMetadata
    ) private pure returns (uint256 subroot) {
        uint256 metadataLen = l2BlockMetadata.length;
        if (metadataLen == 0) revert InvalidTransition(10);
        if (metadataLen % CLIENT_PUBLIC_ITEMS_WIDTH != 0) revert InvalidTransition(11);

        uint256 leafCount = metadataLen / CLIENT_PUBLIC_ITEMS_WIDTH;
        if ((leafCount & (leafCount - 1)) != 0) revert InvalidTransition(12);

        uint256[] memory level = new uint256[](leafCount);
        for (uint256 i = 0; i < leafCount; ++i) {
            uint256 start = i * CLIENT_PUBLIC_ITEMS_WIDTH;
            level[i] = _sha256HashClientPublicItems(l2BlockMetadata, start);
        }

        while (leafCount > 1) {
            uint256 nextCount = leafCount >> 1;
            for (uint256 i = 0; i < nextCount; ++i) {
                uint256 offset = i << 1;
                level[i] = _sha256HashPair(level[offset], level[offset + 1]);
            }
            leafCount = nextCount;
        }
        return level[0];
    }

    function _checkLimbRange(uint256 limb, uint256 idx) private pure {
        if (limb > LIMB_MASK) revert InvalidAccumulatorLimb(idx);
    }

    function _decodeFieldElementWords(
        uint256 l0,
        uint256 l1,
        uint256 l2,
        uint256 l3,
        uint256 l4,
        uint256 l5,
        uint256 l6
    ) private pure returns (uint256 hi, uint256 lo) {
        uint256 lowPart = l0
            | (l1 << 56)
            | (l2 << 112)
            | (l3 << 168)
            | ((l4 & LIMB4_LOW_MASK) << 224);
        uint256 highPart = (l4 >> 32) | (l5 << 24) | (l6 << 80);
        unchecked {
            lowPart += 1;
            if (lowPart == 0) {
                highPart += 1;
            }
        }
        return (highPart, lowPart);
    }

    function _decodeWordsFromPi(
        uint256[28] calldata finalAccumulatorPi,
        uint256 start
    ) private pure returns (uint256 hi, uint256 lo) {
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
    }

    function _decodeXWordsFromPi(
        uint256[28] calldata finalAccumulatorPi,
        uint256 start
    ) private pure returns (uint256 hi, uint256 lo, uint256 isId) {
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
    }

    function _decodePoint(
        uint256[28] calldata finalAccumulatorPi,
        uint256 base
    ) private pure returns (uint256 xHi, uint256 xLo, uint256 yHi, uint256 yLo) {
        uint256 isId;
        (xHi, xLo, isId) = _decodeXWordsFromPi(finalAccumulatorPi, base);
        if (isId == 1) {
            return (0, 0, 0, 0);
        }
        (yHi, yLo) = _decodeWordsFromPi(finalAccumulatorPi, base + 7);
    }

    function _normalizeG1Point(
        uint256 xHi,
        uint256 xLo,
        uint256 yHi,
        uint256 yLo
    ) private view returns (bool ok, uint256 nxHi, uint256 nxLo, uint256 nyHi, uint256 nyLo) {
        if (xHi == 0 && xLo == 0 && yHi == 0 && yLo == 0) {
            return (true, 0, 0, 0, 0);
        }

        uint256[5] memory msmInput;
        msmInput[4] = 1;

        // Try canonical [x_hi, x_lo, y_hi, y_lo] first.
        msmInput[0] = xHi;
        msmInput[1] = xLo;
        msmInput[2] = yHi;
        msmInput[3] = yLo;
        assembly ("memory-safe") {
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }
        if (ok) {
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }

        // Fallback: [x_lo, x_hi, y_lo, y_hi].
        msmInput[0] = xLo;
        msmInput[1] = xHi;
        msmInput[2] = yLo;
        msmInput[3] = yHi;
        assembly ("memory-safe") {
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }
        if (ok) {
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }

        // Fallback: [x_hi, x_lo, y_lo, y_hi].
        msmInput[0] = xHi;
        msmInput[1] = xLo;
        msmInput[2] = yLo;
        msmInput[3] = yHi;
        assembly ("memory-safe") {
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }
        if (ok) {
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }

        // Fallback: [x_lo, x_hi, y_hi, y_lo].
        msmInput[0] = xLo;
        msmInput[1] = xHi;
        msmInput[2] = yHi;
        msmInput[3] = yLo;
        assembly ("memory-safe") {
            let ptr := msmInput
            ok := staticcall(G1MSM_GAS_CAP, 0x0c, ptr, 0xa0, ptr, 0x80)
            nxHi := mload(ptr)
            nxLo := mload(add(ptr, 0x20))
            nyHi := mload(add(ptr, 0x40))
            nyLo := mload(add(ptr, 0x60))
        }
        if (ok) {
            return (ok, nxHi, nxLo, nyHi, nyLo);
        }

        return (false, 0, 0, 0, 0);
    }

    function _checkFinalAccumulatorPairing(
        uint256[28] calldata finalAccumulatorPi
    ) private view returns (bool callOk, uint256 resultWord) {
        (uint256 lhsXHi, uint256 lhsXLo, uint256 lhsYHi, uint256 lhsYLo) =
            _decodePoint(finalAccumulatorPi, 0);
        (uint256 rhsXHi, uint256 rhsXLo, uint256 rhsYHi, uint256 rhsYLo) =
            _decodePoint(finalAccumulatorPi, 14);

        bool lhsNormOk;
        bool rhsNormOk;
        (lhsNormOk, lhsXHi, lhsXLo, lhsYHi, lhsYLo) =
            _normalizeG1Point(lhsXHi, lhsXLo, lhsYHi, lhsYLo);
        if (!lhsNormOk) {
            return (false, 11);
        }
        (rhsNormOk, rhsXHi, rhsXLo, rhsYHi, rhsYLo) =
            _normalizeG1Point(rhsXHi, rhsXLo, rhsYHi, rhsYLo);
        if (!rhsNormOk) {
            return (false, 12);
        }

        uint256[24] memory pairingInput;
        pairingInput[0] = rhsXHi;
        pairingInput[1] = rhsXLo;
        pairingInput[2] = rhsYHi;
        pairingInput[3] = rhsYLo;
        pairingInput[4] = PAIRING_G2_0;
        pairingInput[5] = PAIRING_G2_1;
        pairingInput[6] = PAIRING_G2_2;
        pairingInput[7] = PAIRING_G2_3;
        pairingInput[8] = PAIRING_G2_4;
        pairingInput[9] = PAIRING_G2_5;
        pairingInput[10] = PAIRING_G2_6;
        pairingInput[11] = PAIRING_G2_7;
        pairingInput[12] = lhsXHi;
        pairingInput[13] = lhsXLo;
        pairingInput[14] = lhsYHi;
        pairingInput[15] = lhsYLo;
        pairingInput[16] = PAIRING_MINUS_TAU_0;
        pairingInput[17] = PAIRING_MINUS_TAU_1;
        pairingInput[18] = PAIRING_MINUS_TAU_2;
        pairingInput[19] = PAIRING_MINUS_TAU_3;
        pairingInput[20] = PAIRING_MINUS_TAU_4;
        pairingInput[21] = PAIRING_MINUS_TAU_5;
        pairingInput[22] = PAIRING_MINUS_TAU_6;
        pairingInput[23] = PAIRING_MINUS_TAU_7;

        assembly ("memory-safe") {
            let ptr := pairingInput
            callOk := staticcall(PAIRING_GAS_CAP, 0x0f, ptr, 0x300, ptr, 0x20)
            resultWord := mload(ptr)
            if iszero(callOk) {
                resultWord := 13
            }
        }
        return (callOk, resultWord);
    }

    function verifyAndUpdate(
        bytes calldata verifierCalldata,
        uint256 cPre,
        uint256 cPost,
        uint256 nPre,
        uint256 nPost,
        uint256 blkPre,
        uint256 blkPost,
        uint256 preRootsSetRoot,
        uint256 postRootsSetRoot,
        uint256[28] calldata finalAccumulatorPi,
        uint256[] calldata l2BlockMetadata
    ) external returns (bool) {
        if (cPre != commitmentRoot) revert InvalidTransition(1);
        if (nPre != nullifierRoot) revert InvalidTransition(2);
        if (preRootsSetRoot != rootsSetRoot) revert InvalidTransition(3);
        if (blkPre != blockHead) revert InvalidTransition(4);
        if (blkPost != blkPre + 1) revert InvalidTransition(5);

        (bool ok, bytes memory ret) = verifier.call(verifierCalldata);
        if (!ok) revert VerifierCallFailed();
        if (ret.length >= 32) {
            uint256 value;
            assembly ("memory-safe") {
                value := mload(add(ret, 0x20))
            }
            if (value == 0) revert VerifierReturnedFalse();
        }

        (bool pairingCallOk, uint256 pairingResult) =
            _checkFinalAccumulatorPairing(finalAccumulatorPi);
        if (!pairingCallOk) revert InvalidAccumulatorPairingResult(pairingResult);
        if (pairingResult != 1) revert InvalidAccumulatorPairingResult(pairingResult);

        uint256 proofSubroot = _extractSubrootFromProofPublicInputs(verifierCalldata);
        uint256 subroot = _recomputeSubrootFromMetadata(l2BlockMetadata);
        //if (subroot != proofSubroot) revert InvalidTransition(13);

        commitmentRoot = cPost;
        nullifierRoot = nPost;
        rootsSetRoot = postRootsSetRoot;
        blockHead = blkPost;
        lastSubroot = subroot;
        emit ValidationApplied(
            "Validation successful",
            blkPost,
            blkPre,
            blkPost,
            cPost,
            nPost,
            postRootsSetRoot,
            subroot
        );
        return true;
    }
}
