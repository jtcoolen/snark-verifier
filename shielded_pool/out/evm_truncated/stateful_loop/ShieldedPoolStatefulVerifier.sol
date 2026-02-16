
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract ShieldedPoolStatefulVerifier {
    error InvalidTransition(uint256 code);
    error VerifierCallFailed();
    error VerifierReturnedFalse();

    address public immutable verifier;
    uint256 public commitmentRoot;
    uint256 public nullifierRoot;
    uint256 public rootsSetRoot;
    uint256 public blockHead;
    uint256 public lastSubroot;

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

    function verifyAndUpdate(
        bytes calldata verifierCalldata,
        uint256 cPre,
        uint256 cPost,
        uint256 nPre,
        uint256 nPost,
        uint256 blkPre,
        uint256 blkPost,
        uint256 subroot,
        uint256 preRootsSetRoot,
        uint256 postRootsSetRoot
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

        commitmentRoot = cPost;
        nullifierRoot = nPost;
        rootsSetRoot = postRootsSetRoot;
        blockHead = blkPost;
        lastSubroot = subroot;
        return true;
    }
}
