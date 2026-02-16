
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

contract Halo2VerifierDispatcher {
    address[] private shards;

    constructor(address[] memory _shards) {
        shards = _shards;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {
                revert(0, 0)
            }

            mstore(0x25b40, 1)

            let len := sload(0)
            mstore(0x00, 0)
            let base := keccak256(0x00, 0x20)

            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                mstore(0x40, 0x80)
                let shard := and(
                    sload(add(base, i)),
                    0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
                )
                if iszero(delegatecall(gas(), shard, 0, calldatasize(), 0, 0)) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
            }

            if iszero(mload(0x25b40)) {
                revert(0, 0)
            }
            return(0, 0)
        }
    }
}
