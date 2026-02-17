
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

contract Halo2Verifier {
    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {
                revert(0, 0)
            }

            let success := true
            let f_q := 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
            
        {
            mstore(0x220, 0x00000000000000000000000000000000139b631597bdbd49196d2d62d20197da)
            mstore(0x240, 0x11982b3d62098ec59d15d70db4098e242b7ed05e4c09ea953a2ac011d1b72daa)
            mstore(0x260, 0x00000000000000000000000000000000038c336ac9259157371685785e5bdf2d)
            mstore(0x280, 0xf54cd5d306c2f08a613302407081d2cec0ceb97c64a769f9cc968c9179381cac)
        }

        {
            mstore(0x2a0, 0x0000000000000000000000000000000006b2686b6361752794eff6d9f11c8612)
            mstore(0x2c0, 0xaa891fb290d5962c164082ed247caea7504c9c3aa2ac2318046c1e757cd6c682)
            mstore(0x2e0, 0x0000000000000000000000000000000004f3fd07bc9831148c998d9e3b70e026)
            mstore(0x300, 0x39c70ef9b620b060f0ff724a15a609bf34c25e70df9eaf35a815f7d5950985f8)
        }

        {
            mstore(0x320, 0x000000000000000000000000000000000b38e07d75fd1740470f505d279cea3e)
            mstore(0x340, 0xdf21a9d4c77102c751c226bf2cbaea428bf543639fe7078341df6aca50382572)
            mstore(0x360, 0x000000000000000000000000000000000bde9c0a9037d7be4141dae01bd71a28)
            mstore(0x380, 0x95918cfecfa199843bb40d0ca2286c5ae4ae3d72c0b07176c348aab20075587f)
        }

        {
            mstore(0x3a0, 0x000000000000000000000000000000000c466608a4603295f7e63265064dbd0c)
            mstore(0x3c0, 0xb6f4fa032bec91c5e4d5a18d26cd7bc718cf16fd721379cfed00a60e88d1c210)
            mstore(0x3e0, 0x00000000000000000000000000000000042962c1ec7417dddb1c0acdc2d5fa21)
            mstore(0x400, 0x0d7009e362b2561d2191a5e19ccd539ba7741cf0ba3575e614d8cb7b6d35ce53)
        }

        {
            mstore(0x420, 0x000000000000000000000000000000000321ecc8b4cd35eed10899b0853b1f38)
            mstore(0x440, 0x220ab5ea4a46fc10db042a5522b175082b858b2d95a8e5d97960156e88a72278)
            mstore(0x460, 0x00000000000000000000000000000000069cd236ee42ef64c16ce18300d62757)
            mstore(0x480, 0xed2462e41a2cf08ee6bf04dc0a73d7784870833bdcfdaaa09015f32ce1f1137f)
        }

        {
            mstore(0x4a0, 0x000000000000000000000000000000000bf6ee4f45dee3fbaae5650ea30a5c15)
            mstore(0x4c0, 0x079d01637901bfb2a61af62c5a0ae36e55e577de19551835329629c642c7d2ce)
            mstore(0x4e0, 0x00000000000000000000000000000000061bc0e90ea25657ed5ad20652c614c9)
            mstore(0x500, 0x1deaeb897e49f9760256b5e711b8c8baae1fb635733443efc13947ea86b211c7)
        }

        {
            mstore(0x520, 0x000000000000000000000000000000000239f14edc813f067dcb36a0a4b7e178)
            mstore(0x540, 0xa644918df7bb5a83b0173e30bdc1b8715372bcdbcf340cfde5503d81ed36336b)
            mstore(0x560, 0x0000000000000000000000000000000018df15ae4597a66019d1c17a6ee5fb2e)
            mstore(0x580, 0x245b11b8eb125d69da90d7c48a24d23576660f8be440aca249a9bc8597309eeb)
        }

        {
            mstore(0x5a0, 0x000000000000000000000000000000000e12c63aec033e3d88a1fb8781cb3e52)
            mstore(0x5c0, 0x620375c557d06bb4f40b80a112015ac4b7c082cec41c2358c1ae73a219331c47)
            mstore(0x5e0, 0x0000000000000000000000000000000001d5a2ce8354d2c862ab62fb2cee74f9)
            mstore(0x600, 0xd8a9a0a5c6b3d4b93035f731c223c058ffa23859b9fc3d93eff6c4dad34604dc)
        }
mstore(0x640, mod(calldataload(0x0), f_q))
mstore(0x620, 29835137816753854245315318298259226497787828252175160484610535021087050655573)

        {
            mstore(0x660, 0)
            mstore(0x680, 0)
            mstore(0x6a0, 0)
            mstore(0x6c0, 0)
            calldatacopy(0x670, 0x20, 0x30)
            calldatacopy(0x6b0, 0x50, 0x30)
        }

        {
            mstore(0x6e0, 0)
            mstore(0x700, 0)
            mstore(0x720, 0)
            mstore(0x740, 0)
            calldatacopy(0x6f0, 0x80, 0x30)
            calldatacopy(0x730, 0xb0, 0x30)
        }

        {
            mstore(0x760, 0)
            mstore(0x780, 0)
            mstore(0x7a0, 0)
            mstore(0x7c0, 0)
            calldatacopy(0x770, 0xe0, 0x30)
            calldatacopy(0x7b0, 0x110, 0x30)
        }
mstore(0x7e0, keccak256(0x620, 448))
{
            let hash := mload(0x7e0)
            mstore(0x800, mod(hash, f_q))
            mstore(0x820, hash)
        }
mstore8(2112, 1)
mstore(0x840, keccak256(0x820, 33))
{
            let hash := mload(0x840)
            mstore(0x860, mod(hash, f_q))
            mstore(0x880, hash)
        }
mstore8(2208, 1)
mstore(0x8a0, keccak256(0x880, 33))
{
            let hash := mload(0x8a0)
            mstore(0x8c0, mod(hash, f_q))
            mstore(0x8e0, hash)
        }

        {
            mstore(0x900, 0)
            mstore(0x920, 0)
            mstore(0x940, 0)
            mstore(0x960, 0)
            calldatacopy(0x910, 0x140, 0x30)
            calldatacopy(0x950, 0x170, 0x30)
        }

        {
            mstore(0x980, 0)
            mstore(0x9a0, 0)
            mstore(0x9c0, 0)
            mstore(0x9e0, 0)
            calldatacopy(0x990, 0x1a0, 0x30)
            calldatacopy(0x9d0, 0x1d0, 0x30)
        }

        {
            mstore(0xa00, 0)
            mstore(0xa20, 0)
            mstore(0xa40, 0)
            mstore(0xa60, 0)
            calldatacopy(0xa10, 0x200, 0x30)
            calldatacopy(0xa50, 0x230, 0x30)
        }
mstore(0xa80, keccak256(0x8e0, 416))
{
            let hash := mload(0xa80)
            mstore(0xaa0, mod(hash, f_q))
            mstore(0xac0, hash)
        }

        {
            mstore(0xae0, 0)
            mstore(0xb00, 0)
            mstore(0xb20, 0)
            mstore(0xb40, 0)
            calldatacopy(0xaf0, 0x260, 0x30)
            calldatacopy(0xb30, 0x290, 0x30)
        }

        {
            mstore(0xb60, 0)
            mstore(0xb80, 0)
            mstore(0xba0, 0)
            mstore(0xbc0, 0)
            calldatacopy(0xb70, 0x2c0, 0x30)
            calldatacopy(0xbb0, 0x2f0, 0x30)
        }

        {
            mstore(0xbe0, 0)
            mstore(0xc00, 0)
            mstore(0xc20, 0)
            mstore(0xc40, 0)
            calldatacopy(0xbf0, 0x320, 0x30)
            calldatacopy(0xc30, 0x350, 0x30)
        }
mstore(0xc60, keccak256(0xac0, 416))
{
            let hash := mload(0xc60)
            mstore(0xc80, mod(hash, f_q))
            mstore(0xca0, hash)
        }
mstore(0xcc0, mod(calldataload(0x380), f_q))
mstore(0xce0, mod(calldataload(0x3a0), f_q))
mstore(0xd00, mod(calldataload(0x3c0), f_q))
mstore(0xd20, mod(calldataload(0x3e0), f_q))
mstore(0xd40, mod(calldataload(0x400), f_q))
mstore(0xd60, mod(calldataload(0x420), f_q))
mstore(0xd80, mod(calldataload(0x440), f_q))
mstore(0xda0, mod(calldataload(0x460), f_q))
mstore(0xdc0, mod(calldataload(0x480), f_q))
mstore(0xde0, mod(calldataload(0x4a0), f_q))
mstore(0xe00, mod(calldataload(0x4c0), f_q))
mstore(0xe20, mod(calldataload(0x4e0), f_q))
mstore(0xe40, mod(calldataload(0x500), f_q))
mstore(0xe60, mod(calldataload(0x520), f_q))
mstore(0xe80, mod(calldataload(0x540), f_q))
mstore(0xea0, mod(calldataload(0x560), f_q))
mstore(0xec0, mod(calldataload(0x580), f_q))
mstore(0xee0, keccak256(0xca0, 576))
{
            let hash := mload(0xee0)
            mstore(0xf00, mod(hash, f_q))
            mstore(0xf20, hash)
        }

        {
            mstore(0xf40, 0)
            mstore(0xf60, 0)
            mstore(0xf80, 0)
            mstore(0xfa0, 0)
            calldatacopy(0xf50, 0x5a0, 0x30)
            calldatacopy(0xf90, 0x5d0, 0x30)
        }

        {
            mstore(0xfc0, 0)
            mstore(0xfe0, 0)
            mstore(0x1000, 0)
            mstore(0x1020, 0)
            calldatacopy(0xfd0, 0x600, 0x30)
            calldatacopy(0x1010, 0x630, 0x30)
        }

        {
            mstore(0x1040, 0)
            mstore(0x1060, 0)
            mstore(0x1080, 0)
            mstore(0x10a0, 0)
            calldatacopy(0x1050, 0x660, 0x30)
            calldatacopy(0x1090, 0x690, 0x30)
        }
mstore(0x10c0, keccak256(0xf20, 416))
{
            let hash := mload(0x10c0)
            mstore(0x10e0, mod(hash, f_q))
            mstore(0x1100, hash)
        }
mstore(0x1120, mulmod(mload(0xc80), mload(0xc80), f_q))
mstore(0x1140, mulmod(mload(0x1120), mload(0x1120), f_q))
mstore(0x1160, mulmod(mload(0x1140), mload(0x1140), f_q))
mstore(0x1180, mulmod(mload(0x1160), mload(0x1160), f_q))
mstore(0x11a0, mulmod(mload(0x1180), mload(0x1180), f_q))
mstore(0x11c0, mulmod(mload(0x11a0), mload(0x11a0), f_q))
mstore(0x11e0, mulmod(mload(0x11c0), mload(0x11c0), f_q))
mstore(0x1200, mulmod(mload(0x11e0), mload(0x11e0), f_q))
mstore(0x1220, mulmod(mload(0x1200), mload(0x1200), f_q))
mstore(0x1240, mulmod(mload(0x1220), mload(0x1220), f_q))
mstore(0x1260, mulmod(mload(0x1240), mload(0x1240), f_q))
mstore(0x1280, mulmod(mload(0x1260), mload(0x1260), f_q))
mstore(0x12a0, addmod(mload(0x1280), 52435875175126190479447740508185965837690552500527637822603658699938581184512, f_q))
mstore(0x12c0, mulmod(mload(0x12a0), 52423073447788513186850219087163459498374710080483563692275874603576291491841, f_q))
mstore(0x12e0, mulmod(mload(0x12c0), 20090193668266119872620102064832883765253348140414125816117877893436209362462, f_q))
mstore(0x1300, addmod(mload(0xc80), 32345681506860070606827638443353082072437204360113512006485780806502371822051, f_q))
mstore(0x1320, mulmod(mload(0x12c0), 32649132425011766248107187750088482855434888486916405379705025557137526796582, f_q))
mstore(0x1340, addmod(mload(0xc80), 19786742750114424231340552758097482982255664013611232442898633142801054387931, f_q))
mstore(0x1360, mulmod(mload(0x12c0), 36815421669481109810171413925233110915304823983913164224028689762034127238951, f_q))
mstore(0x1380, addmod(mload(0xc80), 15620453505645080669276326582952854922385728516614473598574968937904453945562, f_q))
mstore(0x13a0, mulmod(mload(0x12c0), 15452603480080784356295137210386725334417616592955538195175950284291734913331, f_q))
mstore(0x13c0, addmod(mload(0xc80), 36983271695045406123152603297799240503272935907572099627427708415646846271182, f_q))
mstore(0x13e0, mulmod(mload(0x12c0), 38618283626480733637682686497654511901394394074436352158867102736890772187910, f_q))
mstore(0x1400, addmod(mload(0xc80), 13817591548645456841765054010531453936296158426091285663736555963047808996603, f_q))
mstore(0x1420, mulmod(mload(0x12c0), 25829815649260311651249373569448671287036547786131478959351418120540316250978, f_q))
mstore(0x1440, addmod(mload(0xc80), 26606059525865878828198366938737294550654004714396158863252240579398264933535, f_q))
mstore(0x1460, mulmod(mload(0x12c0), 1, f_q))
mstore(0x1480, addmod(mload(0xc80), 52435875175126190479447740508185965837690552500527637822603658699938581184512, f_q))
{
            let prod := mload(0x1300)

                prod := mulmod(mload(0x1340), prod, f_q)
                mstore(0x14a0, prod)
            
                prod := mulmod(mload(0x1380), prod, f_q)
                mstore(0x14c0, prod)
            
                prod := mulmod(mload(0x13c0), prod, f_q)
                mstore(0x14e0, prod)
            
                prod := mulmod(mload(0x1400), prod, f_q)
                mstore(0x1500, prod)
            
                prod := mulmod(mload(0x1440), prod, f_q)
                mstore(0x1520, prod)
            
                prod := mulmod(mload(0x1480), prod, f_q)
                mstore(0x1540, prod)
            
                prod := mulmod(mload(0x12a0), prod, f_q)
                mstore(0x1560, prod)
            
        }
mstore(0x15a0, 32)
mstore(0x15c0, 32)
mstore(0x15e0, 32)
mstore(0x1600, mload(0x1560))
mstore(0x1620, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x1640, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x15a0, 0xc0, 0x1580, 0x20), 1), success)
{
            
            let inv := mload(0x1580)
            let v
        
                    v := mload(0x12a0)
                    mstore(4768, mulmod(mload(0x1540), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1480)
                    mstore(5248, mulmod(mload(0x1520), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1440)
                    mstore(5184, mulmod(mload(0x1500), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1400)
                    mstore(5120, mulmod(mload(0x14e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x13c0)
                    mstore(5056, mulmod(mload(0x14c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1380)
                    mstore(4992, mulmod(mload(0x14a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1340)
                    mstore(4928, mulmod(mload(0x1300), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x1300, inv)

        }
mstore(0x1660, mulmod(mload(0x12e0), mload(0x1300), f_q))
mstore(0x1680, mulmod(mload(0x1320), mload(0x1340), f_q))
mstore(0x16a0, mulmod(mload(0x1360), mload(0x1380), f_q))
mstore(0x16c0, mulmod(mload(0x13a0), mload(0x13c0), f_q))
mstore(0x16e0, mulmod(mload(0x13e0), mload(0x1400), f_q))
mstore(0x1700, mulmod(mload(0x1420), mload(0x1440), f_q))
mstore(0x1720, mulmod(mload(0x1460), mload(0x1480), f_q))
{
            let result := mulmod(mload(0x1720), mload(0x640), f_q)
mstore(5952, result)
        }
mstore(0x1760, mulmod(mload(0xcc0), mload(0xd20), f_q))
mstore(0x1780, mulmod(mload(0xce0), mload(0xd40), f_q))
mstore(0x17a0, addmod(mload(0x1760), mload(0x1780), f_q))
mstore(0x17c0, mulmod(mload(0xd00), mload(0xd60), f_q))
mstore(0x17e0, addmod(mload(0x17a0), mload(0x17c0), f_q))
mstore(0x1800, mulmod(mload(0xcc0), mload(0xd80), f_q))
mstore(0x1820, mulmod(mload(0xce0), mload(0x1800), f_q))
mstore(0x1840, addmod(mload(0x17e0), mload(0x1820), f_q))
mstore(0x1860, addmod(mload(0x1840), mload(0xda0), f_q))
mstore(0x1880, addmod(mload(0x1860), mload(0x1740), f_q))
mstore(0x18a0, mulmod(mload(0xaa0), mload(0x1880), f_q))
mstore(0x18c0, addmod(1, sub(f_q, mload(0xe40)), f_q))
mstore(0x18e0, mulmod(mload(0x18c0), mload(0x1720), f_q))
mstore(0x1900, addmod(mload(0x18a0), mload(0x18e0), f_q))
mstore(0x1920, mulmod(mload(0xaa0), mload(0x1900), f_q))
mstore(0x1940, mulmod(mload(0xea0), mload(0xea0), f_q))
mstore(0x1960, addmod(mload(0x1940), sub(f_q, mload(0xea0)), f_q))
mstore(0x1980, mulmod(mload(0x1960), mload(0x1660), f_q))
mstore(0x19a0, addmod(mload(0x1920), mload(0x1980), f_q))
mstore(0x19c0, mulmod(mload(0xaa0), mload(0x19a0), f_q))
mstore(0x19e0, addmod(mload(0xea0), sub(f_q, mload(0xe80)), f_q))
mstore(0x1a00, mulmod(mload(0x19e0), mload(0x1720), f_q))
mstore(0x1a20, addmod(mload(0x19c0), mload(0x1a00), f_q))
mstore(0x1a40, mulmod(mload(0xaa0), mload(0x1a20), f_q))
mstore(0x1a60, addmod(1, sub(f_q, mload(0x1660)), f_q))
mstore(0x1a80, addmod(mload(0x1680), mload(0x16a0), f_q))
mstore(0x1aa0, addmod(mload(0x1a80), mload(0x16c0), f_q))
mstore(0x1ac0, addmod(mload(0x1aa0), mload(0x16e0), f_q))
mstore(0x1ae0, addmod(mload(0x1ac0), mload(0x1700), f_q))
mstore(0x1b00, addmod(mload(0x1a60), sub(f_q, mload(0x1ae0)), f_q))
mstore(0x1b20, mulmod(mload(0xde0), mload(0x860), f_q))
mstore(0x1b40, addmod(mload(0xcc0), mload(0x1b20), f_q))
mstore(0x1b60, addmod(mload(0x1b40), mload(0x8c0), f_q))
mstore(0x1b80, mulmod(mload(0xe00), mload(0x860), f_q))
mstore(0x1ba0, addmod(mload(0xce0), mload(0x1b80), f_q))
mstore(0x1bc0, addmod(mload(0x1ba0), mload(0x8c0), f_q))
mstore(0x1be0, mulmod(mload(0x1bc0), mload(0x1b60), f_q))
mstore(0x1c00, mulmod(mload(0x1be0), mload(0xe60), f_q))
mstore(0x1c20, mulmod(1, mload(0x860), f_q))
mstore(0x1c40, mulmod(mload(0xc80), mload(0x1c20), f_q))
mstore(0x1c60, addmod(mload(0xcc0), mload(0x1c40), f_q))
mstore(0x1c80, addmod(mload(0x1c60), mload(0x8c0), f_q))
mstore(0x1ca0, mulmod(3793952369011177517951424454785176000433849974408744014172535497121832470999, mload(0x860), f_q))
mstore(0x1cc0, mulmod(mload(0xc80), mload(0x1ca0), f_q))
mstore(0x1ce0, addmod(mload(0xce0), mload(0x1cc0), f_q))
mstore(0x1d00, addmod(mload(0x1ce0), mload(0x8c0), f_q))
mstore(0x1d20, mulmod(mload(0x1d00), mload(0x1c80), f_q))
mstore(0x1d40, mulmod(mload(0x1d20), mload(0xe40), f_q))
mstore(0x1d60, addmod(mload(0x1c00), sub(f_q, mload(0x1d40)), f_q))
mstore(0x1d80, mulmod(mload(0x1d60), mload(0x1b00), f_q))
mstore(0x1da0, addmod(mload(0x1a40), mload(0x1d80), f_q))
mstore(0x1dc0, mulmod(mload(0xaa0), mload(0x1da0), f_q))
mstore(0x1de0, mulmod(mload(0xe20), mload(0x860), f_q))
mstore(0x1e00, addmod(mload(0xd00), mload(0x1de0), f_q))
mstore(0x1e20, addmod(mload(0x1e00), mload(0x8c0), f_q))
mstore(0x1e40, mulmod(mload(0x1e20), mload(0xec0), f_q))
mstore(0x1e60, mulmod(29260201042546974833203213796440688721049425934417030432187341694347311461130, mload(0x860), f_q))
mstore(0x1e80, mulmod(mload(0xc80), mload(0x1e60), f_q))
mstore(0x1ea0, addmod(mload(0xd00), mload(0x1e80), f_q))
mstore(0x1ec0, addmod(mload(0x1ea0), mload(0x8c0), f_q))
mstore(0x1ee0, mulmod(mload(0x1ec0), mload(0xea0), f_q))
mstore(0x1f00, addmod(mload(0x1e40), sub(f_q, mload(0x1ee0)), f_q))
mstore(0x1f20, mulmod(mload(0x1f00), mload(0x1b00), f_q))
mstore(0x1f40, addmod(mload(0x1dc0), mload(0x1f20), f_q))
mstore(0x1f60, mulmod(mload(0x1280), mload(0x1280), f_q))
mstore(0x1f80, mulmod(mload(0x1f60), mload(0x1280), f_q))
mstore(0x1fa0, mulmod(1, mload(0x1280), f_q))
mstore(0x1fc0, mulmod(1, mload(0x1f60), f_q))
mstore(0x1fe0, mulmod(mload(0x1f40), mload(0x12a0), f_q))
mstore(0x2000, mulmod(mload(0x10e0), mload(0x10e0), f_q))
mstore(0x2020, mulmod(mload(0x2000), mload(0x10e0), f_q))
mstore(0x2040, mulmod(mload(0xf00), mload(0xf00), f_q))
mstore(0x2060, mulmod(mload(0x2040), mload(0xf00), f_q))
mstore(0x2080, mulmod(mload(0x2060), mload(0xf00), f_q))
mstore(0x20a0, mulmod(mload(0x2080), mload(0xf00), f_q))
mstore(0x20c0, mulmod(mload(0x20a0), mload(0xf00), f_q))
mstore(0x20e0, mulmod(mload(0x20c0), mload(0xf00), f_q))
mstore(0x2100, mulmod(mload(0x20e0), mload(0xf00), f_q))
mstore(0x2120, mulmod(mload(0x2100), mload(0xf00), f_q))
mstore(0x2140, mulmod(mload(0x2120), mload(0xf00), f_q))
mstore(0x2160, mulmod(mload(0x2140), mload(0xf00), f_q))
mstore(0x2180, mulmod(mload(0x2160), mload(0xf00), f_q))
mstore(0x21a0, mulmod(mload(0x2180), mload(0xf00), f_q))
mstore(0x21c0, mulmod(mload(0x21a0), mload(0xf00), f_q))
mstore(0x21e0, mulmod(mload(0x21c0), mload(0xf00), f_q))
mstore(0x2200, mulmod(sub(f_q, mload(0xcc0)), 1, f_q))
mstore(0x2220, mulmod(sub(f_q, mload(0xce0)), mload(0xf00), f_q))
mstore(0x2240, mulmod(1, mload(0xf00), f_q))
mstore(0x2260, addmod(mload(0x2200), mload(0x2220), f_q))
mstore(0x2280, mulmod(sub(f_q, mload(0xd00)), mload(0x2040), f_q))
mstore(0x22a0, mulmod(1, mload(0x2040), f_q))
mstore(0x22c0, addmod(mload(0x2260), mload(0x2280), f_q))
mstore(0x22e0, mulmod(sub(f_q, mload(0xe40)), mload(0x2060), f_q))
mstore(0x2300, mulmod(1, mload(0x2060), f_q))
mstore(0x2320, addmod(mload(0x22c0), mload(0x22e0), f_q))
mstore(0x2340, mulmod(sub(f_q, mload(0xea0)), mload(0x2080), f_q))
mstore(0x2360, mulmod(1, mload(0x2080), f_q))
mstore(0x2380, addmod(mload(0x2320), mload(0x2340), f_q))
mstore(0x23a0, mulmod(sub(f_q, mload(0xd20)), mload(0x20a0), f_q))
mstore(0x23c0, mulmod(1, mload(0x20a0), f_q))
mstore(0x23e0, addmod(mload(0x2380), mload(0x23a0), f_q))
mstore(0x2400, mulmod(sub(f_q, mload(0xd40)), mload(0x20c0), f_q))
mstore(0x2420, mulmod(1, mload(0x20c0), f_q))
mstore(0x2440, addmod(mload(0x23e0), mload(0x2400), f_q))
mstore(0x2460, mulmod(sub(f_q, mload(0xd60)), mload(0x20e0), f_q))
mstore(0x2480, mulmod(1, mload(0x20e0), f_q))
mstore(0x24a0, addmod(mload(0x2440), mload(0x2460), f_q))
mstore(0x24c0, mulmod(sub(f_q, mload(0xd80)), mload(0x2100), f_q))
mstore(0x24e0, mulmod(1, mload(0x2100), f_q))
mstore(0x2500, addmod(mload(0x24a0), mload(0x24c0), f_q))
mstore(0x2520, mulmod(sub(f_q, mload(0xda0)), mload(0x2120), f_q))
mstore(0x2540, mulmod(1, mload(0x2120), f_q))
mstore(0x2560, addmod(mload(0x2500), mload(0x2520), f_q))
mstore(0x2580, mulmod(sub(f_q, mload(0xde0)), mload(0x2140), f_q))
mstore(0x25a0, mulmod(1, mload(0x2140), f_q))
mstore(0x25c0, addmod(mload(0x2560), mload(0x2580), f_q))
mstore(0x25e0, mulmod(sub(f_q, mload(0xe00)), mload(0x2160), f_q))
mstore(0x2600, mulmod(1, mload(0x2160), f_q))
mstore(0x2620, addmod(mload(0x25c0), mload(0x25e0), f_q))
mstore(0x2640, mulmod(sub(f_q, mload(0xe20)), mload(0x2180), f_q))
mstore(0x2660, mulmod(1, mload(0x2180), f_q))
mstore(0x2680, addmod(mload(0x2620), mload(0x2640), f_q))
mstore(0x26a0, mulmod(sub(f_q, mload(0x1fe0)), mload(0x21a0), f_q))
mstore(0x26c0, mulmod(1, mload(0x21a0), f_q))
mstore(0x26e0, mulmod(mload(0x1fa0), mload(0x21a0), f_q))
mstore(0x2700, mulmod(mload(0x1fc0), mload(0x21a0), f_q))
mstore(0x2720, addmod(mload(0x2680), mload(0x26a0), f_q))
mstore(0x2740, mulmod(sub(f_q, mload(0xdc0)), mload(0x21c0), f_q))
mstore(0x2760, mulmod(1, mload(0x21c0), f_q))
mstore(0x2780, addmod(mload(0x2720), mload(0x2740), f_q))
mstore(0x27a0, mulmod(mload(0x2780), 1, f_q))
mstore(0x27c0, mulmod(mload(0x2240), 1, f_q))
mstore(0x27e0, mulmod(mload(0x22a0), 1, f_q))
mstore(0x2800, mulmod(mload(0x2300), 1, f_q))
mstore(0x2820, mulmod(mload(0x2360), 1, f_q))
mstore(0x2840, mulmod(mload(0x23c0), 1, f_q))
mstore(0x2860, mulmod(mload(0x2420), 1, f_q))
mstore(0x2880, mulmod(mload(0x2480), 1, f_q))
mstore(0x28a0, mulmod(mload(0x24e0), 1, f_q))
mstore(0x28c0, mulmod(mload(0x2540), 1, f_q))
mstore(0x28e0, mulmod(mload(0x25a0), 1, f_q))
mstore(0x2900, mulmod(mload(0x2600), 1, f_q))
mstore(0x2920, mulmod(mload(0x2660), 1, f_q))
mstore(0x2940, mulmod(mload(0x26c0), 1, f_q))
mstore(0x2960, mulmod(mload(0x26e0), 1, f_q))
mstore(0x2980, mulmod(mload(0x2700), 1, f_q))
mstore(0x29a0, mulmod(mload(0x2760), 1, f_q))
mstore(0x29c0, mulmod(sub(f_q, mload(0xe60)), 1, f_q))
mstore(0x29e0, mulmod(sub(f_q, mload(0xec0)), mload(0xf00), f_q))
mstore(0x2a00, addmod(mload(0x29c0), mload(0x29e0), f_q))
mstore(0x2a20, mulmod(mload(0x2a00), mload(0x10e0), f_q))
mstore(0x2a40, mulmod(1, mload(0x10e0), f_q))
mstore(0x2a60, mulmod(mload(0x2240), mload(0x10e0), f_q))
mstore(0x2a80, addmod(mload(0x27a0), mload(0x2a20), f_q))
mstore(0x2aa0, addmod(mload(0x2800), mload(0x2a40), f_q))
mstore(0x2ac0, addmod(mload(0x2820), mload(0x2a60), f_q))
mstore(0x2ae0, mulmod(sub(f_q, mload(0xe80)), 1, f_q))
mstore(0x2b00, mulmod(mload(0x2ae0), mload(0x2000), f_q))
mstore(0x2b20, mulmod(1, mload(0x2000), f_q))
mstore(0x2b40, addmod(mload(0x2a80), mload(0x2b00), f_q))
mstore(0x2b60, addmod(mload(0x2aa0), mload(0x2b20), f_q))
mstore(0x2b80, mulmod(1, mload(0xc80), f_q))
mstore(0x2ba0, mulmod(1, mload(0x2b80), f_q))
mstore(0x2bc0, mulmod(39033254847818212395286706435128746857159659164139250548781411570340225835782, mload(0xc80), f_q))
mstore(0x2be0, mulmod(mload(0x2a40), mload(0x2bc0), f_q))
mstore(0x2c00, mulmod(20090193668266119872620102064832883765253348140414125816117877893436209362462, mload(0xc80), f_q))
mstore(0x2c20, mulmod(mload(0x2b20), mload(0x2c00), f_q))

        {
            mstore(0x2c40, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f)
            mstore(0x2c60, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)
            mstore(0x2c80, 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4)
            mstore(0x2ca0, 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
        }
{
                    mstore(0x2cc0, mload(0x2c40))
mstore(0x2ce0, mload(0x2c60))
mstore(0x2d00, mload(0x2c80))
mstore(0x2d20, mload(0x2ca0))
                }
mstore(0x2d40, mload(0x2b40))
success := and(eq(staticcall(gas(), 0xc, 0x2cc0, 0xa0, 0x2cc0, 0x80), 1), success)
{
                    mstore(0x2d60, mload(0x2cc0))
mstore(0x2d80, mload(0x2ce0))
mstore(0x2da0, mload(0x2d00))
mstore(0x2dc0, mload(0x2d20))
                }
{
                    mstore(0x2de0, mload(0x660))
mstore(0x2e00, mload(0x680))
mstore(0x2e20, mload(0x6a0))
mstore(0x2e40, mload(0x6c0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x2d60, 0x100, 0x2d60, 0x80), 1), success)
{
                    mstore(0x2e60, mload(0x6e0))
mstore(0x2e80, mload(0x700))
mstore(0x2ea0, mload(0x720))
mstore(0x2ec0, mload(0x740))
                }
mstore(0x2ee0, mload(0x27c0))
success := and(eq(staticcall(gas(), 0xc, 0x2e60, 0xa0, 0x2e60, 0x80), 1), success)
{
                    mstore(0x2f00, mload(0x2d60))
mstore(0x2f20, mload(0x2d80))
mstore(0x2f40, mload(0x2da0))
mstore(0x2f60, mload(0x2dc0))
                }
{
                    mstore(0x2f80, mload(0x2e60))
mstore(0x2fa0, mload(0x2e80))
mstore(0x2fc0, mload(0x2ea0))
mstore(0x2fe0, mload(0x2ec0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x2f00, 0x100, 0x2f00, 0x80), 1), success)
{
                    mstore(0x3000, mload(0x760))
mstore(0x3020, mload(0x780))
mstore(0x3040, mload(0x7a0))
mstore(0x3060, mload(0x7c0))
                }
mstore(0x3080, mload(0x27e0))
success := and(eq(staticcall(gas(), 0xc, 0x3000, 0xa0, 0x3000, 0x80), 1), success)
{
                    mstore(0x30a0, mload(0x2f00))
mstore(0x30c0, mload(0x2f20))
mstore(0x30e0, mload(0x2f40))
mstore(0x3100, mload(0x2f60))
                }
{
                    mstore(0x3120, mload(0x3000))
mstore(0x3140, mload(0x3020))
mstore(0x3160, mload(0x3040))
mstore(0x3180, mload(0x3060))
                }
success := and(eq(staticcall(gas(), 0xb, 0x30a0, 0x100, 0x30a0, 0x80), 1), success)
{
                    mstore(0x31a0, mload(0x900))
mstore(0x31c0, mload(0x920))
mstore(0x31e0, mload(0x940))
mstore(0x3200, mload(0x960))
                }
mstore(0x3220, mload(0x2b60))
success := and(eq(staticcall(gas(), 0xc, 0x31a0, 0xa0, 0x31a0, 0x80), 1), success)
{
                    mstore(0x3240, mload(0x30a0))
mstore(0x3260, mload(0x30c0))
mstore(0x3280, mload(0x30e0))
mstore(0x32a0, mload(0x3100))
                }
{
                    mstore(0x32c0, mload(0x31a0))
mstore(0x32e0, mload(0x31c0))
mstore(0x3300, mload(0x31e0))
mstore(0x3320, mload(0x3200))
                }
success := and(eq(staticcall(gas(), 0xb, 0x3240, 0x100, 0x3240, 0x80), 1), success)
{
                    mstore(0x3340, mload(0x980))
mstore(0x3360, mload(0x9a0))
mstore(0x3380, mload(0x9c0))
mstore(0x33a0, mload(0x9e0))
                }
mstore(0x33c0, mload(0x2ac0))
success := and(eq(staticcall(gas(), 0xc, 0x3340, 0xa0, 0x3340, 0x80), 1), success)
{
                    mstore(0x33e0, mload(0x3240))
mstore(0x3400, mload(0x3260))
mstore(0x3420, mload(0x3280))
mstore(0x3440, mload(0x32a0))
                }
{
                    mstore(0x3460, mload(0x3340))
mstore(0x3480, mload(0x3360))
mstore(0x34a0, mload(0x3380))
mstore(0x34c0, mload(0x33a0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x33e0, 0x100, 0x33e0, 0x80), 1), success)
{
                    mstore(0x34e0, mload(0x220))
mstore(0x3500, mload(0x240))
mstore(0x3520, mload(0x260))
mstore(0x3540, mload(0x280))
                }
mstore(0x3560, mload(0x2840))
success := and(eq(staticcall(gas(), 0xc, 0x34e0, 0xa0, 0x34e0, 0x80), 1), success)
{
                    mstore(0x3580, mload(0x33e0))
mstore(0x35a0, mload(0x3400))
mstore(0x35c0, mload(0x3420))
mstore(0x35e0, mload(0x3440))
                }
{
                    mstore(0x3600, mload(0x34e0))
mstore(0x3620, mload(0x3500))
mstore(0x3640, mload(0x3520))
mstore(0x3660, mload(0x3540))
                }
success := and(eq(staticcall(gas(), 0xb, 0x3580, 0x100, 0x3580, 0x80), 1), success)
{
                    mstore(0x3680, mload(0x2a0))
mstore(0x36a0, mload(0x2c0))
mstore(0x36c0, mload(0x2e0))
mstore(0x36e0, mload(0x300))
                }
mstore(0x3700, mload(0x2860))
success := and(eq(staticcall(gas(), 0xc, 0x3680, 0xa0, 0x3680, 0x80), 1), success)
{
                    mstore(0x3720, mload(0x3580))
mstore(0x3740, mload(0x35a0))
mstore(0x3760, mload(0x35c0))
mstore(0x3780, mload(0x35e0))
                }
{
                    mstore(0x37a0, mload(0x3680))
mstore(0x37c0, mload(0x36a0))
mstore(0x37e0, mload(0x36c0))
mstore(0x3800, mload(0x36e0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x3720, 0x100, 0x3720, 0x80), 1), success)
{
                    mstore(0x3820, mload(0x320))
mstore(0x3840, mload(0x340))
mstore(0x3860, mload(0x360))
mstore(0x3880, mload(0x380))
                }
mstore(0x38a0, mload(0x2880))
success := and(eq(staticcall(gas(), 0xc, 0x3820, 0xa0, 0x3820, 0x80), 1), success)
{
                    mstore(0x38c0, mload(0x3720))
mstore(0x38e0, mload(0x3740))
mstore(0x3900, mload(0x3760))
mstore(0x3920, mload(0x3780))
                }
{
                    mstore(0x3940, mload(0x3820))
mstore(0x3960, mload(0x3840))
mstore(0x3980, mload(0x3860))
mstore(0x39a0, mload(0x3880))
                }
success := and(eq(staticcall(gas(), 0xb, 0x38c0, 0x100, 0x38c0, 0x80), 1), success)
{
                    mstore(0x39c0, mload(0x3a0))
mstore(0x39e0, mload(0x3c0))
mstore(0x3a00, mload(0x3e0))
mstore(0x3a20, mload(0x400))
                }
mstore(0x3a40, mload(0x28a0))
success := and(eq(staticcall(gas(), 0xc, 0x39c0, 0xa0, 0x39c0, 0x80), 1), success)
{
                    mstore(0x3a60, mload(0x38c0))
mstore(0x3a80, mload(0x38e0))
mstore(0x3aa0, mload(0x3900))
mstore(0x3ac0, mload(0x3920))
                }
{
                    mstore(0x3ae0, mload(0x39c0))
mstore(0x3b00, mload(0x39e0))
mstore(0x3b20, mload(0x3a00))
mstore(0x3b40, mload(0x3a20))
                }
success := and(eq(staticcall(gas(), 0xb, 0x3a60, 0x100, 0x3a60, 0x80), 1), success)
{
                    mstore(0x3b60, mload(0x420))
mstore(0x3b80, mload(0x440))
mstore(0x3ba0, mload(0x460))
mstore(0x3bc0, mload(0x480))
                }
mstore(0x3be0, mload(0x28c0))
success := and(eq(staticcall(gas(), 0xc, 0x3b60, 0xa0, 0x3b60, 0x80), 1), success)
{
                    mstore(0x3c00, mload(0x3a60))
mstore(0x3c20, mload(0x3a80))
mstore(0x3c40, mload(0x3aa0))
mstore(0x3c60, mload(0x3ac0))
                }
{
                    mstore(0x3c80, mload(0x3b60))
mstore(0x3ca0, mload(0x3b80))
mstore(0x3cc0, mload(0x3ba0))
mstore(0x3ce0, mload(0x3bc0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x3c00, 0x100, 0x3c00, 0x80), 1), success)
{
                    mstore(0x3d00, mload(0x4a0))
mstore(0x3d20, mload(0x4c0))
mstore(0x3d40, mload(0x4e0))
mstore(0x3d60, mload(0x500))
                }
mstore(0x3d80, mload(0x28e0))
success := and(eq(staticcall(gas(), 0xc, 0x3d00, 0xa0, 0x3d00, 0x80), 1), success)
{
                    mstore(0x3da0, mload(0x3c00))
mstore(0x3dc0, mload(0x3c20))
mstore(0x3de0, mload(0x3c40))
mstore(0x3e00, mload(0x3c60))
                }
{
                    mstore(0x3e20, mload(0x3d00))
mstore(0x3e40, mload(0x3d20))
mstore(0x3e60, mload(0x3d40))
mstore(0x3e80, mload(0x3d60))
                }
success := and(eq(staticcall(gas(), 0xb, 0x3da0, 0x100, 0x3da0, 0x80), 1), success)
{
                    mstore(0x3ea0, mload(0x520))
mstore(0x3ec0, mload(0x540))
mstore(0x3ee0, mload(0x560))
mstore(0x3f00, mload(0x580))
                }
mstore(0x3f20, mload(0x2900))
success := and(eq(staticcall(gas(), 0xc, 0x3ea0, 0xa0, 0x3ea0, 0x80), 1), success)
{
                    mstore(0x3f40, mload(0x3da0))
mstore(0x3f60, mload(0x3dc0))
mstore(0x3f80, mload(0x3de0))
mstore(0x3fa0, mload(0x3e00))
                }
{
                    mstore(0x3fc0, mload(0x3ea0))
mstore(0x3fe0, mload(0x3ec0))
mstore(0x4000, mload(0x3ee0))
mstore(0x4020, mload(0x3f00))
                }
success := and(eq(staticcall(gas(), 0xb, 0x3f40, 0x100, 0x3f40, 0x80), 1), success)
{
                    mstore(0x4040, mload(0x5a0))
mstore(0x4060, mload(0x5c0))
mstore(0x4080, mload(0x5e0))
mstore(0x40a0, mload(0x600))
                }
mstore(0x40c0, mload(0x2920))
success := and(eq(staticcall(gas(), 0xc, 0x4040, 0xa0, 0x4040, 0x80), 1), success)
{
                    mstore(0x40e0, mload(0x3f40))
mstore(0x4100, mload(0x3f60))
mstore(0x4120, mload(0x3f80))
mstore(0x4140, mload(0x3fa0))
                }
{
                    mstore(0x4160, mload(0x4040))
mstore(0x4180, mload(0x4060))
mstore(0x41a0, mload(0x4080))
mstore(0x41c0, mload(0x40a0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x40e0, 0x100, 0x40e0, 0x80), 1), success)
{
                    mstore(0x41e0, mload(0xae0))
mstore(0x4200, mload(0xb00))
mstore(0x4220, mload(0xb20))
mstore(0x4240, mload(0xb40))
                }
mstore(0x4260, mload(0x2940))
success := and(eq(staticcall(gas(), 0xc, 0x41e0, 0xa0, 0x41e0, 0x80), 1), success)
{
                    mstore(0x4280, mload(0x40e0))
mstore(0x42a0, mload(0x4100))
mstore(0x42c0, mload(0x4120))
mstore(0x42e0, mload(0x4140))
                }
{
                    mstore(0x4300, mload(0x41e0))
mstore(0x4320, mload(0x4200))
mstore(0x4340, mload(0x4220))
mstore(0x4360, mload(0x4240))
                }
success := and(eq(staticcall(gas(), 0xb, 0x4280, 0x100, 0x4280, 0x80), 1), success)
{
                    mstore(0x4380, mload(0xb60))
mstore(0x43a0, mload(0xb80))
mstore(0x43c0, mload(0xba0))
mstore(0x43e0, mload(0xbc0))
                }
mstore(0x4400, mload(0x2960))
success := and(eq(staticcall(gas(), 0xc, 0x4380, 0xa0, 0x4380, 0x80), 1), success)
{
                    mstore(0x4420, mload(0x4280))
mstore(0x4440, mload(0x42a0))
mstore(0x4460, mload(0x42c0))
mstore(0x4480, mload(0x42e0))
                }
{
                    mstore(0x44a0, mload(0x4380))
mstore(0x44c0, mload(0x43a0))
mstore(0x44e0, mload(0x43c0))
mstore(0x4500, mload(0x43e0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x4420, 0x100, 0x4420, 0x80), 1), success)
{
                    mstore(0x4520, mload(0xbe0))
mstore(0x4540, mload(0xc00))
mstore(0x4560, mload(0xc20))
mstore(0x4580, mload(0xc40))
                }
mstore(0x45a0, mload(0x2980))
success := and(eq(staticcall(gas(), 0xc, 0x4520, 0xa0, 0x4520, 0x80), 1), success)
{
                    mstore(0x45c0, mload(0x4420))
mstore(0x45e0, mload(0x4440))
mstore(0x4600, mload(0x4460))
mstore(0x4620, mload(0x4480))
                }
{
                    mstore(0x4640, mload(0x4520))
mstore(0x4660, mload(0x4540))
mstore(0x4680, mload(0x4560))
mstore(0x46a0, mload(0x4580))
                }
success := and(eq(staticcall(gas(), 0xb, 0x45c0, 0x100, 0x45c0, 0x80), 1), success)
{
                    mstore(0x46c0, mload(0xa00))
mstore(0x46e0, mload(0xa20))
mstore(0x4700, mload(0xa40))
mstore(0x4720, mload(0xa60))
                }
mstore(0x4740, mload(0x29a0))
success := and(eq(staticcall(gas(), 0xc, 0x46c0, 0xa0, 0x46c0, 0x80), 1), success)
{
                    mstore(0x4760, mload(0x45c0))
mstore(0x4780, mload(0x45e0))
mstore(0x47a0, mload(0x4600))
mstore(0x47c0, mload(0x4620))
                }
{
                    mstore(0x47e0, mload(0x46c0))
mstore(0x4800, mload(0x46e0))
mstore(0x4820, mload(0x4700))
mstore(0x4840, mload(0x4720))
                }
success := and(eq(staticcall(gas(), 0xb, 0x4760, 0x100, 0x4760, 0x80), 1), success)
{
                    mstore(0x4860, mload(0xf40))
mstore(0x4880, mload(0xf60))
mstore(0x48a0, mload(0xf80))
mstore(0x48c0, mload(0xfa0))
                }
mstore(0x48e0, mload(0x2ba0))
success := and(eq(staticcall(gas(), 0xc, 0x4860, 0xa0, 0x4860, 0x80), 1), success)
{
                    mstore(0x4900, mload(0x4760))
mstore(0x4920, mload(0x4780))
mstore(0x4940, mload(0x47a0))
mstore(0x4960, mload(0x47c0))
                }
{
                    mstore(0x4980, mload(0x4860))
mstore(0x49a0, mload(0x4880))
mstore(0x49c0, mload(0x48a0))
mstore(0x49e0, mload(0x48c0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x4900, 0x100, 0x4900, 0x80), 1), success)
{
                    mstore(0x4a00, mload(0xfc0))
mstore(0x4a20, mload(0xfe0))
mstore(0x4a40, mload(0x1000))
mstore(0x4a60, mload(0x1020))
                }
mstore(0x4a80, mload(0x2be0))
success := and(eq(staticcall(gas(), 0xc, 0x4a00, 0xa0, 0x4a00, 0x80), 1), success)
{
                    mstore(0x4aa0, mload(0x4900))
mstore(0x4ac0, mload(0x4920))
mstore(0x4ae0, mload(0x4940))
mstore(0x4b00, mload(0x4960))
                }
{
                    mstore(0x4b20, mload(0x4a00))
mstore(0x4b40, mload(0x4a20))
mstore(0x4b60, mload(0x4a40))
mstore(0x4b80, mload(0x4a60))
                }
success := and(eq(staticcall(gas(), 0xb, 0x4aa0, 0x100, 0x4aa0, 0x80), 1), success)
{
                    mstore(0x4ba0, mload(0x1040))
mstore(0x4bc0, mload(0x1060))
mstore(0x4be0, mload(0x1080))
mstore(0x4c00, mload(0x10a0))
                }
mstore(0x4c20, mload(0x2c20))
success := and(eq(staticcall(gas(), 0xc, 0x4ba0, 0xa0, 0x4ba0, 0x80), 1), success)
{
                    mstore(0x4c40, mload(0x4aa0))
mstore(0x4c60, mload(0x4ac0))
mstore(0x4c80, mload(0x4ae0))
mstore(0x4ca0, mload(0x4b00))
                }
{
                    mstore(0x4cc0, mload(0x4ba0))
mstore(0x4ce0, mload(0x4bc0))
mstore(0x4d00, mload(0x4be0))
mstore(0x4d20, mload(0x4c00))
                }
success := and(eq(staticcall(gas(), 0xb, 0x4c40, 0x100, 0x4c40, 0x80), 1), success)

        {
            mstore(0x4d40, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f)
            mstore(0x4d60, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)
            mstore(0x4d80, 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4)
            mstore(0x4da0, 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
        }
{
                    mstore(0x4dc0, mload(0xfc0))
mstore(0x4de0, mload(0xfe0))
mstore(0x4e00, mload(0x1000))
mstore(0x4e20, mload(0x1020))
                }
mstore(0x4e40, mload(0x2a40))
success := and(eq(staticcall(gas(), 0xc, 0x4dc0, 0xa0, 0x4dc0, 0x80), 1), success)
{
                    mstore(0x4e60, mload(0xf40))
mstore(0x4e80, mload(0xf60))
mstore(0x4ea0, mload(0xf80))
mstore(0x4ec0, mload(0xfa0))
                }
{
                    mstore(0x4ee0, mload(0x4dc0))
mstore(0x4f00, mload(0x4de0))
mstore(0x4f20, mload(0x4e00))
mstore(0x4f40, mload(0x4e20))
                }
success := and(eq(staticcall(gas(), 0xb, 0x4e60, 0x100, 0x4e60, 0x80), 1), success)
{
                    mstore(0x4f60, mload(0x1040))
mstore(0x4f80, mload(0x1060))
mstore(0x4fa0, mload(0x1080))
mstore(0x4fc0, mload(0x10a0))
                }
mstore(0x4fe0, mload(0x2b20))
success := and(eq(staticcall(gas(), 0xc, 0x4f60, 0xa0, 0x4f60, 0x80), 1), success)
{
                    mstore(0x5000, mload(0x4e60))
mstore(0x5020, mload(0x4e80))
mstore(0x5040, mload(0x4ea0))
mstore(0x5060, mload(0x4ec0))
                }
{
                    mstore(0x5080, mload(0x4f60))
mstore(0x50a0, mload(0x4f80))
mstore(0x50c0, mload(0x4fa0))
mstore(0x50e0, mload(0x4fc0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x5000, 0x100, 0x5000, 0x80), 1), success)
{
                    mstore(0x5100, mload(0x4c40))
mstore(0x5120, mload(0x4c60))
mstore(0x5140, mload(0x4c80))
mstore(0x5160, mload(0x4ca0))
                }
mstore(0x5180, 0x00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051)
mstore(0x51a0, 0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8)
mstore(0x51c0, 0x0000000000000000000000000000000013e02b6052719f607dacd3a088274f65)
mstore(0x51e0, 0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e)
mstore(0x5200, 0x000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a)
mstore(0x5220, 0xadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801)
mstore(0x5240, 0x000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99)
mstore(0x5260, 0xcb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be)
{
                    mstore(0x5280, mload(0x5000))
mstore(0x52a0, mload(0x5020))
mstore(0x52c0, mload(0x5040))
mstore(0x52e0, mload(0x5060))
                }
mstore(0x5300, 0x0000000000000000000000000000000019d5a75bdb11ecd2ce4f350406acfb92)
mstore(0x5320, 0xf727d71020f64a9fe5b4d67aeff0eb08d162861d27a14416173836fe4bf1a301)
mstore(0x5340, 0x0000000000000000000000000000000018d7902500b6a77929110dab107d243a)
mstore(0x5360, 0xbf0c555515295b8ee76139736671121b44805fa002ed76e452b6898acc085ad4)
mstore(0x5380, 0x000000000000000000000000000000000dcc2476aa087c1d4128de32f0536adc)
mstore(0x53a0, 0x68ac56f27cec75c732c17574ba2a7542336371388dee566442004a79b6e37f59)
mstore(0x53c0, 0x0000000000000000000000000000000001739420d824b582399ab9f4fff4a8a0)
mstore(0x53e0, 0x0c23c94351e23921416fda8e0022b590d37907f856a878c7a521d4973d684c33)
success := and(eq(staticcall(gas(), 0xf, 0x5100, 0x300, 0x5100, 0x20), 1), success)
success := and(eq(mload(0x5100), 1), success)

            // Revert if anything fails
            if iszero(success) { revert(0, 0) }

            // Return empty bytes on success
            return(0, 0)

        }
    }
}
        