
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
            mstore(0x220, 0x00000000000000000000000000000000041b3b38e38b31b42aee4db96d806074)
mstore(0x240, 0xf3fd8755cc47af9e83f581c73e0c63cfe079446e3ac3ea7482f6371a27b4d3dc)
mstore(0x260, 0x000000000000000000000000000000000c8a4bb69ac32ed788b1fd39f334ece8)
mstore(0x280, 0xd18081ff9e6c2b0a34ae60ee1b8a32225f675a9e56d0ddee36d35c80404db587)
mstore(0x2a0, 0x0000000000000000000000000000000010ac035be7f5fd5fbec9bfa5334305a7)
mstore(0x2c0, 0x122ae1a1bd9d8d44485165339b252773c321e8a070c5a93a6953d9aca3f5b570)
mstore(0x2e0, 0x000000000000000000000000000000000ded1a455eef3f8f2f3ce2210dc0cf29)
mstore(0x300, 0x26ea631bde581814f8697ddbdbaad32bf48373794a30434e1f8ed1d303c0f519)
mstore(0x320, 0x000000000000000000000000000000000c3ede3559a1ab90632474158c531ab5)
mstore(0x340, 0xfb1c4af516743acb86052a29dbe94f201a8626443c0d06f60b4dfb88155590b0)
mstore(0x360, 0x000000000000000000000000000000000b92266037e281ab90f1a4b47fe96dcf)
mstore(0x380, 0x9b8fdfe1996ab651e4eb9dc649a77833b5776546f78197a45495547961a5c5e2)
mstore(0x3a0, 0x000000000000000000000000000000001532aead68ae07a439c65e161de72fad)
mstore(0x3c0, 0x0dde016f259200c304df91625755623c16456175b1eab113bd3c83a0895f4904)
mstore(0x3e0, 0x000000000000000000000000000000000e1d3b3ea57c9a5dcded0927a2056225)
mstore(0x400, 0x5dce2fe15a4de6744ee825b05dd6c1bba97c773c9a53b7a7feb0836aed867f70)
mstore(0x420, 0x00000000000000000000000000000000101e99c1f40f53fb481ba6a3427ac6ee)
mstore(0x440, 0x89385aa378a3ed656445498190a5f6e79edde122bf927d46e764b5ccd866ac5e)
mstore(0x460, 0x00000000000000000000000000000000099d42240de2fb056d224209a7adf76c)
mstore(0x480, 0x6d4b1ad40c9222cda4561f8e44ba358e06a8a4a59ab1128525bb05ea3719891e)
mstore(0x4a0, 0x0000000000000000000000000000000007c3ec8c1d004c438817ffec17a7d399)
mstore(0x4c0, 0xe4f414a28b5fcc8071a29d6e11847e3e7582e614a1d8ff1299ef2fa375c6f2c5)
mstore(0x4e0, 0x000000000000000000000000000000001162067f31d484843144e92f2397b48a)
mstore(0x500, 0x2efc079a2a31521dd41c2c8ef13613375fb961a948ee4259d395da9ad98f1867)
mstore(0x520, 0x0000000000000000000000000000000008263739e8c19f10c1de91f241717698)
mstore(0x540, 0xec2171184a3389bc96dd91c4e7021fd9c929b253553df9ff1d4774807ba48f5d)
mstore(0x560, 0x0000000000000000000000000000000006280ab78e49807ee0776a85cb29887a)
mstore(0x580, 0xd7ae251df1a194143f33e7a32abba74c4df92e97563605a79878c2d377d236f9)
mstore(0x5a0, 0x0000000000000000000000000000000004f9cec1be5a44374426246c8e4af4fe)
mstore(0x5c0, 0x775bc89b0e77c6f6d5feebbe0215de767c07f70a26bca3039d96ca131650d12f)
mstore(0x5e0, 0x00000000000000000000000000000000153059eb1f9baad4d3edfae747b193c3)
mstore(0x600, 0xb977387b7de1d6c24670111d7dd168bd5889086f21b1b33669309eb11c588c1f)
mstore(0x620, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x640, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x660, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x680, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x6a0, 0x0000000000000000000000000000000017cd99443ec64982cacf37c2e00df7d9)
mstore(0x6c0, 0xef9349adbe8bc8857d788b2c5e938f3bfb1c142d1bc6a5f3d10229ff6113558f)
mstore(0x6e0, 0x00000000000000000000000000000000165824c379719a179e87e46632051309)
mstore(0x700, 0xa4803288130f5c2e6c13b02ab1237eb7f73df471297c66dcb8d8daee83d60cb6)
mstore(0x720, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x740, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x760, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x780, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x7a0, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x7c0, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x7e0, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x800, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x820, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x840, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x860, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x880, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x8a0, 0x0000000000000000000000000000000001ea02a01f71c8d38d3432139ee20af1)
mstore(0x8c0, 0xaac9259303b48e4a29e0e8545447eee8720cb8dae4cbdaacc6a01beebb0d2b35)
mstore(0x8e0, 0x000000000000000000000000000000001058b7931476e829786f4fd97ce61995)
mstore(0x900, 0xb2d52640eb379ea610340f1cb6212e69f4d702b2c12080413ce5c1122079ecb6)
mstore(0x920, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x940, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x960, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x980, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x9a0, 0x00000000000000000000000000000000075b506f6239b6376ee4baa8a57d3b3e)
mstore(0x9c0, 0x505f27cc8c984b53a630903a8ced60cc71f55de6de2195f727ae1669488438f0)
mstore(0x9e0, 0x0000000000000000000000000000000010de43b027029e746840e23c715e5ffb)
mstore(0xa00, 0x385d130a1c5dc73d7c1ee6696dc1a468b892538de3b66e3481ca6a9f4ae477dd)
mstore(0xa20, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0xa40, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0xa60, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0xa80, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0xaa0, 0x00000000000000000000000000000000033b48b104c9ccb3c80e6cae2d91d45e)
mstore(0xac0, 0x14446ee194bab644c5f8064ee542371d6e162c69057dd0a1694ca8bda2bbe5aa)
mstore(0xae0, 0x00000000000000000000000000000000150734247e95b726adf2ea102f11462e)
mstore(0xb00, 0x664fa43d20860959b465072841e573819da118644d6738e58ac41bb1ba00e766)
mstore(0xb20, 0x0000000000000000000000000000000009d02736a674c275efe35e6c0ba34ab2)
mstore(0xb40, 0x32259f7280bbc11027c2fedf2df5b8e912a21d470516e5967ab339724411236f)
mstore(0xb60, 0x000000000000000000000000000000000282bde118b07c897970cafadff71bd6)
mstore(0xb80, 0x637822f5a494dacca0d1c2d1b9e4154e5c37dbbaf207aef0e9e5bad87fa7b069)
mstore(0xba0, 0x0000000000000000000000000000000004031172eda8f96609e97ac46ebef039)
mstore(0xbc0, 0xff88ce8470298fc1f49198bcaf4b5c473101fcd1a89acba3c38341b0fb9697eb)
mstore(0xbe0, 0x0000000000000000000000000000000000e44acc9f3b87c6843bb08691bc7eb2)
mstore(0xc00, 0x5db2cc2bf5966da3bc461c1186337bb894ccd9483c56599a0aa9e953eb464dc9)
mstore(0xc20, 0x0000000000000000000000000000000015af7bc0200332a3ac3de5406a02768d)
mstore(0xc40, 0x39a7e244ff1d75b912efcc8fc22ee849c96dfb648ace6b8389c64e1d2765651d)
mstore(0xc60, 0x0000000000000000000000000000000016b05f0b594434ee5bb050d40e5b82b0)
mstore(0xc80, 0x16b5d9d1d950e7c238a62349eae1a270aa331cb5e2b46d50ea37059287db62ac)
mstore(0xca0, 0x000000000000000000000000000000000804d35b9a1bbad92b5964714f5590dd)
mstore(0xcc0, 0xed3aefdeb3eac498ac28fb500aabd7e32000fb3b2d57f98030c078cb24b46042)
mstore(0xce0, 0x00000000000000000000000000000000001703264f0bc926e997efbe4c9521f0)
mstore(0xd00, 0x359e9c9d70598694d14ebd45a223930cd05712a6892933a6fef380e9d34721fc)
mstore(0xd20, 0x0000000000000000000000000000000000031c6a392be679d3ea4af2ab154bdb)
mstore(0xd40, 0xc5d2dae09a9a70e04774dc8c7401dfa04247dd2d635fdf90bae4cce87f024f37)
mstore(0xd60, 0x0000000000000000000000000000000018eaa12b980a91ddc2c3551a22a6c132)
mstore(0xd80, 0x21d42e4d187f72a370cc204e5ebec780291f80e8fda995b5a7dd35010a156e4d)
mstore(0xda0, 0x000000000000000000000000000000000bb34630cdb822b5a16b2c082601d6a3)
mstore(0xdc0, 0x4d07e8a3c5cde392199490593d8087c833e447a5c0cd5e80173a7d6b311a7ff4)
mstore(0xde0, 0x0000000000000000000000000000000004aa468ce0c8743f96ae6eb7d49374c9)
mstore(0xe00, 0xd01dc61edf641dc1cfcfd6a490aab008936c8bf7a5752883ad053449c5bdd368)
mstore(0xe20, 0x00000000000000000000000000000000123c5910d99dc7b5c66eb9d4b2dc74e0)
mstore(0xe40, 0xc0326726eade6c414c70fac92e4a4feea9fe9044b3fe8c71e98ff8125e5bfad5)
mstore(0xe60, 0x0000000000000000000000000000000004e5c5b78998a9144462b65fb9b13bc1)
mstore(0xe80, 0x367fb70b42afe0290bff7acecfe6b51ae14201173563dca0231b57b1049906b7)
mstore(0xea0, 0x00000000000000000000000000000000057b772f8cb125acfb37ee03d55ea12d)
mstore(0xec0, 0x11ceb8ae106e8dd84b35b3d1482c35613b0d3f712475ad568f7a72554c6fc995)
mstore(0xee0, 0x0000000000000000000000000000000001ec0f05e2de1fb4c9677505f0b17d3d)
mstore(0xf00, 0xc6c524f4af3e4dc8b906185d6a2f603b9b16b13c9a85acd866cc8639f2e8dde1)
mstore(0xf20, 0x0000000000000000000000000000000007fe505e2f103048bad3b173b6456d6a)
mstore(0xf40, 0x1392b30938e2b265ed7f286d5897b5876765887583bd955b50ea1fc9bf02b079)
mstore(0xf60, 0x000000000000000000000000000000001486a82a1f10bbfdf6e131d50df86fd0)
mstore(0xf80, 0x159abe7a95704f721a99591c0b7198950a44b3058cb498015a2ee2a404038117)
mstore(0xfc0, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0xfe0, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x1000, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x1020, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x1040, mod(calldataload(0x0), f_q))
mstore(0x1060, 33824681912417750056784288193663605962236179847225101020381911378169861020144)
{
                            mstore(0x1080, mload(0xfc0))
mstore(0x10a0, mload(0xfe0))
mstore(0x10c0, mload(0x1000))
mstore(0x10e0, mload(0x1020))
                        }
mstore(0x1100, 1)
mstore(0x1120, mload(0x1040))

        {
            let flag := byte(0, calldataload(0x20))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1140, 0)
            mstore(0x1160, 0)
            mstore(0x1180, 0)
            mstore(0x11a0, 0)
            calldatacopy(0x1150, 0x21, 0x30)

            let x_hi := mload(0x1140)
            let x_lo := mload(0x1160)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1180, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1180))
                mstore(0x100, mload(0x11a0))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x11a0)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1180)), borrow)
                    mstore(0x1180, neg_y_hi)
                    mstore(0x11a0, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x51))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x11c0, 0)
            mstore(0x11e0, 0)
            mstore(0x1200, 0)
            mstore(0x1220, 0)
            calldatacopy(0x11d0, 0x52, 0x30)

            let x_hi := mload(0x11c0)
            let x_lo := mload(0x11e0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1200, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1200))
                mstore(0x100, mload(0x1220))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1220)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1200)), borrow)
                    mstore(0x1200, neg_y_hi)
                    mstore(0x1220, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x82))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1240, 0)
            mstore(0x1260, 0)
            mstore(0x1280, 0)
            mstore(0x12a0, 0)
            calldatacopy(0x1250, 0x83, 0x30)

            let x_hi := mload(0x1240)
            let x_lo := mload(0x1260)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1280, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1280))
                mstore(0x100, mload(0x12a0))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x12a0)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1280)), borrow)
                    mstore(0x1280, neg_y_hi)
                    mstore(0x12a0, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0xb3))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x12c0, 0)
            mstore(0x12e0, 0)
            mstore(0x1300, 0)
            mstore(0x1320, 0)
            calldatacopy(0x12d0, 0xb4, 0x30)

            let x_hi := mload(0x12c0)
            let x_lo := mload(0x12e0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1300, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1300))
                mstore(0x100, mload(0x1320))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1320)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1300)), borrow)
                    mstore(0x1300, neg_y_hi)
                    mstore(0x1320, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0xe4))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1340, 0)
            mstore(0x1360, 0)
            mstore(0x1380, 0)
            mstore(0x13a0, 0)
            calldatacopy(0x1350, 0xe5, 0x30)

            let x_hi := mload(0x1340)
            let x_lo := mload(0x1360)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1380, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1380))
                mstore(0x100, mload(0x13a0))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x13a0)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1380)), borrow)
                    mstore(0x1380, neg_y_hi)
                    mstore(0x13a0, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x115))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x13c0, 0)
            mstore(0x13e0, 0)
            mstore(0x1400, 0)
            mstore(0x1420, 0)
            calldatacopy(0x13d0, 0x116, 0x30)

            let x_hi := mload(0x13c0)
            let x_lo := mload(0x13e0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1400, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1400))
                mstore(0x100, mload(0x1420))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1420)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1400)), borrow)
                    mstore(0x1400, neg_y_hi)
                    mstore(0x1420, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x146))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1440, 0)
            mstore(0x1460, 0)
            mstore(0x1480, 0)
            mstore(0x14a0, 0)
            calldatacopy(0x1450, 0x147, 0x30)

            let x_hi := mload(0x1440)
            let x_lo := mload(0x1460)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1480, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1480))
                mstore(0x100, mload(0x14a0))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x14a0)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1480)), borrow)
                    mstore(0x1480, neg_y_hi)
                    mstore(0x14a0, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x177))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x14c0, 0)
            mstore(0x14e0, 0)
            mstore(0x1500, 0)
            mstore(0x1520, 0)
            calldatacopy(0x14d0, 0x178, 0x30)

            let x_hi := mload(0x14c0)
            let x_lo := mload(0x14e0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1500, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1500))
                mstore(0x100, mload(0x1520))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1520)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1500)), borrow)
                    mstore(0x1500, neg_y_hi)
                    mstore(0x1520, neg_y_lo)
                }
            }
        }
mstore(0x1540, keccak256(0x1060, 1248))
mstore(0x1560, mod(mload(0x1540), f_q))
mstore(0x1580, mload(0x1540))

        {
            let flag := byte(0, calldataload(0x1a8))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x15a0, 0)
            mstore(0x15c0, 0)
            mstore(0x15e0, 0)
            mstore(0x1600, 0)
            calldatacopy(0x15b0, 0x1a9, 0x30)

            let x_hi := mload(0x15a0)
            let x_lo := mload(0x15c0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x15e0, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x15e0))
                mstore(0x100, mload(0x1600))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1600)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x15e0)), borrow)
                    mstore(0x15e0, neg_y_hi)
                    mstore(0x1600, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x1d9))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1620, 0)
            mstore(0x1640, 0)
            mstore(0x1660, 0)
            mstore(0x1680, 0)
            calldatacopy(0x1630, 0x1da, 0x30)

            let x_hi := mload(0x1620)
            let x_lo := mload(0x1640)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1660, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1660))
                mstore(0x100, mload(0x1680))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1680)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1660)), borrow)
                    mstore(0x1660, neg_y_hi)
                    mstore(0x1680, neg_y_lo)
                }
            }
        }
mstore(0x16a0, keccak256(0x1580, 288))
mstore(0x16c0, mod(mload(0x16a0), f_q))
mstore(0x16e0, mload(0x16a0))
mstore8(0x1700, 1)
mstore(0x1700, keccak256(0x16e0, 33))
mstore(0x1720, mod(mload(0x1700), f_q))
mstore(0x1740, mload(0x1700))

        {
            let flag := byte(0, calldataload(0x20a))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1760, 0)
            mstore(0x1780, 0)
            mstore(0x17a0, 0)
            mstore(0x17c0, 0)
            calldatacopy(0x1770, 0x20b, 0x30)

            let x_hi := mload(0x1760)
            let x_lo := mload(0x1780)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x17a0, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x17a0))
                mstore(0x100, mload(0x17c0))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x17c0)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x17a0)), borrow)
                    mstore(0x17a0, neg_y_hi)
                    mstore(0x17c0, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x23b))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x17e0, 0)
            mstore(0x1800, 0)
            mstore(0x1820, 0)
            mstore(0x1840, 0)
            calldatacopy(0x17f0, 0x23c, 0x30)

            let x_hi := mload(0x17e0)
            let x_lo := mload(0x1800)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1820, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1820))
                mstore(0x100, mload(0x1840))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1840)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1820)), borrow)
                    mstore(0x1820, neg_y_hi)
                    mstore(0x1840, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x26c))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1860, 0)
            mstore(0x1880, 0)
            mstore(0x18a0, 0)
            mstore(0x18c0, 0)
            calldatacopy(0x1870, 0x26d, 0x30)

            let x_hi := mload(0x1860)
            let x_lo := mload(0x1880)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x18a0, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x18a0))
                mstore(0x100, mload(0x18c0))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x18c0)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x18a0)), borrow)
                    mstore(0x18a0, neg_y_hi)
                    mstore(0x18c0, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x29d))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x18e0, 0)
            mstore(0x1900, 0)
            mstore(0x1920, 0)
            mstore(0x1940, 0)
            calldatacopy(0x18f0, 0x29e, 0x30)

            let x_hi := mload(0x18e0)
            let x_lo := mload(0x1900)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1920, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1920))
                mstore(0x100, mload(0x1940))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1940)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1920)), borrow)
                    mstore(0x1920, neg_y_hi)
                    mstore(0x1940, neg_y_lo)
                }
            }
        }
mstore(0x1960, keccak256(0x1740, 544))
mstore(0x1980, mod(mload(0x1960), f_q))
mstore(0x19a0, mload(0x1960))

        {
            let flag := byte(0, calldataload(0x2ce))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x19c0, 0)
            mstore(0x19e0, 0)
            mstore(0x1a00, 0)
            mstore(0x1a20, 0)
            calldatacopy(0x19d0, 0x2cf, 0x30)

            let x_hi := mload(0x19c0)
            let x_lo := mload(0x19e0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a00, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1a00))
                mstore(0x100, mload(0x1a20))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1a20)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1a00)), borrow)
                    mstore(0x1a00, neg_y_hi)
                    mstore(0x1a20, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x2ff))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1a40, 0)
            mstore(0x1a60, 0)
            mstore(0x1a80, 0)
            mstore(0x1aa0, 0)
            calldatacopy(0x1a50, 0x300, 0x30)

            let x_hi := mload(0x1a40)
            let x_lo := mload(0x1a60)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a80, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1a80))
                mstore(0x100, mload(0x1aa0))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1aa0)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1a80)), borrow)
                    mstore(0x1a80, neg_y_hi)
                    mstore(0x1aa0, neg_y_lo)
                }
            }
        }
mstore(0x1ac0, keccak256(0x19a0, 288))
mstore(0x1ae0, mod(mload(0x1ac0), f_q))
mstore(0x1b00, mload(0x1ac0))

        {
            let flag := byte(0, calldataload(0x330))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1b20, 0)
            mstore(0x1b40, 0)
            mstore(0x1b60, 0)
            mstore(0x1b80, 0)
            calldatacopy(0x1b30, 0x331, 0x30)

            let x_hi := mload(0x1b20)
            let x_lo := mload(0x1b40)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1b60, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1b60))
                mstore(0x100, mload(0x1b80))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1b80)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1b60)), borrow)
                    mstore(0x1b60, neg_y_hi)
                    mstore(0x1b80, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x361))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1ba0, 0)
            mstore(0x1bc0, 0)
            mstore(0x1be0, 0)
            mstore(0x1c00, 0)
            calldatacopy(0x1bb0, 0x362, 0x30)

            let x_hi := mload(0x1ba0)
            let x_lo := mload(0x1bc0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1be0, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1be0))
                mstore(0x100, mload(0x1c00))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1c00)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1be0)), borrow)
                    mstore(0x1be0, neg_y_hi)
                    mstore(0x1c00, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x392))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1c20, 0)
            mstore(0x1c40, 0)
            mstore(0x1c60, 0)
            mstore(0x1c80, 0)
            calldatacopy(0x1c30, 0x393, 0x30)

            let x_hi := mload(0x1c20)
            let x_lo := mload(0x1c40)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1c60, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1c60))
                mstore(0x100, mload(0x1c80))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1c80)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1c60)), borrow)
                    mstore(0x1c60, neg_y_hi)
                    mstore(0x1c80, neg_y_lo)
                }
            }
        }

        {
            let flag := byte(0, calldataload(0x3c3))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x1ca0, 0)
            mstore(0x1cc0, 0)
            mstore(0x1ce0, 0)
            mstore(0x1d00, 0)
            calldatacopy(0x1cb0, 0x3c4, 0x30)

            let x_hi := mload(0x1ca0)
            let x_lo := mload(0x1cc0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1ce0, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x1ce0))
                mstore(0x100, mload(0x1d00))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x1d00)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x1ce0)), borrow)
                    mstore(0x1ce0, neg_y_hi)
                    mstore(0x1d00, neg_y_lo)
                }
            }
        }
mstore(0x1d20, keccak256(0x1b00, 544))
mstore(0x1d40, mod(mload(0x1d20), f_q))
mstore(0x1d60, mload(0x1d20))
mstore(0x1d80, mod(calldataload(0x3f4), f_q))
mstore(0x1da0, mod(calldataload(0x414), f_q))
mstore(0x1dc0, mod(calldataload(0x434), f_q))
mstore(0x1de0, mod(calldataload(0x454), f_q))
mstore(0x1e00, mod(calldataload(0x474), f_q))
mstore(0x1e20, mod(calldataload(0x494), f_q))
mstore(0x1e40, mod(calldataload(0x4b4), f_q))
mstore(0x1e60, mod(calldataload(0x4d4), f_q))
mstore(0x1e80, mod(calldataload(0x4f4), f_q))
mstore(0x1ea0, mod(calldataload(0x514), f_q))
mstore(0x1ec0, mod(calldataload(0x534), f_q))
mstore(0x1ee0, mod(calldataload(0x554), f_q))
mstore(0x1f00, mod(calldataload(0x574), f_q))
mstore(0x1f20, mod(calldataload(0x594), f_q))
mstore(0x1f40, mod(calldataload(0x5b4), f_q))
mstore(0x1f60, mod(calldataload(0x5d4), f_q))
mstore(0x1f80, mod(calldataload(0x5f4), f_q))
mstore(0x1fa0, mod(calldataload(0x614), f_q))
mstore(0x1fc0, mod(calldataload(0x634), f_q))
mstore(0x1fe0, mod(calldataload(0x654), f_q))
mstore(0x2000, mod(calldataload(0x674), f_q))
mstore(0x2020, mod(calldataload(0x694), f_q))
mstore(0x2040, mod(calldataload(0x6b4), f_q))
mstore(0x2060, mod(calldataload(0x6d4), f_q))
mstore(0x2080, mod(calldataload(0x6f4), f_q))
mstore(0x20a0, mod(calldataload(0x714), f_q))
mstore(0x20c0, mod(calldataload(0x734), f_q))
mstore(0x20e0, mod(calldataload(0x754), f_q))
mstore(0x2100, mod(calldataload(0x774), f_q))
mstore(0x2120, mod(calldataload(0x794), f_q))
mstore(0x2140, mod(calldataload(0x7b4), f_q))
mstore(0x2160, mod(calldataload(0x7d4), f_q))
mstore(0x2180, mod(calldataload(0x7f4), f_q))
mstore(0x21a0, mod(calldataload(0x814), f_q))
mstore(0x21c0, mod(calldataload(0x834), f_q))
mstore(0x21e0, mod(calldataload(0x854), f_q))
mstore(0x2200, mod(calldataload(0x874), f_q))
mstore(0x2220, mod(calldataload(0x894), f_q))
mstore(0x2240, mod(calldataload(0x8b4), f_q))
mstore(0x2260, mod(calldataload(0x8d4), f_q))
mstore(0x2280, mod(calldataload(0x8f4), f_q))
mstore(0x22a0, mod(calldataload(0x914), f_q))
mstore(0x22c0, mod(calldataload(0x934), f_q))
mstore(0x22e0, mod(calldataload(0x954), f_q))
mstore(0x2300, mod(calldataload(0x974), f_q))
mstore(0x2320, mod(calldataload(0x994), f_q))
mstore(0x2340, mod(calldataload(0x9b4), f_q))
mstore(0x2360, mod(calldataload(0x9d4), f_q))
mstore(0x2380, mod(calldataload(0x9f4), f_q))
mstore(0x23a0, mod(calldataload(0xa14), f_q))
mstore(0x23c0, mod(calldataload(0xa34), f_q))
mstore(0x23e0, mod(calldataload(0xa54), f_q))
mstore(0x2400, mod(calldataload(0xa74), f_q))
mstore(0x2420, mod(calldataload(0xa94), f_q))
mstore(0x2440, keccak256(0x1d60, 1760))
mstore(0x2460, mod(mload(0x2440), f_q))
mstore(0x2480, mload(0x2440))
mstore8(0x24a0, 1)
mstore(0x24a0, keccak256(0x2480, 33))
mstore(0x24c0, mod(mload(0x24a0), f_q))
mstore(0x24e0, mload(0x24a0))

        {
            let flag := byte(0, calldataload(0xab4))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x2500, 0)
            mstore(0x2520, 0)
            mstore(0x2540, 0)
            mstore(0x2560, 0)
            calldatacopy(0x2510, 0xab5, 0x30)

            let x_hi := mload(0x2500)
            let x_lo := mload(0x2520)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x2540, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x2540))
                mstore(0x100, mload(0x2560))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x2560)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x2540)), borrow)
                    mstore(0x2540, neg_y_hi)
                    mstore(0x2560, neg_y_lo)
                }
            }
        }
mstore(0x2580, keccak256(0x24e0, 160))
mstore(0x25a0, mod(mload(0x2580), f_q))
mstore(0x25c0, mload(0x2580))
mstore(0x25e0, mod(calldataload(0xae5), f_q))
mstore(0x2600, mod(calldataload(0xb05), f_q))
mstore(0x2620, mod(calldataload(0xb25), f_q))
mstore(0x2640, mod(calldataload(0xb45), f_q))
mstore(0x2660, keccak256(0x25c0, 160))
mstore(0x2680, mod(mload(0x2660), f_q))
mstore(0x26a0, mload(0x2660))

        {
            let flag := byte(0, calldataload(0xb65))
            let y_odd := and(flag, 1)
            let is_inf := and(shr(1, flag), 1)
            // Reject unsupported flag bits.
            success := and(iszero(and(flag, 0xfc)), success)

            // Zero-initialize x/y limbs then copy compact x.
            mstore(0x26c0, 0)
            mstore(0x26e0, 0)
            mstore(0x2700, 0)
            mstore(0x2720, 0)
            calldatacopy(0x26d0, 0xb66, 0x30)

            let x_hi := mload(0x26c0)
            let x_lo := mload(0x26e0)

            if is_inf {
                // Infinity must carry zero x and odd-flag unset.
                success := and(eq(y_odd, 0), success)
                success := and(eq(x_hi, 0), success)
                success := and(eq(x_lo, 0), success)
            }

            if iszero(is_inf) {
                // Enforce x < p.
                success := and(
                    or(lt(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(x_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), lt(x_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab))),
                    success
                )

                // rhs <- x^3 mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, x_hi)
                mstore(0x100, x_lo)
                mstore(0x120, 0)
                mstore(0x140, 3)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1a0, 0x40), 1),
                    success
                )

                // rhs <- (x^3 + 4) mod p.
                let rhs_hi := mload(0x1a0)
                let rhs_lo0 := mload(0x1c0)
                let rhs_lo := add(rhs_lo0, 4)
                let carry := lt(rhs_lo, rhs_lo0)
                rhs_hi := add(rhs_hi, carry)
                if or(gt(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), and(eq(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7), iszero(lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)))) {
                    rhs_hi := sub(rhs_hi, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                    let borrow := lt(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_lo := sub(rhs_lo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                    rhs_hi := sub(rhs_hi, borrow)
                }
                mstore(0x1a0, rhs_hi)
                mstore(0x1c0, rhs_lo)

                // y <- rhs^((p+1)/4) mod p.
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, rhs_hi)
                mstore(0x100, rhs_lo)
                mstore(0x120, 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35)
                mstore(0x140, 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x2700, 0x40), 1),
                    success
                )

                // Validate square root: y^2 == rhs (mod p).
                mstore(0x80, 0x40)
                mstore(0xa0, 0x40)
                mstore(0xc0, 0x40)
                mstore(0xe0, mload(0x2700))
                mstore(0x100, mload(0x2720))
                mstore(0x120, 0)
                mstore(0x140, 2)
                mstore(0x160, 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
                mstore(0x180, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                success := and(
                    eq(staticcall(gas(), 0x5, 0x80, 0x120, 0x1e0, 0x40), 1),
                    success
                )
                success := and(eq(mload(0x1e0), mload(0x1a0)), success)
                success := and(eq(mload(0x200), mload(0x1c0)), success)

                // Select y root by oddness bit.
                let y_lo := mload(0x2720)
                let is_odd_y := and(y_lo, 1)
                if xor(is_odd_y, y_odd) {
                    let neg_y_lo := sub(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let borrow := lt(0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, y_lo)
                    let neg_y_hi := sub(sub(0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7, mload(0x2700)), borrow)
                    mstore(0x2700, neg_y_hi)
                    mstore(0x2720, neg_y_lo)
                }
            }
        }
mstore(0x2740, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x2760, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x2780, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x27a0, 0x0000000000000000000000000000000000000000000000000000000000000000)
mstore(0x27c0, mulmod(mload(0x1d40), mload(0x1d40), f_q))
mstore(0x27e0, mulmod(mload(0x27c0), mload(0x27c0), f_q))
mstore(0x2800, mulmod(mload(0x27e0), mload(0x27e0), f_q))
mstore(0x2820, mulmod(mload(0x2800), mload(0x2800), f_q))
mstore(0x2840, mulmod(mload(0x2820), mload(0x2820), f_q))
mstore(0x2860, mulmod(mload(0x2840), mload(0x2840), f_q))
mstore(0x2880, addmod(mload(0x2860), 52435875175126190479447740508185965837690552500527637822603658699938581184512, f_q))
mstore(0x28a0, mulmod(mload(0x2880), 51616564625514843753206369562745560121476637617706893481625476532752040853505, f_q))
mstore(0x28c0, mulmod(mload(0x28a0), 21259823323969146045885553965890482219221908228759787200404479960115227367690, f_q))
mstore(0x28e0, addmod(mload(0x1d40), 31176051851157044433562186542295483618468644271767850622199178739823353816823, f_q))
mstore(0x2900, mulmod(mload(0x28a0), 14887102955893838413024403264664292195708703256831905665143363416435654328648, f_q))
mstore(0x2920, addmod(mload(0x1d40), 37548772219232352066423337243521673641981849243695732157460295283502926855865, f_q))
mstore(0x2940, mulmod(mload(0x28a0), 2527721918302134385520002926840515195543678449692795676238296383251703745807, f_q))
mstore(0x2960, addmod(mload(0x1d40), 49908153256824056093927737581345450642146874050834842146365362316686877438706, f_q))
mstore(0x2980, mulmod(mload(0x28a0), 26753076894533791554649012143113393549300550745003194222677083919072199473480, f_q))
mstore(0x29a0, addmod(mload(0x1d40), 25682798280592398924798728365072572288390001755524443599926574780866381711033, f_q))
mstore(0x29c0, mulmod(mload(0x28a0), 7500590202698556019030633716209352927214297656990813043538655792743940636058, f_q))
mstore(0x29e0, addmod(mload(0x1d40), 44935284972427634460417106791976612910476254843536824779065002907194640548455, f_q))
mstore(0x2a00, mulmod(mload(0x28a0), 42722234674624019897108426302713230860602919991722520098540931937949837992684, f_q))
mstore(0x2a20, addmod(mload(0x1d40), 9713640500502170582339314205472734977087632508805117724062726761988743191829, f_q))
mstore(0x2a40, mulmod(mload(0x28a0), 45254319123522011116259460062854627366454101350769349111320208945036885998124, f_q))
mstore(0x2a60, addmod(mload(0x1d40), 7181556051604179363188280445331338471236451149758288711283449754901695186389, f_q))
mstore(0x2a80, mulmod(mload(0x28a0), 1, f_q))
mstore(0x2aa0, addmod(mload(0x1d40), 52435875175126190479447740508185965837690552500527637822603658699938581184512, f_q))
{
            let prod := mload(0x28e0)

                prod := mulmod(mload(0x2920), prod, f_q)
                mstore(0x2ac0, prod)
            
                prod := mulmod(mload(0x2960), prod, f_q)
                mstore(0x2ae0, prod)
            
                prod := mulmod(mload(0x29a0), prod, f_q)
                mstore(0x2b00, prod)
            
                prod := mulmod(mload(0x29e0), prod, f_q)
                mstore(0x2b20, prod)
            
                prod := mulmod(mload(0x2a20), prod, f_q)
                mstore(0x2b40, prod)
            
                prod := mulmod(mload(0x2a60), prod, f_q)
                mstore(0x2b60, prod)
            
                prod := mulmod(mload(0x2aa0), prod, f_q)
                mstore(0x2b80, prod)
            
                prod := mulmod(mload(0x2880), prod, f_q)
                mstore(0x2ba0, prod)
            
        }
mstore(0x2be0, 32)
mstore(0x2c00, 32)
mstore(0x2c20, 32)
mstore(0x2c40, mload(0x2ba0))
mstore(0x2c60, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x2c80, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x2be0, 0xc0, 0x2bc0, 0x20), 1), success)
{
            
            let inv := mload(0x2bc0)
            let v
        
                    v := mload(0x2880)
                    mstore(10368, mulmod(mload(0x2b80), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2aa0)
                    mstore(10912, mulmod(mload(0x2b60), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2a60)
                    mstore(10848, mulmod(mload(0x2b40), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2a20)
                    mstore(10784, mulmod(mload(0x2b20), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x29e0)
                    mstore(10720, mulmod(mload(0x2b00), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x29a0)
                    mstore(10656, mulmod(mload(0x2ae0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2960)
                    mstore(10592, mulmod(mload(0x2ac0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2920)
                    mstore(10528, mulmod(mload(0x28e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x28e0, inv)

        }
mstore(0x2ca0, mulmod(mload(0x28c0), mload(0x28e0), f_q))
mstore(0x2cc0, mulmod(mload(0x2900), mload(0x2920), f_q))
mstore(0x2ce0, mulmod(mload(0x2940), mload(0x2960), f_q))
mstore(0x2d00, mulmod(mload(0x2980), mload(0x29a0), f_q))
mstore(0x2d20, mulmod(mload(0x29c0), mload(0x29e0), f_q))
mstore(0x2d40, mulmod(mload(0x2a00), mload(0x2a20), f_q))
mstore(0x2d60, mulmod(mload(0x2a40), mload(0x2a60), f_q))
mstore(0x2d80, mulmod(mload(0x2a80), mload(0x2aa0), f_q))
{
            let result := mulmod(mload(0x2d80), mload(0x1040), f_q)
mstore(11680, result)
        }
mstore(0x2dc0, mulmod(mload(0x1da0), mload(0x1f20), f_q))
mstore(0x2de0, addmod(mload(0x2020), mload(0x2dc0), f_q))
mstore(0x2e00, mulmod(mload(0x1dc0), mload(0x1f40), f_q))
mstore(0x2e20, addmod(mload(0x2de0), mload(0x2e00), f_q))
mstore(0x2e40, mulmod(mload(0x1de0), mload(0x1f60), f_q))
mstore(0x2e60, addmod(mload(0x2e20), mload(0x2e40), f_q))
mstore(0x2e80, mulmod(mload(0x1e00), mload(0x1f80), f_q))
mstore(0x2ea0, addmod(mload(0x2e60), mload(0x2e80), f_q))
mstore(0x2ec0, mulmod(mload(0x1e20), mload(0x1fa0), f_q))
mstore(0x2ee0, addmod(mload(0x2ea0), mload(0x2ec0), f_q))
mstore(0x2f00, mulmod(mload(0x1e40), mload(0x1fc0), f_q))
mstore(0x2f20, addmod(mload(0x2ee0), mload(0x2f00), f_q))
mstore(0x2f40, mulmod(mload(0x1da0), mload(0x1fe0), f_q))
mstore(0x2f60, mulmod(mload(0x1dc0), mload(0x2f40), f_q))
mstore(0x2f80, addmod(mload(0x2f20), mload(0x2f60), f_q))
mstore(0x2fa0, mulmod(mload(0x1da0), mload(0x2000), f_q))
mstore(0x2fc0, mulmod(mload(0x1de0), mload(0x2fa0), f_q))
mstore(0x2fe0, addmod(mload(0x2f80), mload(0x2fc0), f_q))
mstore(0x3000, mulmod(mload(0x2fe0), mload(0x20a0), f_q))
mstore(0x3020, mulmod(mload(0x1ae0), mload(0x3000), f_q))
mstore(0x3040, addmod(mload(0x1dc0), mload(0x1de0), f_q))
mstore(0x3060, addmod(mload(0x3040), sub(f_q, mload(0x1e00)), f_q))
mstore(0x3080, addmod(mload(0x3060), sub(f_q, mload(0x1e20)), f_q))
mstore(0x30a0, mulmod(mload(0x3080), mload(0x20c0), f_q))
mstore(0x30c0, addmod(mload(0x3020), mload(0x30a0), f_q))
mstore(0x30e0, mulmod(mload(0x1ae0), mload(0x30c0), f_q))
mstore(0x3100, addmod(mload(0x1da0), mload(0x1f20), f_q))
mstore(0x3120, addmod(mload(0x3100), sub(f_q, mload(0x1e40)), f_q))
mstore(0x3140, mulmod(mload(0x3120), mload(0x20e0), f_q))
mstore(0x3160, addmod(mload(0x30e0), mload(0x3140), f_q))
mstore(0x3180, mulmod(mload(0x1ae0), mload(0x3160), f_q))
mstore(0x31a0, addmod(mload(0x1dc0), mload(0x1f40), f_q))
mstore(0x31c0, addmod(mload(0x31a0), sub(f_q, mload(0x1e60)), f_q))
mstore(0x31e0, mulmod(mload(0x31c0), mload(0x20e0), f_q))
mstore(0x3200, addmod(mload(0x3180), mload(0x31e0), f_q))
mstore(0x3220, mulmod(mload(0x1ae0), mload(0x3200), f_q))
mstore(0x3240, addmod(mload(0x1de0), mload(0x1f60), f_q))
mstore(0x3260, addmod(mload(0x3240), sub(f_q, mload(0x1e80)), f_q))
mstore(0x3280, mulmod(mload(0x3260), mload(0x20e0), f_q))
mstore(0x32a0, addmod(mload(0x3220), mload(0x3280), f_q))
mstore(0x32c0, mulmod(mload(0x1ae0), mload(0x32a0), f_q))
mstore(0x32e0, mulmod(mload(0x1da0), mload(0x1da0), f_q))
mstore(0x3300, mulmod(mload(0x32e0), mload(0x1da0), f_q))
mstore(0x3320, addmod(mload(0x3300), sub(f_q, mload(0x1e00)), f_q))
mstore(0x3340, mulmod(mload(0x3320), mload(0x2120), f_q))
mstore(0x3360, addmod(mload(0x32c0), mload(0x3340), f_q))
mstore(0x3380, mulmod(mload(0x1ae0), mload(0x3360), f_q))
mstore(0x33a0, mulmod(mload(0x1dc0), mload(0x1dc0), f_q))
mstore(0x33c0, mulmod(mload(0x33a0), mload(0x1dc0), f_q))
mstore(0x33e0, addmod(mload(0x33c0), sub(f_q, mload(0x1e20)), f_q))
mstore(0x3400, mulmod(mload(0x33e0), mload(0x2120), f_q))
mstore(0x3420, addmod(mload(0x3380), mload(0x3400), f_q))
mstore(0x3440, mulmod(mload(0x1ae0), mload(0x3420), f_q))
mstore(0x3460, mulmod(mload(0x1de0), mload(0x1de0), f_q))
mstore(0x3480, mulmod(mload(0x3460), mload(0x1de0), f_q))
mstore(0x34a0, addmod(mload(0x3480), sub(f_q, mload(0x1ea0)), f_q))
mstore(0x34c0, mulmod(mload(0x34a0), mload(0x2120), f_q))
mstore(0x34e0, addmod(mload(0x3440), mload(0x34c0), f_q))
mstore(0x3500, mulmod(mload(0x1ae0), mload(0x34e0), f_q))
mstore(0x3520, addmod(mload(0x1fc0), sub(f_q, mload(0x1e40)), f_q))
mstore(0x3540, mulmod(mload(0x1e00), mload(0x32e0), f_q))
mstore(0x3560, mulmod(mload(0x3540), 12440513488882586407557540066179884648646530011544707182889396930153310132942, f_q))
mstore(0x3580, addmod(mload(0x3520), mload(0x3560), f_q))
mstore(0x35a0, mulmod(mload(0x1e20), mload(0x33a0), f_q))
mstore(0x35c0, mulmod(mload(0x35a0), 28020747150333089913259220781304558809551608596314918030152947066915898054499, f_q))
mstore(0x35e0, addmod(mload(0x3580), mload(0x35c0), f_q))
mstore(0x3600, mulmod(mload(0x1ea0), mload(0x3460), f_q))
mstore(0x3620, mulmod(mload(0x3600), 28505902463311974130913002774524928623644005505993681602486681565155683331521, f_q))
mstore(0x3640, addmod(mload(0x35e0), mload(0x3620), f_q))
mstore(0x3660, mulmod(mload(0x3640), mload(0x2120), f_q))
mstore(0x3680, addmod(mload(0x3500), mload(0x3660), f_q))
mstore(0x36a0, mulmod(mload(0x1ae0), mload(0x3680), f_q))
mstore(0x36c0, addmod(mload(0x1fe0), sub(f_q, mload(0x1e60)), f_q))
mstore(0x36e0, mulmod(mload(0x3540), 29084297485723905200880885323289986130569887053242706304266829364413965316980, f_q))
mstore(0x3700, addmod(mload(0x36c0), mload(0x36e0), f_q))
mstore(0x3720, mulmod(mload(0x35a0), 5054565981041632243581284853746902850980503096245579875276544410572564089329, f_q))
mstore(0x3740, addmod(mload(0x3700), mload(0x3720), f_q))
mstore(0x3760, mulmod(mload(0x3600), 7179405695647424344643177657798954274869382720335107962712222495241823787551, f_q))
mstore(0x3780, addmod(mload(0x3740), mload(0x3760), f_q))
mstore(0x37a0, mulmod(mload(0x3780), mload(0x2120), f_q))
mstore(0x37c0, addmod(mload(0x36a0), mload(0x37a0), f_q))
mstore(0x37e0, mulmod(mload(0x1ae0), mload(0x37c0), f_q))
mstore(0x3800, addmod(mload(0x2000), sub(f_q, mload(0x1e80)), f_q))
mstore(0x3820, mulmod(mload(0x3540), 42569072482279996318031820844820583094661593761988851871644829917446303682880, f_q))
mstore(0x3840, addmod(mload(0x3800), mload(0x3820), f_q))
mstore(0x3860, mulmod(mload(0x35a0), 48777675531739959342114240072267441286903816384223937749440830379544192657290, f_q))
mstore(0x3880, addmod(mload(0x3840), mload(0x3860), f_q))
mstore(0x38a0, mulmod(mload(0x3600), 33286996086728685078854749126251163286167502628080690207063928367301359689947, f_q))
mstore(0x38c0, addmod(mload(0x3880), mload(0x38a0), f_q))
mstore(0x38e0, mulmod(mload(0x38c0), mload(0x2120), f_q))
mstore(0x3900, addmod(mload(0x37e0), mload(0x38e0), f_q))
mstore(0x3920, mulmod(mload(0x1ae0), mload(0x3900), f_q))
mstore(0x3940, addmod(1, sub(f_q, mload(0x2280)), f_q))
mstore(0x3960, mulmod(mload(0x3940), mload(0x2d80), f_q))
mstore(0x3980, addmod(mload(0x3920), mload(0x3960), f_q))
mstore(0x39a0, mulmod(mload(0x1ae0), mload(0x3980), f_q))
mstore(0x39c0, mulmod(mload(0x2340), mload(0x2340), f_q))
mstore(0x39e0, addmod(mload(0x39c0), sub(f_q, mload(0x2340)), f_q))
mstore(0x3a00, mulmod(mload(0x39e0), mload(0x2ca0), f_q))
mstore(0x3a20, addmod(mload(0x39a0), mload(0x3a00), f_q))
mstore(0x3a40, mulmod(mload(0x1ae0), mload(0x3a20), f_q))
mstore(0x3a60, addmod(mload(0x22e0), sub(f_q, mload(0x22c0)), f_q))
mstore(0x3a80, mulmod(mload(0x3a60), mload(0x2d80), f_q))
mstore(0x3aa0, addmod(mload(0x3a40), mload(0x3a80), f_q))
mstore(0x3ac0, mulmod(mload(0x1ae0), mload(0x3aa0), f_q))
mstore(0x3ae0, addmod(mload(0x2340), sub(f_q, mload(0x2320)), f_q))
mstore(0x3b00, mulmod(mload(0x3ae0), mload(0x2d80), f_q))
mstore(0x3b20, addmod(mload(0x3ac0), mload(0x3b00), f_q))
mstore(0x3b40, mulmod(mload(0x1ae0), mload(0x3b20), f_q))
mstore(0x3b60, addmod(1, sub(f_q, mload(0x2ca0)), f_q))
mstore(0x3b80, addmod(mload(0x2cc0), mload(0x2ce0), f_q))
mstore(0x3ba0, addmod(mload(0x3b80), mload(0x2d00), f_q))
mstore(0x3bc0, addmod(mload(0x3ba0), mload(0x2d20), f_q))
mstore(0x3be0, addmod(mload(0x3bc0), mload(0x2d40), f_q))
mstore(0x3c00, addmod(mload(0x3be0), mload(0x2d60), f_q))
mstore(0x3c20, addmod(mload(0x3b60), sub(f_q, mload(0x3c00)), f_q))
mstore(0x3c40, mulmod(mload(0x2180), mload(0x16c0), f_q))
mstore(0x3c60, addmod(mload(0x1f00), mload(0x3c40), f_q))
mstore(0x3c80, addmod(mload(0x3c60), mload(0x1720), f_q))
mstore(0x3ca0, mulmod(mload(0x21a0), mload(0x16c0), f_q))
mstore(0x3cc0, addmod(mload(0x1da0), mload(0x3ca0), f_q))
mstore(0x3ce0, addmod(mload(0x3cc0), mload(0x1720), f_q))
mstore(0x3d00, mulmod(mload(0x3ce0), mload(0x3c80), f_q))
mstore(0x3d20, mulmod(mload(0x21c0), mload(0x16c0), f_q))
mstore(0x3d40, addmod(mload(0x1dc0), mload(0x3d20), f_q))
mstore(0x3d60, addmod(mload(0x3d40), mload(0x1720), f_q))
mstore(0x3d80, mulmod(mload(0x3d60), mload(0x3d00), f_q))
mstore(0x3da0, mulmod(mload(0x3d80), mload(0x22a0), f_q))
mstore(0x3dc0, mulmod(1, mload(0x16c0), f_q))
mstore(0x3de0, mulmod(mload(0x1d40), mload(0x3dc0), f_q))
mstore(0x3e00, addmod(mload(0x1f00), mload(0x3de0), f_q))
mstore(0x3e20, addmod(mload(0x3e00), mload(0x1720), f_q))
mstore(0x3e40, mulmod(3793952369011177517951424454785176000433849974408744014172535497121832470999, mload(0x16c0), f_q))
mstore(0x3e60, mulmod(mload(0x1d40), mload(0x3e40), f_q))
mstore(0x3e80, addmod(mload(0x1da0), mload(0x3e60), f_q))
mstore(0x3ea0, addmod(mload(0x3e80), mload(0x1720), f_q))
mstore(0x3ec0, mulmod(mload(0x3ea0), mload(0x3e20), f_q))
mstore(0x3ee0, mulmod(29260201042546974833203213796440688721049425934417030432187341694347311461130, mload(0x16c0), f_q))
mstore(0x3f00, mulmod(mload(0x1d40), mload(0x3ee0), f_q))
mstore(0x3f20, addmod(mload(0x1dc0), mload(0x3f00), f_q))
mstore(0x3f40, addmod(mload(0x3f20), mload(0x1720), f_q))
mstore(0x3f60, mulmod(mload(0x3f40), mload(0x3ec0), f_q))
mstore(0x3f80, mulmod(mload(0x3f60), mload(0x2280), f_q))
mstore(0x3fa0, addmod(mload(0x3da0), sub(f_q, mload(0x3f80)), f_q))
mstore(0x3fc0, mulmod(mload(0x3fa0), mload(0x3c20), f_q))
mstore(0x3fe0, addmod(mload(0x3b40), mload(0x3fc0), f_q))
mstore(0x4000, mulmod(mload(0x1ae0), mload(0x3fe0), f_q))
mstore(0x4020, mulmod(mload(0x21e0), mload(0x16c0), f_q))
mstore(0x4040, addmod(mload(0x1de0), mload(0x4020), f_q))
mstore(0x4060, addmod(mload(0x4040), mload(0x1720), f_q))
mstore(0x4080, mulmod(mload(0x2200), mload(0x16c0), f_q))
mstore(0x40a0, addmod(mload(0x1e00), mload(0x4080), f_q))
mstore(0x40c0, addmod(mload(0x40a0), mload(0x1720), f_q))
mstore(0x40e0, mulmod(mload(0x40c0), mload(0x4060), f_q))
mstore(0x4100, mulmod(mload(0x2220), mload(0x16c0), f_q))
mstore(0x4120, addmod(mload(0x1e20), mload(0x4100), f_q))
mstore(0x4140, addmod(mload(0x4120), mload(0x1720), f_q))
mstore(0x4160, mulmod(mload(0x4140), mload(0x40e0), f_q))
mstore(0x4180, mulmod(mload(0x4160), mload(0x2300), f_q))
mstore(0x41a0, mulmod(30087697416233164107364529847082617342382024227044140347550467692890124986659, mload(0x16c0), f_q))
mstore(0x41c0, mulmod(mload(0x1d40), mload(0x41a0), f_q))
mstore(0x41e0, addmod(mload(0x1de0), mload(0x41c0), f_q))
mstore(0x4200, addmod(mload(0x41e0), mload(0x1720), f_q))
mstore(0x4220, mulmod(50007016967099397293092916471763530035790684642821601195394169310725916110291, mload(0x16c0), f_q))
mstore(0x4240, mulmod(mload(0x1d40), mload(0x4220), f_q))
mstore(0x4260, addmod(mload(0x1e00), mload(0x4240), f_q))
mstore(0x4280, addmod(mload(0x4260), mload(0x1720), f_q))
mstore(0x42a0, mulmod(mload(0x4280), mload(0x4200), f_q))
mstore(0x42c0, mulmod(27153057483211730484975145092142082049750746716056827598870820011140481502624, mload(0x16c0), f_q))
mstore(0x42e0, mulmod(mload(0x1d40), mload(0x42c0), f_q))
mstore(0x4300, addmod(mload(0x1e20), mload(0x42e0), f_q))
mstore(0x4320, addmod(mload(0x4300), mload(0x1720), f_q))
mstore(0x4340, mulmod(mload(0x4320), mload(0x42a0), f_q))
mstore(0x4360, mulmod(mload(0x4340), mload(0x22e0), f_q))
mstore(0x4380, addmod(mload(0x4180), sub(f_q, mload(0x4360)), f_q))
mstore(0x43a0, mulmod(mload(0x4380), mload(0x3c20), f_q))
mstore(0x43c0, addmod(mload(0x4000), mload(0x43a0), f_q))
mstore(0x43e0, mulmod(mload(0x1ae0), mload(0x43c0), f_q))
mstore(0x4400, mulmod(mload(0x2240), mload(0x16c0), f_q))
mstore(0x4420, addmod(mload(0x1d80), mload(0x4400), f_q))
mstore(0x4440, addmod(mload(0x4420), mload(0x1720), f_q))
mstore(0x4460, mulmod(mload(0x2260), mload(0x16c0), f_q))
mstore(0x4480, addmod(mload(0x2da0), mload(0x4460), f_q))
mstore(0x44a0, addmod(mload(0x4480), mload(0x1720), f_q))
mstore(0x44c0, mulmod(mload(0x44a0), mload(0x4440), f_q))
mstore(0x44e0, mulmod(mload(0x44c0), mload(0x2360), f_q))
mstore(0x4500, mulmod(10702539897433481834547003544093270805576009760020429658622430844384109348913, mload(0x16c0), f_q))
mstore(0x4520, mulmod(mload(0x1d40), mload(0x4500), f_q))
mstore(0x4540, addmod(mload(0x1d80), mload(0x4520), f_q))
mstore(0x4560, addmod(mload(0x4540), mload(0x1720), f_q))
mstore(0x4580, mulmod(12176195809781855613695208773552147130199916160023471917144658464292859735274, mload(0x16c0), f_q))
mstore(0x45a0, mulmod(mload(0x1d40), mload(0x4580), f_q))
mstore(0x45c0, addmod(mload(0x2da0), mload(0x45a0), f_q))
mstore(0x45e0, addmod(mload(0x45c0), mload(0x1720), f_q))
mstore(0x4600, mulmod(mload(0x45e0), mload(0x4560), f_q))
mstore(0x4620, mulmod(mload(0x4600), mload(0x2340), f_q))
mstore(0x4640, addmod(mload(0x44e0), sub(f_q, mload(0x4620)), f_q))
mstore(0x4660, mulmod(mload(0x4640), mload(0x3c20), f_q))
mstore(0x4680, addmod(mload(0x43e0), mload(0x4660), f_q))
mstore(0x46a0, mulmod(mload(0x1ae0), mload(0x4680), f_q))
mstore(0x46c0, addmod(1, sub(f_q, mload(0x2380)), f_q))
mstore(0x46e0, mulmod(mload(0x46c0), mload(0x2d80), f_q))
mstore(0x4700, addmod(mload(0x46a0), mload(0x46e0), f_q))
mstore(0x4720, mulmod(mload(0x1ae0), mload(0x4700), f_q))
mstore(0x4740, mulmod(mload(0x2380), mload(0x2380), f_q))
mstore(0x4760, addmod(mload(0x4740), sub(f_q, mload(0x2380)), f_q))
mstore(0x4780, mulmod(mload(0x4760), mload(0x2ca0), f_q))
mstore(0x47a0, addmod(mload(0x4720), mload(0x4780), f_q))
mstore(0x47c0, mulmod(mload(0x1ae0), mload(0x47a0), f_q))
mstore(0x47e0, addmod(mload(0x23c0), mload(0x16c0), f_q))
mstore(0x4800, mulmod(mload(0x47e0), mload(0x23a0), f_q))
mstore(0x4820, addmod(mload(0x2400), mload(0x1720), f_q))
mstore(0x4840, mulmod(mload(0x4820), mload(0x4800), f_q))
mstore(0x4860, mulmod(mload(0x1560), mload(0x2040), f_q))
mstore(0x4880, mulmod(mload(0x1dc0), mload(0x2100), f_q))
mstore(0x48a0, addmod(mload(0x4860), mload(0x4880), f_q))
mstore(0x48c0, addmod(mload(0x48a0), mload(0x16c0), f_q))
mstore(0x48e0, mulmod(mload(0x48c0), mload(0x2380), f_q))
mstore(0x4900, mulmod(mload(0x1560), mload(0x2060), f_q))
mstore(0x4920, addmod(mload(0x4900), mload(0x2080), f_q))
mstore(0x4940, addmod(mload(0x4920), mload(0x1720), f_q))
mstore(0x4960, mulmod(mload(0x4940), mload(0x48e0), f_q))
mstore(0x4980, addmod(mload(0x4840), sub(f_q, mload(0x4960)), f_q))
mstore(0x49a0, mulmod(mload(0x4980), mload(0x3c20), f_q))
mstore(0x49c0, addmod(mload(0x47c0), mload(0x49a0), f_q))
mstore(0x49e0, mulmod(mload(0x1ae0), mload(0x49c0), f_q))
mstore(0x4a00, addmod(mload(0x23c0), sub(f_q, mload(0x2400)), f_q))
mstore(0x4a20, mulmod(mload(0x4a00), mload(0x2d80), f_q))
mstore(0x4a40, addmod(mload(0x49e0), mload(0x4a20), f_q))
mstore(0x4a60, mulmod(mload(0x1ae0), mload(0x4a40), f_q))
mstore(0x4a80, mulmod(mload(0x4a00), mload(0x3c20), f_q))
mstore(0x4aa0, addmod(mload(0x23c0), sub(f_q, mload(0x23e0)), f_q))
mstore(0x4ac0, mulmod(mload(0x4aa0), mload(0x4a80), f_q))
mstore(0x4ae0, addmod(mload(0x4a60), mload(0x4ac0), f_q))
mstore(0x4b00, mulmod(mload(0x1ae0), mload(0x4ae0), f_q))
mstore(0x4b20, mulmod(mload(0x1da0), 40276410782279108334863105369904789343040261455045516584779277825615697839985, f_q))
mstore(0x4b40, mulmod(mload(0x1dc0), 37527016513455530468277088833539226510789135770417315120855317098742889359215, f_q))
mstore(0x4b60, addmod(mload(0x4b20), mload(0x4b40), f_q))
mstore(0x4b80, mulmod(mload(0x3460), mload(0x3460), f_q))
mstore(0x4ba0, mulmod(mload(0x4b80), mload(0x1de0), f_q))
mstore(0x4bc0, mulmod(mload(0x4ba0), 23990009175532390848383686641478884818239121606019298540653394434675622011304, f_q))
mstore(0x4be0, addmod(mload(0x4b60), mload(0x4bc0), f_q))
mstore(0x4c00, mulmod(mload(0x1e00), mload(0x1e00), f_q))
mstore(0x4c20, mulmod(mload(0x4c00), mload(0x4c00), f_q))
mstore(0x4c40, mulmod(mload(0x4c20), mload(0x1e00), f_q))
mstore(0x4c60, mulmod(mload(0x4c40), 23180151978504326669680984036118508621180775988903922469131210268215350444530, f_q))
mstore(0x4c80, addmod(mload(0x4be0), mload(0x4c60), f_q))
mstore(0x4ca0, mulmod(mload(0x1e20), mload(0x1e20), f_q))
mstore(0x4cc0, mulmod(mload(0x4ca0), mload(0x4ca0), f_q))
mstore(0x4ce0, mulmod(mload(0x4cc0), mload(0x1e20), f_q))
mstore(0x4d00, mulmod(mload(0x4ce0), 29479126442377740792305085857437384138015409209423896273007595542837761281189, f_q))
mstore(0x4d20, addmod(mload(0x4c80), mload(0x4d00), f_q))
mstore(0x4d40, mulmod(mload(0x1ea0), mload(0x1ea0), f_q))
mstore(0x4d60, mulmod(mload(0x4d40), mload(0x4d40), f_q))
mstore(0x4d80, mulmod(mload(0x4d60), mload(0x1ea0), f_q))
mstore(0x4da0, mulmod(mload(0x4d80), 37990615931907094420184937091556956528876595328335061740913699785965517240590, f_q))
mstore(0x4dc0, addmod(mload(0x4d20), mload(0x4da0), f_q))
mstore(0x4de0, mulmod(mload(0x1ec0), mload(0x1ec0), f_q))
mstore(0x4e00, mulmod(mload(0x4de0), mload(0x4de0), f_q))
mstore(0x4e20, mulmod(mload(0x4e00), mload(0x1ec0), f_q))
mstore(0x4e40, mulmod(mload(0x4e20), 3075540889646953729606836824147910283102396481803053667698778232583469493556, f_q))
mstore(0x4e60, addmod(mload(0x4dc0), mload(0x4e40), f_q))
mstore(0x4e80, mulmod(mload(0x1ee0), mload(0x1ee0), f_q))
mstore(0x4ea0, mulmod(mload(0x4e80), mload(0x4e80), f_q))
mstore(0x4ec0, mulmod(mload(0x4ea0), mload(0x1ee0), f_q))
mstore(0x4ee0, mulmod(mload(0x4ec0), 28505902463311974130913002774524928623644005505993681602486681565155683331521, f_q))
mstore(0x4f00, addmod(mload(0x4e60), mload(0x4ee0), f_q))
mstore(0x4f20, addmod(mload(0x3520), mload(0x4f00), f_q))
mstore(0x4f40, mulmod(mload(0x1980), mload(0x4f20), f_q))
mstore(0x4f60, mulmod(mload(0x1da0), 41216583078069907292136355165153270142521178992429414226155254333730607536733, f_q))
mstore(0x4f80, mulmod(mload(0x1dc0), 34853984525125276266590937240908152702715112008598809217765432339048892301352, f_q))
mstore(0x4fa0, addmod(mload(0x4f60), mload(0x4f80), f_q))
mstore(0x4fc0, mulmod(mload(0x4ba0), 17548561380688843065348281029305916198268522889382278651903462232179510668048, f_q))
mstore(0x4fe0, addmod(mload(0x4fa0), mload(0x4fc0), f_q))
mstore(0x5000, mulmod(mload(0x4c40), 22573484092096950280151461091492173066588738155952808584348937425179801521445, f_q))
mstore(0x5020, addmod(mload(0x4fe0), mload(0x5000), f_q))
mstore(0x5040, mulmod(mload(0x4ce0), 17799439645526593468527852005527707639891232191326421130080209212181800663685, f_q))
mstore(0x5060, addmod(mload(0x5020), mload(0x5040), f_q))
mstore(0x5080, mulmod(mload(0x4d80), 43072347715431875659722495403924484570295794297555905065846140476197612812033, f_q))
mstore(0x50a0, addmod(mload(0x5060), mload(0x5080), f_q))
mstore(0x50c0, mulmod(mload(0x4e20), 21762182386571606640672645248729054582240844218141454043565005480082460585677, f_q))
mstore(0x50e0, addmod(mload(0x50a0), mload(0x50c0), f_q))
mstore(0x5100, mulmod(mload(0x4ec0), 7179405695647424344643177657798954274869382720335107962712222495241823787551, f_q))
mstore(0x5120, addmod(mload(0x50e0), mload(0x5100), f_q))
mstore(0x5140, addmod(mload(0x36c0), mload(0x5120), f_q))
mstore(0x5160, addmod(mload(0x4f40), mload(0x5140), f_q))
mstore(0x5180, mulmod(mload(0x1980), mload(0x5160), f_q))
mstore(0x51a0, addmod(mload(0x2000), sub(f_q, mload(0x1e00)), f_q))
mstore(0x51c0, mulmod(mload(0x1da0), 42569072482279996318031820844820583094661593761988851871644829917446303682880, f_q))
mstore(0x51e0, mulmod(mload(0x1dc0), 48777675531739959342114240072267441286903816384223937749440830379544192657290, f_q))
mstore(0x5200, addmod(mload(0x51c0), mload(0x51e0), f_q))
mstore(0x5220, mulmod(mload(0x4ba0), 33286996086728685078854749126251163286167502628080690207063928367301359689947, f_q))
mstore(0x5240, addmod(mload(0x5200), mload(0x5220), f_q))
mstore(0x5260, addmod(mload(0x51a0), mload(0x5240), f_q))
mstore(0x5280, addmod(mload(0x5180), mload(0x5260), f_q))
mstore(0x52a0, mulmod(mload(0x1980), mload(0x5280), f_q))
mstore(0x52c0, addmod(mload(0x2020), sub(f_q, mload(0x1e20)), f_q))
mstore(0x52e0, mulmod(mload(0x1da0), 15460822173785725787510766083057066620988948322919030231014542645107533362369, f_q))
mstore(0x5300, mulmod(mload(0x1dc0), 17532068198837287192548063441235938928456800450058734482970684092419295703441, f_q))
mstore(0x5320, addmod(mload(0x52e0), mload(0x5300), f_q))
mstore(0x5340, mulmod(mload(0x4ba0), 30536090514433970940206888994283604712174418989908022047600262784049007297138, f_q))
mstore(0x5360, addmod(mload(0x5320), mload(0x5340), f_q))
mstore(0x5380, mulmod(mload(0x4c40), 33286996086728685078854749126251163286167502628080690207063928367301359689947, f_q))
mstore(0x53a0, addmod(mload(0x5360), mload(0x5380), f_q))
mstore(0x53c0, addmod(mload(0x52c0), mload(0x53a0), f_q))
mstore(0x53e0, addmod(mload(0x52a0), mload(0x53c0), f_q))
mstore(0x5400, mulmod(mload(0x1980), mload(0x53e0), f_q))
mstore(0x5420, addmod(mload(0x1f20), sub(f_q, mload(0x1ea0)), f_q))
mstore(0x5440, mulmod(mload(0x1da0), 51757916557095931492101637894700153753738985202877927051595743124655465049675, f_q))
mstore(0x5460, mulmod(mload(0x1dc0), 16513270875002105355154055214392863859886533828870466617169669632972895048992, f_q))
mstore(0x5480, addmod(mload(0x5440), mload(0x5460), f_q))
mstore(0x54a0, mulmod(mload(0x4ba0), 35426167520291240455001880880580845749581081201345737315527923196315309304361, f_q))
mstore(0x54c0, addmod(mload(0x5480), mload(0x54a0), f_q))
mstore(0x54e0, mulmod(mload(0x4c40), 30536090514433970940206888994283604712174418989908022047600262784049007297138, f_q))
mstore(0x5500, addmod(mload(0x54c0), mload(0x54e0), f_q))
mstore(0x5520, mulmod(mload(0x4ce0), 33286996086728685078854749126251163286167502628080690207063928367301359689947, f_q))
mstore(0x5540, addmod(mload(0x5500), mload(0x5520), f_q))
mstore(0x5560, addmod(mload(0x5420), mload(0x5540), f_q))
mstore(0x5580, addmod(mload(0x5400), mload(0x5560), f_q))
mstore(0x55a0, mulmod(mload(0x1980), mload(0x5580), f_q))
mstore(0x55c0, addmod(mload(0x1f40), sub(f_q, mload(0x1ec0)), f_q))
mstore(0x55e0, mulmod(mload(0x1da0), 21416013269199706780655207523311618433421828314385182423308221541654338163111, f_q))
mstore(0x5600, mulmod(mload(0x1dc0), 16124966132388516597090803080166171234527932877010453966457664182846667286567, f_q))
mstore(0x5620, addmod(mload(0x55e0), mload(0x5600), f_q))
mstore(0x5640, mulmod(mload(0x4ba0), 11536991632578856038169226946888068627873692153441762213164802460898458963278, f_q))
mstore(0x5660, addmod(mload(0x5620), mload(0x5640), f_q))
mstore(0x5680, mulmod(mload(0x4c40), 35426167520291240455001880880580845749581081201345737315527923196315309304361, f_q))
mstore(0x56a0, addmod(mload(0x5660), mload(0x5680), f_q))
mstore(0x56c0, mulmod(mload(0x4ce0), 30536090514433970940206888994283604712174418989908022047600262784049007297138, f_q))
mstore(0x56e0, addmod(mload(0x56a0), mload(0x56c0), f_q))
mstore(0x5700, mulmod(mload(0x4d80), 33286996086728685078854749126251163286167502628080690207063928367301359689947, f_q))
mstore(0x5720, addmod(mload(0x56e0), mload(0x5700), f_q))
mstore(0x5740, addmod(mload(0x55c0), mload(0x5720), f_q))
mstore(0x5760, addmod(mload(0x55a0), mload(0x5740), f_q))
mstore(0x5780, mulmod(mload(0x1980), mload(0x5760), f_q))
mstore(0x57a0, addmod(mload(0x1f60), sub(f_q, mload(0x1ee0)), f_q))
mstore(0x57c0, mulmod(mload(0x1da0), 49312067300773142348143637644007756944161175278464826357343119536320139437898, f_q))
mstore(0x57e0, mulmod(mload(0x1dc0), 18048464036633869753218556016152804134446546727997311594407968562256775743561, f_q))
mstore(0x5800, addmod(mload(0x57c0), mload(0x57e0), f_q))
mstore(0x5820, mulmod(mload(0x4ba0), 383932250696541742607310001569714138555014361290971921083431601725621863731, f_q))
mstore(0x5840, addmod(mload(0x5800), mload(0x5820), f_q))
mstore(0x5860, mulmod(mload(0x4c40), 11536991632578856038169226946888068627873692153441762213164802460898458963278, f_q))
mstore(0x5880, addmod(mload(0x5840), mload(0x5860), f_q))
mstore(0x58a0, mulmod(mload(0x4ce0), 35426167520291240455001880880580845749581081201345737315527923196315309304361, f_q))
mstore(0x58c0, addmod(mload(0x5880), mload(0x58a0), f_q))
mstore(0x58e0, mulmod(mload(0x4d80), 30536090514433970940206888994283604712174418989908022047600262784049007297138, f_q))
mstore(0x5900, addmod(mload(0x58c0), mload(0x58e0), f_q))
mstore(0x5920, mulmod(mload(0x4e20), 33286996086728685078854749126251163286167502628080690207063928367301359689947, f_q))
mstore(0x5940, addmod(mload(0x5900), mload(0x5920), f_q))
mstore(0x5960, addmod(mload(0x57a0), mload(0x5940), f_q))
mstore(0x5980, addmod(mload(0x5780), mload(0x5960), f_q))
mstore(0x59a0, mulmod(mload(0x1980), mload(0x5980), f_q))
mstore(0x59c0, addmod(mload(0x1f80), sub(f_q, mload(0x1e80)), f_q))
mstore(0x59e0, mulmod(mload(0x1da0), 51042352737684322926421982719448027244098131173912330356286361328735472870963, f_q))
mstore(0x5a00, mulmod(mload(0x1dc0), 29390124884714250559401457937586375728515143848012653816777731013221302010465, f_q))
mstore(0x5a20, addmod(mload(0x59e0), mload(0x5a00), f_q))
mstore(0x5a40, mulmod(mload(0x4ba0), 14193443826180214291995136727309819104154361382389237431794542473275951615294, f_q))
mstore(0x5a60, addmod(mload(0x5a20), mload(0x5a40), f_q))
mstore(0x5a80, mulmod(mload(0x4c40), 383932250696541742607310001569714138555014361290971921083431601725621863731, f_q))
mstore(0x5aa0, addmod(mload(0x5a60), mload(0x5a80), f_q))
mstore(0x5ac0, mulmod(mload(0x4ce0), 11536991632578856038169226946888068627873692153441762213164802460898458963278, f_q))
mstore(0x5ae0, addmod(mload(0x5aa0), mload(0x5ac0), f_q))
mstore(0x5b00, mulmod(mload(0x4d80), 35426167520291240455001880880580845749581081201345737315527923196315309304361, f_q))
mstore(0x5b20, addmod(mload(0x5ae0), mload(0x5b00), f_q))
mstore(0x5b40, mulmod(mload(0x4e20), 30536090514433970940206888994283604712174418989908022047600262784049007297138, f_q))
mstore(0x5b60, addmod(mload(0x5b20), mload(0x5b40), f_q))
mstore(0x5b80, mulmod(mload(0x4ec0), 33286996086728685078854749126251163286167502628080690207063928367301359689947, f_q))
mstore(0x5ba0, addmod(mload(0x5b60), mload(0x5b80), f_q))
mstore(0x5bc0, addmod(mload(0x59c0), mload(0x5ba0), f_q))
mstore(0x5be0, addmod(mload(0x59a0), mload(0x5bc0), f_q))
mstore(0x5c00, addmod(1, sub(f_q, mload(0x2140)), f_q))
mstore(0x5c20, mulmod(mload(0x2420), mload(0x5c00), f_q))
mstore(0x5c40, addmod(mload(0x5be0), sub(f_q, mload(0x5c20)), f_q))
mstore(0x5c60, addmod(mload(0x4b00), mload(0x5c40), f_q))
mstore(0x5ca0, 32)
mstore(0x5cc0, 32)
mstore(0x5ce0, 32)
mstore(0x5d00, mload(0x1d40))
mstore(0x5d20, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x5d40, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x5ca0, 0xc0, 0x5c80, 0x20), 1), success)
mstore(0x5d60, mulmod(mload(0x2860), mload(0x5c80), f_q))
mstore(0x5d80, mulmod(mload(0x5d60), mload(0x5d60), f_q))
mstore(0x5da0, mulmod(mload(0x5d80), mload(0x5d60), f_q))
mstore(0x5dc0, mulmod(mload(0x5da0), mload(0x5d60), f_q))
mstore(0x5de0, mulmod(1, mload(0x5d60), f_q))
mstore(0x5e00, mulmod(1, mload(0x5d80), f_q))
mstore(0x5e20, mulmod(1, mload(0x5da0), f_q))
mstore(0x5e40, mulmod(mload(0x5c60), mload(0x2880), f_q))
mstore(0x5e60, mulmod(mload(0x1d40), 1, f_q))
mstore(0x5e80, mulmod(mload(0x1d40), 31519469946562159605140591558550197856588417350474800936898404023113662197331, f_q))
mstore(0x5ea0, mulmod(mload(0x1d40), 21259823323969146045885553965890482219221908228759787200404479960115227367690, f_q))
mstore(0x5ec0, mulmod(mload(0x1d40), 45254319123522011116259460062854627366454101350769349111320208945036885998124, f_q))
mstore(0x5ee0, mulmod(mload(0x2460), mload(0x2460), f_q))
mstore(0x5f00, mulmod(mload(0x5ee0), mload(0x2460), f_q))
mstore(0x5f20, mulmod(mload(0x5f00), mload(0x2460), f_q))
mstore(0x5f40, mulmod(mload(0x5f20), mload(0x2460), f_q))
mstore(0x5f60, mulmod(mload(0x5f40), mload(0x2460), f_q))
mstore(0x5f80, mulmod(mload(0x5f60), mload(0x2460), f_q))
mstore(0x5fa0, mulmod(mload(0x5f80), mload(0x2460), f_q))
mstore(0x5fc0, mulmod(mload(0x5fa0), mload(0x2460), f_q))
mstore(0x5fe0, mulmod(mload(0x5fc0), mload(0x2460), f_q))
mstore(0x6000, mulmod(mload(0x5fe0), mload(0x2460), f_q))
mstore(0x6020, mulmod(mload(0x6000), mload(0x2460), f_q))
mstore(0x6040, mulmod(mload(0x6020), mload(0x2460), f_q))
mstore(0x6060, mulmod(mload(0x6040), mload(0x2460), f_q))
mstore(0x6080, mulmod(mload(0x6060), mload(0x2460), f_q))
mstore(0x60a0, mulmod(mload(0x6080), mload(0x2460), f_q))
mstore(0x60c0, mulmod(mload(0x60a0), mload(0x2460), f_q))
mstore(0x60e0, mulmod(mload(0x60c0), mload(0x2460), f_q))
mstore(0x6100, mulmod(mload(0x60e0), mload(0x2460), f_q))
mstore(0x6120, mulmod(mload(0x6100), mload(0x2460), f_q))
mstore(0x6140, mulmod(mload(0x6120), mload(0x2460), f_q))
mstore(0x6160, mulmod(mload(0x6140), mload(0x2460), f_q))
mstore(0x6180, mulmod(mload(0x6160), mload(0x2460), f_q))
mstore(0x61a0, mulmod(mload(0x6180), mload(0x2460), f_q))
mstore(0x61c0, mulmod(mload(0x61a0), mload(0x2460), f_q))
mstore(0x61e0, mulmod(mload(0x61c0), mload(0x2460), f_q))
mstore(0x6200, mulmod(mload(0x61e0), mload(0x2460), f_q))
mstore(0x6220, mulmod(mload(0x6200), mload(0x2460), f_q))
mstore(0x6240, mulmod(mload(0x6220), mload(0x2460), f_q))
mstore(0x6260, mulmod(mload(0x6240), mload(0x2460), f_q))
mstore(0x6280, mulmod(mload(0x6260), mload(0x2460), f_q))
mstore(0x62a0, mulmod(mload(0x6280), mload(0x2460), f_q))
mstore(0x62c0, mulmod(mload(0x62a0), mload(0x2460), f_q))
mstore(0x62e0, mulmod(mload(0x62c0), mload(0x2460), f_q))
mstore(0x6300, mulmod(mload(0x62e0), mload(0x2460), f_q))
mstore(0x6320, mulmod(mload(0x6300), mload(0x2460), f_q))
mstore(0x6340, mulmod(mload(0x6320), mload(0x2460), f_q))
mstore(0x6360, mulmod(1, mload(0x2460), f_q))
mstore(0x6380, mulmod(1, mload(0x5ee0), f_q))
mstore(0x63a0, mulmod(1, mload(0x5f00), f_q))
mstore(0x63c0, mulmod(1, mload(0x5f20), f_q))
mstore(0x63e0, mulmod(1, mload(0x5f40), f_q))
mstore(0x6400, mulmod(1, mload(0x5f60), f_q))
mstore(0x6420, mulmod(1, mload(0x5f80), f_q))
mstore(0x6440, mulmod(1, mload(0x5fa0), f_q))
mstore(0x6460, mulmod(1, mload(0x5fc0), f_q))
mstore(0x6480, mulmod(1, mload(0x5fe0), f_q))
mstore(0x64a0, mulmod(1, mload(0x6000), f_q))
mstore(0x64c0, mulmod(1, mload(0x6020), f_q))
mstore(0x64e0, mulmod(1, mload(0x6040), f_q))
mstore(0x6500, mulmod(1, mload(0x6060), f_q))
mstore(0x6520, mulmod(1, mload(0x6080), f_q))
mstore(0x6540, mulmod(1, mload(0x60a0), f_q))
mstore(0x6560, mulmod(1, mload(0x60c0), f_q))
mstore(0x6580, mulmod(1, mload(0x60e0), f_q))
mstore(0x65a0, mulmod(1, mload(0x6100), f_q))
mstore(0x65c0, mulmod(1, mload(0x6120), f_q))
mstore(0x65e0, mulmod(1, mload(0x6140), f_q))
mstore(0x6600, mulmod(1, mload(0x6160), f_q))
mstore(0x6620, mulmod(1, mload(0x6180), f_q))
mstore(0x6640, mulmod(1, mload(0x61a0), f_q))
mstore(0x6660, mulmod(1, mload(0x61c0), f_q))
mstore(0x6680, mulmod(1, mload(0x61e0), f_q))
mstore(0x66a0, mulmod(1, mload(0x6200), f_q))
mstore(0x66c0, mulmod(1, mload(0x6220), f_q))
mstore(0x66e0, mulmod(1, mload(0x6240), f_q))
mstore(0x6700, mulmod(1, mload(0x6260), f_q))
mstore(0x6720, mulmod(1, mload(0x6280), f_q))
mstore(0x6740, mulmod(1, mload(0x62a0), f_q))
mstore(0x6760, mulmod(1, mload(0x62c0), f_q))
mstore(0x6780, mulmod(1, mload(0x62e0), f_q))
mstore(0x67a0, mulmod(1, mload(0x6300), f_q))
mstore(0x67c0, mulmod(mload(0x5de0), mload(0x6300), f_q))
mstore(0x67e0, mulmod(mload(0x5e00), mload(0x6300), f_q))
mstore(0x6800, mulmod(mload(0x5e20), mload(0x6300), f_q))
mstore(0x6820, mulmod(1, mload(0x6320), f_q))
mstore(0x6840, mulmod(mload(0x1d80), 1, f_q))
mstore(0x6860, addmod(0, mload(0x6840), f_q))
mstore(0x6880, mulmod(mload(0x1e00), mload(0x2460), f_q))
mstore(0x68a0, addmod(mload(0x6860), mload(0x6880), f_q))
mstore(0x68c0, mulmod(mload(0x1e20), mload(0x5ee0), f_q))
mstore(0x68e0, addmod(mload(0x68a0), mload(0x68c0), f_q))
mstore(0x6900, mulmod(mload(0x1ea0), mload(0x5f00), f_q))
mstore(0x6920, addmod(mload(0x68e0), mload(0x6900), f_q))
mstore(0x6940, mulmod(mload(0x1ec0), mload(0x5f20), f_q))
mstore(0x6960, addmod(mload(0x6920), mload(0x6940), f_q))
mstore(0x6980, mulmod(mload(0x1ee0), mload(0x5f40), f_q))
mstore(0x69a0, addmod(mload(0x6960), mload(0x6980), f_q))
mstore(0x69c0, mulmod(mload(0x2400), mload(0x5f60), f_q))
mstore(0x69e0, addmod(mload(0x69a0), mload(0x69c0), f_q))
mstore(0x6a00, mulmod(mload(0x2420), mload(0x5f80), f_q))
mstore(0x6a20, addmod(mload(0x69e0), mload(0x6a00), f_q))
mstore(0x6a40, mulmod(mload(0x1f00), mload(0x5fa0), f_q))
mstore(0x6a60, addmod(mload(0x6a20), mload(0x6a40), f_q))
mstore(0x6a80, mulmod(mload(0x1f20), mload(0x5fc0), f_q))
mstore(0x6aa0, addmod(mload(0x6a60), mload(0x6a80), f_q))
mstore(0x6ac0, mulmod(mload(0x1f40), mload(0x5fe0), f_q))
mstore(0x6ae0, addmod(mload(0x6aa0), mload(0x6ac0), f_q))
mstore(0x6b00, mulmod(mload(0x1f60), mload(0x6000), f_q))
mstore(0x6b20, addmod(mload(0x6ae0), mload(0x6b00), f_q))
mstore(0x6b40, mulmod(mload(0x1f80), mload(0x6020), f_q))
mstore(0x6b60, addmod(mload(0x6b20), mload(0x6b40), f_q))
mstore(0x6b80, mulmod(mload(0x1fa0), mload(0x6040), f_q))
mstore(0x6ba0, addmod(mload(0x6b60), mload(0x6b80), f_q))
mstore(0x6bc0, mulmod(mload(0x1fc0), mload(0x6060), f_q))
mstore(0x6be0, addmod(mload(0x6ba0), mload(0x6bc0), f_q))
mstore(0x6c00, mulmod(mload(0x1fe0), mload(0x6080), f_q))
mstore(0x6c20, addmod(mload(0x6be0), mload(0x6c00), f_q))
mstore(0x6c40, mulmod(mload(0x2000), mload(0x60a0), f_q))
mstore(0x6c60, addmod(mload(0x6c20), mload(0x6c40), f_q))
mstore(0x6c80, mulmod(mload(0x2020), mload(0x60c0), f_q))
mstore(0x6ca0, addmod(mload(0x6c60), mload(0x6c80), f_q))
mstore(0x6cc0, mulmod(mload(0x2040), mload(0x60e0), f_q))
mstore(0x6ce0, addmod(mload(0x6ca0), mload(0x6cc0), f_q))
mstore(0x6d00, mulmod(mload(0x2060), mload(0x6100), f_q))
mstore(0x6d20, addmod(mload(0x6ce0), mload(0x6d00), f_q))
mstore(0x6d40, mulmod(mload(0x2080), mload(0x6120), f_q))
mstore(0x6d60, addmod(mload(0x6d20), mload(0x6d40), f_q))
mstore(0x6d80, mulmod(mload(0x20a0), mload(0x6140), f_q))
mstore(0x6da0, addmod(mload(0x6d60), mload(0x6d80), f_q))
mstore(0x6dc0, mulmod(mload(0x20c0), mload(0x6160), f_q))
mstore(0x6de0, addmod(mload(0x6da0), mload(0x6dc0), f_q))
mstore(0x6e00, mulmod(mload(0x20e0), mload(0x6180), f_q))
mstore(0x6e20, addmod(mload(0x6de0), mload(0x6e00), f_q))
mstore(0x6e40, mulmod(mload(0x2100), mload(0x61a0), f_q))
mstore(0x6e60, addmod(mload(0x6e20), mload(0x6e40), f_q))
mstore(0x6e80, mulmod(mload(0x2120), mload(0x61c0), f_q))
mstore(0x6ea0, addmod(mload(0x6e60), mload(0x6e80), f_q))
mstore(0x6ec0, mulmod(mload(0x2140), mload(0x61e0), f_q))
mstore(0x6ee0, addmod(mload(0x6ea0), mload(0x6ec0), f_q))
mstore(0x6f00, mulmod(mload(0x2180), mload(0x6200), f_q))
mstore(0x6f20, addmod(mload(0x6ee0), mload(0x6f00), f_q))
mstore(0x6f40, mulmod(mload(0x21a0), mload(0x6220), f_q))
mstore(0x6f60, addmod(mload(0x6f20), mload(0x6f40), f_q))
mstore(0x6f80, mulmod(mload(0x21c0), mload(0x6240), f_q))
mstore(0x6fa0, addmod(mload(0x6f60), mload(0x6f80), f_q))
mstore(0x6fc0, mulmod(mload(0x21e0), mload(0x6260), f_q))
mstore(0x6fe0, addmod(mload(0x6fa0), mload(0x6fc0), f_q))
mstore(0x7000, mulmod(mload(0x2200), mload(0x6280), f_q))
mstore(0x7020, addmod(mload(0x6fe0), mload(0x7000), f_q))
mstore(0x7040, mulmod(mload(0x2220), mload(0x62a0), f_q))
mstore(0x7060, addmod(mload(0x7020), mload(0x7040), f_q))
mstore(0x7080, mulmod(mload(0x2240), mload(0x62c0), f_q))
mstore(0x70a0, addmod(mload(0x7060), mload(0x7080), f_q))
mstore(0x70c0, mulmod(mload(0x2260), mload(0x62e0), f_q))
mstore(0x70e0, addmod(mload(0x70a0), mload(0x70c0), f_q))
mstore(0x7100, mulmod(mload(0x5e40), mload(0x6300), f_q))
mstore(0x7120, addmod(mload(0x70e0), mload(0x7100), f_q))
mstore(0x7140, mulmod(mload(0x2160), mload(0x6320), f_q))
mstore(0x7160, addmod(mload(0x7120), mload(0x7140), f_q))
mstore(0x7180, mulmod(mload(0x1da0), 1, f_q))
mstore(0x71a0, addmod(0, mload(0x7180), f_q))
mstore(0x71c0, mulmod(mload(0x1e40), 1, f_q))
mstore(0x71e0, addmod(0, mload(0x71c0), f_q))
mstore(0x7200, mulmod(mload(0x1dc0), mload(0x2460), f_q))
mstore(0x7220, addmod(mload(0x71a0), mload(0x7200), f_q))
mstore(0x7240, mulmod(mload(0x1e60), mload(0x2460), f_q))
mstore(0x7260, addmod(mload(0x71e0), mload(0x7240), f_q))
mstore(0x7280, mulmod(mload(0x1de0), mload(0x5ee0), f_q))
mstore(0x72a0, addmod(mload(0x7220), mload(0x7280), f_q))
mstore(0x72c0, mulmod(mload(0x1e80), mload(0x5ee0), f_q))
mstore(0x72e0, addmod(mload(0x7260), mload(0x72c0), f_q))
mstore(0x7300, mulmod(mload(0x2340), mload(0x5f00), f_q))
mstore(0x7320, addmod(mload(0x72a0), mload(0x7300), f_q))
mstore(0x7340, mulmod(mload(0x2360), mload(0x5f00), f_q))
mstore(0x7360, addmod(mload(0x72e0), mload(0x7340), f_q))
mstore(0x7380, mulmod(mload(0x2380), mload(0x5f20), f_q))
mstore(0x73a0, addmod(mload(0x7320), mload(0x7380), f_q))
mstore(0x73c0, mulmod(mload(0x23a0), mload(0x5f20), f_q))
mstore(0x73e0, addmod(mload(0x7360), mload(0x73c0), f_q))
mstore(0x7400, mulmod(mload(0x2280), 1, f_q))
mstore(0x7420, addmod(0, mload(0x7400), f_q))
mstore(0x7440, mulmod(mload(0x22a0), 1, f_q))
mstore(0x7460, addmod(0, mload(0x7440), f_q))
mstore(0x7480, mulmod(mload(0x22c0), 1, f_q))
mstore(0x74a0, addmod(0, mload(0x7480), f_q))
mstore(0x74c0, mulmod(mload(0x22e0), mload(0x2460), f_q))
mstore(0x74e0, addmod(mload(0x7420), mload(0x74c0), f_q))
mstore(0x7500, mulmod(mload(0x2300), mload(0x2460), f_q))
mstore(0x7520, addmod(mload(0x7460), mload(0x7500), f_q))
mstore(0x7540, mulmod(mload(0x2320), mload(0x2460), f_q))
mstore(0x7560, addmod(mload(0x74a0), mload(0x7540), f_q))
mstore(0x7580, mulmod(mload(0x23c0), 1, f_q))
mstore(0x75a0, addmod(0, mload(0x7580), f_q))
mstore(0x75c0, mulmod(mload(0x23e0), 1, f_q))
mstore(0x75e0, addmod(0, mload(0x75c0), f_q))
mstore(0x7600, addmod(mload(0x5e60), sub(f_q, mload(0x5ec0)), f_q))
mstore(0x7620, mulmod(1, mload(0x7600), f_q))
mstore(0x7640, addmod(mload(0x5ec0), sub(f_q, mload(0x5e60)), f_q))
mstore(0x7660, mulmod(1, mload(0x7640), f_q))
{
            let prod := mload(0x7620)

                prod := mulmod(mload(0x7660), prod, f_q)
                mstore(0x7680, prod)
            
        }
mstore(0x76c0, 32)
mstore(0x76e0, 32)
mstore(0x7700, 32)
mstore(0x7720, mload(0x7680))
mstore(0x7740, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x7760, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x76c0, 0xc0, 0x76a0, 0x20), 1), success)
{
            
            let inv := mload(0x76a0)
            let v
        
                    v := mload(0x7660)
                    mstore(30304, mulmod(mload(0x7620), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x7620, inv)

        }
mstore(0x7780, addmod(mload(0x25a0), sub(f_q, mload(0x5ec0)), f_q))
mstore(0x77a0, mulmod(1, mload(0x7780), f_q))
mstore(0x77c0, mulmod(mload(0x75a0), mload(0x77a0), f_q))
mstore(0x77e0, mulmod(mload(0x77c0), mload(0x7620), f_q))
mstore(0x7800, addmod(0, mload(0x77e0), f_q))
mstore(0x7820, addmod(mload(0x25a0), sub(f_q, mload(0x5e60)), f_q))
mstore(0x7840, mulmod(1, mload(0x7820), f_q))
mstore(0x7860, mulmod(mload(0x75e0), mload(0x7840), f_q))
mstore(0x7880, mulmod(mload(0x7860), mload(0x7660), f_q))
mstore(0x78a0, addmod(mload(0x7800), mload(0x7880), f_q))
mstore(0x78c0, mulmod(mload(0x7840), mload(0x7780), f_q))
mstore(0x7900, 32)
mstore(0x7920, 32)
mstore(0x7940, 32)
mstore(0x7960, mload(0x78c0))
mstore(0x7980, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x79a0, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x7900, 0xc0, 0x78e0, 0x20), 1), success)
mstore(0x79c0, addmod(mload(0x2640), sub(f_q, mload(0x78a0)), f_q))
mstore(0x79e0, mulmod(mload(0x79c0), mload(0x78e0), f_q))
mstore(0x7a00, mulmod(0, mload(0x24c0), f_q))
mstore(0x7a20, addmod(mload(0x7a00), mload(0x79e0), f_q))
mstore(0x7a40, addmod(mload(0x5e60), sub(f_q, mload(0x5e80)), f_q))
mstore(0x7a60, mulmod(1, mload(0x7a40), f_q))
mstore(0x7a80, addmod(mload(0x5e60), sub(f_q, mload(0x5ea0)), f_q))
mstore(0x7aa0, mulmod(mload(0x7a60), mload(0x7a80), f_q))
mstore(0x7ac0, addmod(mload(0x5e80), sub(f_q, mload(0x5e60)), f_q))
mstore(0x7ae0, mulmod(1, mload(0x7ac0), f_q))
mstore(0x7b00, addmod(mload(0x5e80), sub(f_q, mload(0x5ea0)), f_q))
mstore(0x7b20, mulmod(mload(0x7ae0), mload(0x7b00), f_q))
mstore(0x7b40, addmod(mload(0x5ea0), sub(f_q, mload(0x5e60)), f_q))
mstore(0x7b60, mulmod(1, mload(0x7b40), f_q))
mstore(0x7b80, addmod(mload(0x5ea0), sub(f_q, mload(0x5e80)), f_q))
mstore(0x7ba0, mulmod(mload(0x7b60), mload(0x7b80), f_q))
{
            let prod := mload(0x7aa0)

                prod := mulmod(mload(0x7b20), prod, f_q)
                mstore(0x7bc0, prod)
            
                prod := mulmod(mload(0x7ba0), prod, f_q)
                mstore(0x7be0, prod)
            
        }
mstore(0x7c20, 32)
mstore(0x7c40, 32)
mstore(0x7c60, 32)
mstore(0x7c80, mload(0x7be0))
mstore(0x7ca0, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x7cc0, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x7c20, 0xc0, 0x7c00, 0x20), 1), success)
{
            
            let inv := mload(0x7c00)
            let v
        
                    v := mload(0x7ba0)
                    mstore(31648, mulmod(mload(0x7bc0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x7b20)
                    mstore(31520, mulmod(mload(0x7aa0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x7aa0, inv)

        }
mstore(0x7ce0, addmod(mload(0x25a0), sub(f_q, mload(0x5e80)), f_q))
mstore(0x7d00, mulmod(1, mload(0x7ce0), f_q))
mstore(0x7d20, addmod(mload(0x25a0), sub(f_q, mload(0x5ea0)), f_q))
mstore(0x7d40, mulmod(mload(0x7d00), mload(0x7d20), f_q))
mstore(0x7d60, mulmod(mload(0x74e0), mload(0x7d40), f_q))
mstore(0x7d80, mulmod(mload(0x7d60), mload(0x7aa0), f_q))
mstore(0x7da0, addmod(0, mload(0x7d80), f_q))
mstore(0x7dc0, mulmod(mload(0x7840), mload(0x7d20), f_q))
mstore(0x7de0, mulmod(mload(0x7520), mload(0x7dc0), f_q))
mstore(0x7e00, mulmod(mload(0x7de0), mload(0x7b20), f_q))
mstore(0x7e20, addmod(mload(0x7da0), mload(0x7e00), f_q))
mstore(0x7e40, mulmod(mload(0x7840), mload(0x7ce0), f_q))
mstore(0x7e60, mulmod(mload(0x7560), mload(0x7e40), f_q))
mstore(0x7e80, mulmod(mload(0x7e60), mload(0x7ba0), f_q))
mstore(0x7ea0, addmod(mload(0x7e20), mload(0x7e80), f_q))
mstore(0x7ec0, mulmod(mload(0x7e40), mload(0x7d20), f_q))
mstore(0x7f00, 32)
mstore(0x7f20, 32)
mstore(0x7f40, 32)
mstore(0x7f60, mload(0x7ec0))
mstore(0x7f80, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x7fa0, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x7f00, 0xc0, 0x7ee0, 0x20), 1), success)
mstore(0x7fc0, addmod(mload(0x2620), sub(f_q, mload(0x7ea0)), f_q))
mstore(0x7fe0, mulmod(mload(0x7fc0), mload(0x7ee0), f_q))
mstore(0x8000, mulmod(mload(0x7a20), mload(0x24c0), f_q))
mstore(0x8020, addmod(mload(0x8000), mload(0x7fe0), f_q))
{
            let prod := mload(0x7a60)

                prod := mulmod(mload(0x7ae0), prod, f_q)
                mstore(0x8040, prod)
            
        }
mstore(0x8080, 32)
mstore(0x80a0, 32)
mstore(0x80c0, 32)
mstore(0x80e0, mload(0x8040))
mstore(0x8100, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x8120, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x8080, 0xc0, 0x8060, 0x20), 1), success)
{
            
            let inv := mload(0x8060)
            let v
        
                    v := mload(0x7ae0)
                    mstore(31456, mulmod(mload(0x7a60), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x7a60, inv)

        }
mstore(0x8140, mulmod(mload(0x73a0), mload(0x7d00), f_q))
mstore(0x8160, mulmod(mload(0x8140), mload(0x7a60), f_q))
mstore(0x8180, addmod(0, mload(0x8160), f_q))
mstore(0x81a0, mulmod(mload(0x73e0), mload(0x7840), f_q))
mstore(0x81c0, mulmod(mload(0x81a0), mload(0x7ae0), f_q))
mstore(0x81e0, addmod(mload(0x8180), mload(0x81c0), f_q))
mstore(0x8220, 32)
mstore(0x8240, 32)
mstore(0x8260, 32)
mstore(0x8280, mload(0x7e40))
mstore(0x82a0, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x82c0, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x8220, 0xc0, 0x8200, 0x20), 1), success)
mstore(0x82e0, addmod(mload(0x2600), sub(f_q, mload(0x81e0)), f_q))
mstore(0x8300, mulmod(mload(0x82e0), mload(0x8200), f_q))
mstore(0x8320, mulmod(mload(0x8020), mload(0x24c0), f_q))
mstore(0x8340, addmod(mload(0x8320), mload(0x8300), f_q))
mstore(0x8380, 32)
mstore(0x83a0, 32)
mstore(0x83c0, 32)
mstore(0x83e0, mload(0x7840))
mstore(0x8400, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x8420, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x8380, 0xc0, 0x8360, 0x20), 1), success)
mstore(0x8440, addmod(mload(0x25e0), sub(f_q, mload(0x7160)), f_q))
mstore(0x8460, mulmod(mload(0x8440), mload(0x8360), f_q))
mstore(0x8480, mulmod(mload(0x8340), mload(0x24c0), f_q))
mstore(0x84a0, addmod(mload(0x8480), mload(0x8460), f_q))
mstore(0x84c0, mulmod(mload(0x2680), mload(0x2680), f_q))
mstore(0x84e0, mulmod(mload(0x84c0), mload(0x2680), f_q))
mstore(0x8500, mulmod(mload(0x84e0), mload(0x2680), f_q))
mstore(0x8520, mulmod(mload(0x8500), mload(0x2680), f_q))
mstore(0x8540, mulmod(mload(0x6360), 1, f_q))
mstore(0x8560, mulmod(mload(0x6380), 1, f_q))
mstore(0x8580, mulmod(mload(0x63a0), 1, f_q))
mstore(0x85a0, mulmod(mload(0x63c0), 1, f_q))
mstore(0x85c0, mulmod(mload(0x63e0), 1, f_q))
mstore(0x85e0, mulmod(mload(0x6400), 1, f_q))
mstore(0x8600, mulmod(mload(0x6420), 1, f_q))
mstore(0x8620, mulmod(mload(0x6440), 1, f_q))
mstore(0x8640, mulmod(mload(0x6460), 1, f_q))
mstore(0x8660, mulmod(mload(0x6480), 1, f_q))
mstore(0x8680, mulmod(mload(0x64a0), 1, f_q))
mstore(0x86a0, mulmod(mload(0x64c0), 1, f_q))
mstore(0x86c0, mulmod(mload(0x64e0), 1, f_q))
mstore(0x86e0, mulmod(mload(0x6500), 1, f_q))
mstore(0x8700, mulmod(mload(0x6520), 1, f_q))
mstore(0x8720, mulmod(mload(0x6540), 1, f_q))
mstore(0x8740, mulmod(mload(0x6560), 1, f_q))
mstore(0x8760, mulmod(mload(0x6580), 1, f_q))
mstore(0x8780, mulmod(mload(0x65a0), 1, f_q))
mstore(0x87a0, mulmod(mload(0x65c0), 1, f_q))
mstore(0x87c0, mulmod(mload(0x65e0), 1, f_q))
mstore(0x87e0, mulmod(mload(0x6600), 1, f_q))
mstore(0x8800, mulmod(mload(0x6620), 1, f_q))
mstore(0x8820, mulmod(mload(0x6640), 1, f_q))
mstore(0x8840, mulmod(mload(0x6660), 1, f_q))
mstore(0x8860, mulmod(mload(0x6680), 1, f_q))
mstore(0x8880, mulmod(mload(0x66a0), 1, f_q))
mstore(0x88a0, mulmod(mload(0x66c0), 1, f_q))
mstore(0x88c0, mulmod(mload(0x66e0), 1, f_q))
mstore(0x88e0, mulmod(mload(0x6700), 1, f_q))
mstore(0x8900, mulmod(mload(0x6720), 1, f_q))
mstore(0x8920, mulmod(mload(0x6740), 1, f_q))
mstore(0x8940, mulmod(mload(0x6760), 1, f_q))
mstore(0x8960, mulmod(mload(0x6780), 1, f_q))
mstore(0x8980, mulmod(mload(0x67a0), 1, f_q))
mstore(0x89a0, mulmod(mload(0x67c0), 1, f_q))
mstore(0x89c0, mulmod(mload(0x67e0), 1, f_q))
mstore(0x89e0, mulmod(mload(0x6800), 1, f_q))
mstore(0x8a00, mulmod(mload(0x6820), 1, f_q))
mstore(0x8a20, mulmod(1, mload(0x2680), f_q))
mstore(0x8a40, mulmod(mload(0x6360), mload(0x2680), f_q))
mstore(0x8a60, mulmod(mload(0x6380), mload(0x2680), f_q))
mstore(0x8a80, mulmod(mload(0x63a0), mload(0x2680), f_q))
mstore(0x8aa0, mulmod(mload(0x63c0), mload(0x2680), f_q))
mstore(0x8ac0, mulmod(1, mload(0x84c0), f_q))
mstore(0x8ae0, mulmod(mload(0x6360), mload(0x84c0), f_q))
mstore(0x8b00, mulmod(1, mload(0x84e0), f_q))
mstore(0x8b20, mulmod(1, mload(0x8500), f_q))
mstore(0x8b40, mulmod(mload(0x25e0), 1, f_q))
mstore(0x8b60, addmod(0, mload(0x8b40), f_q))
mstore(0x8b80, mulmod(mload(0x2600), mload(0x2680), f_q))
mstore(0x8ba0, addmod(mload(0x8b60), mload(0x8b80), f_q))
mstore(0x8bc0, mulmod(mload(0x2620), mload(0x84c0), f_q))
mstore(0x8be0, addmod(mload(0x8ba0), mload(0x8bc0), f_q))
mstore(0x8c00, mulmod(mload(0x2640), mload(0x84e0), f_q))
mstore(0x8c20, addmod(mload(0x8be0), mload(0x8c00), f_q))
mstore(0x8c40, mulmod(mload(0x84a0), mload(0x8500), f_q))
mstore(0x8c60, addmod(mload(0x8c20), mload(0x8c40), f_q))
mstore(0x8c80, mulmod(1, mload(0x25a0), f_q))
mstore(0x8ca0, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f)
mstore(0x8cc0, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)
mstore(0x8ce0, 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4)
mstore(0x8d00, 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
{
                            mstore(0x8d20, mload(0x8ca0))
mstore(0x8d40, mload(0x8cc0))
mstore(0x8d60, mload(0x8ce0))
mstore(0x8d80, mload(0x8d00))
                        }
mstore(0x8da0, sub(f_q, mload(0x8c60)))
{
                            mstore(0x8dc0, mload(0xfc0))
mstore(0x8de0, mload(0xfe0))
mstore(0x8e00, mload(0x1000))
mstore(0x8e20, mload(0x1020))
                        }
mstore(0x8e40, 1)
{
                            mstore(0x8e60, mload(0x12c0))
mstore(0x8e80, mload(0x12e0))
mstore(0x8ea0, mload(0x1300))
mstore(0x8ec0, mload(0x1320))
                        }
mstore(0x8ee0, mload(0x8540))
{
                            mstore(0x8f00, mload(0x1340))
mstore(0x8f20, mload(0x1360))
mstore(0x8f40, mload(0x1380))
mstore(0x8f60, mload(0x13a0))
                        }
mstore(0x8f80, mload(0x8560))
{
                            mstore(0x8fa0, mload(0x13c0))
mstore(0x8fc0, mload(0x13e0))
mstore(0x8fe0, mload(0x1400))
mstore(0x9000, mload(0x1420))
                        }
mstore(0x9020, mload(0x8580))
{
                            mstore(0x9040, mload(0x1440))
mstore(0x9060, mload(0x1460))
mstore(0x9080, mload(0x1480))
mstore(0x90a0, mload(0x14a0))
                        }
mstore(0x90c0, mload(0x85a0))
{
                            mstore(0x90e0, mload(0x14c0))
mstore(0x9100, mload(0x14e0))
mstore(0x9120, mload(0x1500))
mstore(0x9140, mload(0x1520))
                        }
mstore(0x9160, mload(0x85c0))
{
                            mstore(0x9180, mload(0x1620))
mstore(0x91a0, mload(0x1640))
mstore(0x91c0, mload(0x1660))
mstore(0x91e0, mload(0x1680))
                        }
mstore(0x9200, mload(0x85e0))
{
                            mstore(0x9220, mload(0x19c0))
mstore(0x9240, mload(0x19e0))
mstore(0x9260, mload(0x1a00))
mstore(0x9280, mload(0x1a20))
                        }
mstore(0x92a0, mload(0x8600))
{
                            mstore(0x92c0, mload(0x6a0))
mstore(0x92e0, mload(0x6c0))
mstore(0x9300, mload(0x6e0))
mstore(0x9320, mload(0x700))
                        }
mstore(0x9340, mload(0x8620))
{
                            mstore(0x9360, mload(0x420))
mstore(0x9380, mload(0x440))
mstore(0x93a0, mload(0x460))
mstore(0x93c0, mload(0x480))
                        }
mstore(0x93e0, mload(0x8640))
{
                            mstore(0x9400, mload(0x4a0))
mstore(0x9420, mload(0x4c0))
mstore(0x9440, mload(0x4e0))
mstore(0x9460, mload(0x500))
                        }
mstore(0x9480, mload(0x8660))
{
                            mstore(0x94a0, mload(0x520))
mstore(0x94c0, mload(0x540))
mstore(0x94e0, mload(0x560))
mstore(0x9500, mload(0x580))
                        }
mstore(0x9520, mload(0x8680))
{
                            mstore(0x9540, mload(0x5a0))
mstore(0x9560, mload(0x5c0))
mstore(0x9580, mload(0x5e0))
mstore(0x95a0, mload(0x600))
                        }
mstore(0x95c0, mload(0x86a0))
{
                            mstore(0x95e0, mload(0x620))
mstore(0x9600, mload(0x640))
mstore(0x9620, mload(0x660))
mstore(0x9640, mload(0x680))
                        }
mstore(0x9660, mload(0x86c0))
{
                            mstore(0x9680, mload(0x220))
mstore(0x96a0, mload(0x240))
mstore(0x96c0, mload(0x260))
mstore(0x96e0, mload(0x280))
                        }
mstore(0x9700, mload(0x86e0))
{
                            mstore(0x9720, mload(0x2a0))
mstore(0x9740, mload(0x2c0))
mstore(0x9760, mload(0x2e0))
mstore(0x9780, mload(0x300))
                        }
mstore(0x97a0, mload(0x8700))
{
                            mstore(0x97c0, mload(0x320))
mstore(0x97e0, mload(0x340))
mstore(0x9800, mload(0x360))
mstore(0x9820, mload(0x380))
                        }
mstore(0x9840, mload(0x8720))
{
                            mstore(0x9860, mload(0x3a0))
mstore(0x9880, mload(0x3c0))
mstore(0x98a0, mload(0x3e0))
mstore(0x98c0, mload(0x400))
                        }
mstore(0x98e0, mload(0x8740))
{
                            mstore(0x9900, mload(0x720))
mstore(0x9920, mload(0x740))
mstore(0x9940, mload(0x760))
mstore(0x9960, mload(0x780))
                        }
mstore(0x9980, mload(0x8760))
{
                            mstore(0x99a0, mload(0x7a0))
mstore(0x99c0, mload(0x7c0))
mstore(0x99e0, mload(0x7e0))
mstore(0x9a00, mload(0x800))
                        }
mstore(0x9a20, mload(0x8780))
{
                            mstore(0x9a40, mload(0x820))
mstore(0x9a60, mload(0x840))
mstore(0x9a80, mload(0x860))
mstore(0x9aa0, mload(0x880))
                        }
mstore(0x9ac0, mload(0x87a0))
{
                            mstore(0x9ae0, mload(0x8a0))
mstore(0x9b00, mload(0x8c0))
mstore(0x9b20, mload(0x8e0))
mstore(0x9b40, mload(0x900))
                        }
mstore(0x9b60, mload(0x87c0))
{
                            mstore(0x9b80, mload(0x920))
mstore(0x9ba0, mload(0x940))
mstore(0x9bc0, mload(0x960))
mstore(0x9be0, mload(0x980))
                        }
mstore(0x9c00, mload(0x87e0))
{
                            mstore(0x9c20, mload(0x9a0))
mstore(0x9c40, mload(0x9c0))
mstore(0x9c60, mload(0x9e0))
mstore(0x9c80, mload(0xa00))
                        }
mstore(0x9ca0, mload(0x8800))
{
                            mstore(0x9cc0, mload(0xa20))
mstore(0x9ce0, mload(0xa40))
mstore(0x9d00, mload(0xa60))
mstore(0x9d20, mload(0xa80))
                        }
mstore(0x9d40, mload(0x8820))
{
                            mstore(0x9d60, mload(0xaa0))
mstore(0x9d80, mload(0xac0))
mstore(0x9da0, mload(0xae0))
mstore(0x9dc0, mload(0xb00))
                        }
mstore(0x9de0, mload(0x8840))
{
                            mstore(0x9e00, mload(0xb20))
mstore(0x9e20, mload(0xb40))
mstore(0x9e40, mload(0xb60))
mstore(0x9e60, mload(0xb80))
                        }
mstore(0x9e80, mload(0x8860))
{
                            mstore(0x9ea0, mload(0xba0))
mstore(0x9ec0, mload(0xbc0))
mstore(0x9ee0, mload(0xbe0))
mstore(0x9f00, mload(0xc00))
                        }
mstore(0x9f20, mload(0x8880))
{
                            mstore(0x9f40, mload(0xc20))
mstore(0x9f60, mload(0xc40))
mstore(0x9f80, mload(0xc60))
mstore(0x9fa0, mload(0xc80))
                        }
mstore(0x9fc0, mload(0x88a0))
{
                            mstore(0x9fe0, mload(0xca0))
mstore(0xa000, mload(0xcc0))
mstore(0xa020, mload(0xce0))
mstore(0xa040, mload(0xd00))
                        }
mstore(0xa060, mload(0x88c0))
{
                            mstore(0xa080, mload(0xd20))
mstore(0xa0a0, mload(0xd40))
mstore(0xa0c0, mload(0xd60))
mstore(0xa0e0, mload(0xd80))
                        }
mstore(0xa100, mload(0x88e0))
{
                            mstore(0xa120, mload(0xda0))
mstore(0xa140, mload(0xdc0))
mstore(0xa160, mload(0xde0))
mstore(0xa180, mload(0xe00))
                        }
mstore(0xa1a0, mload(0x8900))
{
                            mstore(0xa1c0, mload(0xe20))
mstore(0xa1e0, mload(0xe40))
mstore(0xa200, mload(0xe60))
mstore(0xa220, mload(0xe80))
                        }
mstore(0xa240, mload(0x8920))
{
                            mstore(0xa260, mload(0xea0))
mstore(0xa280, mload(0xec0))
mstore(0xa2a0, mload(0xee0))
mstore(0xa2c0, mload(0xf00))
                        }
mstore(0xa2e0, mload(0x8940))
{
                            mstore(0xa300, mload(0xf20))
mstore(0xa320, mload(0xf40))
mstore(0xa340, mload(0xf60))
mstore(0xa360, mload(0xf80))
                        }
mstore(0xa380, mload(0x8960))
{
                            mstore(0xa3a0, mload(0x1b20))
mstore(0xa3c0, mload(0x1b40))
mstore(0xa3e0, mload(0x1b60))
mstore(0xa400, mload(0x1b80))
                        }
mstore(0xa420, mload(0x8980))
{
                            mstore(0xa440, mload(0x1ba0))
mstore(0xa460, mload(0x1bc0))
mstore(0xa480, mload(0x1be0))
mstore(0xa4a0, mload(0x1c00))
                        }
mstore(0xa4c0, mload(0x89a0))
{
                            mstore(0xa4e0, mload(0x1c20))
mstore(0xa500, mload(0x1c40))
mstore(0xa520, mload(0x1c60))
mstore(0xa540, mload(0x1c80))
                        }
mstore(0xa560, mload(0x89c0))
{
                            mstore(0xa580, mload(0x1ca0))
mstore(0xa5a0, mload(0x1cc0))
mstore(0xa5c0, mload(0x1ce0))
mstore(0xa5e0, mload(0x1d00))
                        }
mstore(0xa600, mload(0x89e0))
{
                            mstore(0xa620, mload(0x1a40))
mstore(0xa640, mload(0x1a60))
mstore(0xa660, mload(0x1a80))
mstore(0xa680, mload(0x1aa0))
                        }
mstore(0xa6a0, mload(0x8a00))
{
                            mstore(0xa6c0, mload(0x1140))
mstore(0xa6e0, mload(0x1160))
mstore(0xa700, mload(0x1180))
mstore(0xa720, mload(0x11a0))
                        }
mstore(0xa740, mload(0x8a20))
{
                            mstore(0xa760, mload(0x11c0))
mstore(0xa780, mload(0x11e0))
mstore(0xa7a0, mload(0x1200))
mstore(0xa7c0, mload(0x1220))
                        }
mstore(0xa7e0, mload(0x8a40))
{
                            mstore(0xa800, mload(0x1240))
mstore(0xa820, mload(0x1260))
mstore(0xa840, mload(0x1280))
mstore(0xa860, mload(0x12a0))
                        }
mstore(0xa880, mload(0x8a60))
{
                            mstore(0xa8a0, mload(0x1860))
mstore(0xa8c0, mload(0x1880))
mstore(0xa8e0, mload(0x18a0))
mstore(0xa900, mload(0x18c0))
                        }
mstore(0xa920, mload(0x8a80))
{
                            mstore(0xa940, mload(0x18e0))
mstore(0xa960, mload(0x1900))
mstore(0xa980, mload(0x1920))
mstore(0xa9a0, mload(0x1940))
                        }
mstore(0xa9c0, mload(0x8aa0))
{
                            mstore(0xa9e0, mload(0x1760))
mstore(0xaa00, mload(0x1780))
mstore(0xaa20, mload(0x17a0))
mstore(0xaa40, mload(0x17c0))
                        }
mstore(0xaa60, mload(0x8ac0))
{
                            mstore(0xaa80, mload(0x17e0))
mstore(0xaaa0, mload(0x1800))
mstore(0xaac0, mload(0x1820))
mstore(0xaae0, mload(0x1840))
                        }
mstore(0xab00, mload(0x8ae0))
{
                            mstore(0xab20, mload(0x15a0))
mstore(0xab40, mload(0x15c0))
mstore(0xab60, mload(0x15e0))
mstore(0xab80, mload(0x1600))
                        }
mstore(0xaba0, mload(0x8b00))
{
                            mstore(0xabc0, mload(0x2500))
mstore(0xabe0, mload(0x2520))
mstore(0xac00, mload(0x2540))
mstore(0xac20, mload(0x2560))
                        }
mstore(0xac40, mload(0x8b20))
{
                            mstore(0xac60, mload(0x26c0))
mstore(0xac80, mload(0x26e0))
mstore(0xaca0, mload(0x2700))
mstore(0xacc0, mload(0x2720))
                        }
mstore(0xace0, mload(0x8c80))
success := and(eq(staticcall(gas(), 0xc, 0x8d20, 0x1fe0, 0xad00, 0x80), 1), success)
mstore(0xad80, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f)
mstore(0xada0, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)
mstore(0xadc0, 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4)
mstore(0xade0, 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
{
                            mstore(0xae00, mload(0xad00))
mstore(0xae20, mload(0xad20))
mstore(0xae40, mload(0xad40))
mstore(0xae60, mload(0xad60))
                        }
mstore(0xae80, 0x00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051)
mstore(0xaea0, 0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8)
mstore(0xaec0, 0x0000000000000000000000000000000013e02b6052719f607dacd3a088274f65)
mstore(0xaee0, 0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e)
mstore(0xaf00, 0x000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a)
mstore(0xaf20, 0xadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801)
mstore(0xaf40, 0x000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99)
mstore(0xaf60, 0xcb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be)
{
                            mstore(0xaf80, mload(0x26c0))
mstore(0xafa0, mload(0x26e0))
mstore(0xafc0, mload(0x2700))
mstore(0xafe0, mload(0x2720))
                        }
mstore(0xb000, 0x00000000000000000000000000000000096d0e204d5b61e84c5d7cc5b5e39c12)
mstore(0xb020, 0x90b8f96c46ed27718c102c4336da31dd4df87e11d2b4e7c5fd5133fa97e6706a)
mstore(0xb040, 0x0000000000000000000000000000000003bb68964496acb25ca0d6bdf84dcfba)
mstore(0xb060, 0x9ea623ab34811d61556f3fed354fb835cfb99e803f547fdb69d26719c1bdc7ce)
mstore(0xb080, 0x00000000000000000000000000000000188f5e74480055cdb14f0112b46a8fa6)
mstore(0xb0a0, 0x2f83afc4d4082f238dcd36c8c42775cf3b4af715f36f01f1ebcf64c42d477c68)
mstore(0xb0c0, 0x00000000000000000000000000000000180c2525636ad5f070ef81e383ab8185)
mstore(0xb0e0, 0x8dc30be51d754aa4073faf3a784f5ad1362907ce098fadfc71f4e966e4ad6c78)
success := and(eq(staticcall(gas(), 0xf, 0xae00, 0x300, 0xae00, 0x20), 1), success)
success := and(eq(mload(0xae00), 1), success)

                    // Revert if anything fails
                    if iszero(success) { revert(0, 0) }

                    // Return empty bytes on success
                    return(0, 0)

        }
    }
}
        