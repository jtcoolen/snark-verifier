
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
            mstore(0x220, 0x000000000000000000000000000000000c6e73080239260a5d2e0d9f13ec52fd)
            mstore(0x240, 0xbb0269a5ea1757b53af118d4854249bc441e0e08c1fc5f0ca10fc4d9dc23adfa)
            mstore(0x260, 0x0000000000000000000000000000000003717a6c49366cb9febc1b9e4fed4f04)
            mstore(0x280, 0xf884e1a0d02329f21ca69d9ac01fc32525d6347349cbd0a1188023b186870497)
        }

        {
            mstore(0x2a0, 0x000000000000000000000000000000000409c8be52b351dc789d888d0d1d9392)
            mstore(0x2c0, 0xf6f1b0e272bd0843c6509fec8bd0b4c9f3ec72b041e6d32c04908a07a32966e7)
            mstore(0x2e0, 0x0000000000000000000000000000000005d8a62e220544279460a330fdf79630)
            mstore(0x300, 0xff30d704d4c4b2d69d69774431c793b8fadae066da1d7036117754aa1325aa29)
        }

        {
            mstore(0x320, 0x0000000000000000000000000000000013a68c20a0fa889ea8719d867852f874)
            mstore(0x340, 0xdc43abfee9c15afe1afd798580039da1e4ba7c9d6c5dee2cb12756f83e18b372)
            mstore(0x360, 0x000000000000000000000000000000000ec20a7da4c1d3fec215bba63adbafd6)
            mstore(0x380, 0x62438112243f304978608b415cc735d4a17a35878052df0de694736206c2b99a)
        }

        {
            mstore(0x3a0, 0x0000000000000000000000000000000002c955c7ae9a6908ef689b7b2c5e1478)
            mstore(0x3c0, 0xbfd31b78166dbabcddea219d9db2bb3f0a9ebfb519bb7359fc346cb527d10275)
            mstore(0x3e0, 0x000000000000000000000000000000000980b0e4c9587caa10f9df3568642bf2)
            mstore(0x400, 0x4aeffafe21d7c5ac11bc136525fd6395159623f69d308553f53bd4c2b8466b98)
        }

        {
            mstore(0x420, 0x00000000000000000000000000000000149afac89163c30d4d0f4898fed245f1)
            mstore(0x440, 0xcf7a1c47729a38504080ee0b1465cb5f021dc087773fcc16a261fa825cf457f1)
            mstore(0x460, 0x000000000000000000000000000000000d7f2677385e4b28df0216e7f93bb975)
            mstore(0x480, 0xf61e1a7785cedacae3965757a450a8aa86735a1c664d4b1ee6712050edc7ea1d)
        }

        {
            mstore(0x4a0, 0x000000000000000000000000000000001534950f50faea57e46c034dbed5e0ab)
            mstore(0x4c0, 0x70ad3724d10d1f1af89412e5d5b80bae7f4db9361127f176e63ea5bf232e90b4)
            mstore(0x4e0, 0x00000000000000000000000000000000131533eba36952e744e76c0ac681b936)
            mstore(0x500, 0x3d668f9098797724369a02a716f39ca757bd5023fd8e8203ae11e4b1803f49c6)
        }

        {
            mstore(0x520, 0x00000000000000000000000000000000044781127f30088a422e836e17b35bf9)
            mstore(0x540, 0xcf940d0009ba5037447ab78913451ded6bbbeb73a02a917b392fea5ad9f9cd9f)
            mstore(0x560, 0x00000000000000000000000000000000158b3508fbefa71ed88dd309a30dcc4b)
            mstore(0x580, 0xcc5a772860bb31eecd65d1d604a7987e21b86c51ed42f7f4396d456a698a7777)
        }

        {
            mstore(0x5a0, 0x0000000000000000000000000000000001d6088b8b14961ef9686f69b480af28)
            mstore(0x5c0, 0x441b5373f965dd0146a23fae7af0b0236073e70b1f03edca006e9d7618c15db2)
            mstore(0x5e0, 0x00000000000000000000000000000000093a8832950f2ec0835c82c8f8f58750)
            mstore(0x600, 0xc633b32897053f8861696d220b72cf4c169d01f43e1680509ab7760aadb0ac2a)
        }

        {
            mstore(0x620, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x640, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x660, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x680, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }

        {
            mstore(0x6a0, 0x00000000000000000000000000000000129caac453c3d01a1fd868cbb47ee9e8)
            mstore(0x6c0, 0x27322726bd606527ce1098637fc8861bd38356304b7402ce78ef2fefbb89a202)
            mstore(0x6e0, 0x000000000000000000000000000000000015da168b99eb37056dc8d21569ab4e)
            mstore(0x700, 0x243dbc7d9a2f1af4502dcfd3d44d3da08208208eb2821001d8d623f6b46f6d58)
        }

        {
            mstore(0x720, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x740, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x760, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x780, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }

        {
            mstore(0x7a0, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x7c0, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x7e0, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x800, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }

        {
            mstore(0x820, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x840, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x860, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x880, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }

        {
            mstore(0x8a0, 0x0000000000000000000000000000000006851a97be0773032f93c7f4262c52fc)
            mstore(0x8c0, 0x2c8fd6edede109728f217bbc5859d38d56585836d5b6b9bb254e864bc01e54c6)
            mstore(0x8e0, 0x00000000000000000000000000000000183ccbb9d5ebd36482405249b1355c63)
            mstore(0x900, 0xadaed67afc2360c472d3f2d286e9abca6cccd02b1fc922ed08b843c852738fa5)
        }

        {
            mstore(0x920, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x940, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x960, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x980, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }

        {
            mstore(0x9a0, 0x0000000000000000000000000000000009d5b282e897332e1a88146f5e44f944)
            mstore(0x9c0, 0x3ed97186f388fcedd06ae2357af26b6105ff52e943bdf41b8240206e97a3fc31)
            mstore(0x9e0, 0x00000000000000000000000000000000071cd08ad7c23d0eed8ac8b98ba49311)
            mstore(0xa00, 0x12c48fe80fc4be434fc4a240ff7277f707f4e451a2627e8f871fb7530fefef06)
        }

        {
            mstore(0xa20, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0xa40, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0xa60, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0xa80, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }

        {
            mstore(0xaa0, 0x0000000000000000000000000000000014ce8e4d7f0e21df201940d18a4d782f)
            mstore(0xac0, 0x976a9ddb9a325e6a5316403b317e353296d687b2b8dcb1e82fea46102db7618a)
            mstore(0xae0, 0x0000000000000000000000000000000014dc78f936a05631bba2d205364f3255)
            mstore(0xb00, 0x2c21797c90e100165561b61744d2454ddd20e8de596bc78000c749135763fc2f)
        }

        {
            mstore(0xb20, 0x0000000000000000000000000000000011f61dca5ba3f56424957a46a1cd64d1)
            mstore(0xb40, 0xce3853d8bb53bcba00365fd0fc00a305014648fe9c0df9a7f0d62f3612d24ad4)
            mstore(0xb60, 0x0000000000000000000000000000000008e57224aa38143ce6decda7625ba1cb)
            mstore(0xb80, 0x367f80c4b631e82af3eba3e13fb14686b1ec50039daa0144025d27c7783151c7)
        }

        {
            mstore(0xba0, 0x0000000000000000000000000000000001cf29e53542612e64535c5b998e4caa)
            mstore(0xbc0, 0x55e9656427b22c7485d7e4fd7dd60c1495a5b0d4ac5e073446c823fa802a4f31)
            mstore(0xbe0, 0x00000000000000000000000000000000002d82022b162f928bad9928885d81e2)
            mstore(0xc00, 0x48424428f467c58e88b513eb73bd58380d03995192657ebf310bd17a7b224406)
        }

        {
            mstore(0xc20, 0x00000000000000000000000000000000025d812dae703c1a6c77b2fc4c73f624)
            mstore(0xc40, 0x7120e9d7feb7362d79e2f4cd22db582b645f26b9fd03b78cecfe1b08eb8a7647)
            mstore(0xc60, 0x000000000000000000000000000000000e4e6d16d7c6fb6b07f4000a790812c6)
            mstore(0xc80, 0xae604a9ac7f1315b1a2a1373008101ddb946377ad09f92c5f5515d82a07c5045)
        }

        {
            mstore(0xca0, 0x0000000000000000000000000000000004bd4a44f49517e5b8f85728023b4e2a)
            mstore(0xcc0, 0x0403459fd1fbd6decb5f62173498130ce9c351f82fb6896591e22a56fbcfe67d)
            mstore(0xce0, 0x000000000000000000000000000000000078bfe0fded2d575aa27bd7a078d67e)
            mstore(0xd00, 0xabd63b3b1d4d4cd4d6b5a9e2c1802022c9d11063091c2f9f820da75353cbe29e)
        }

        {
            mstore(0xd20, 0x00000000000000000000000000000000145c5922f83a19266716ca3fa862c503)
            mstore(0xd40, 0x1a09644b736bb4fbadeca0cd346f6394c33392387544a9961dea3d6fc7a853a9)
            mstore(0xd60, 0x000000000000000000000000000000000553816f29f9e4008dd29ae5d50534df)
            mstore(0xd80, 0x36079277f11df0a5101ec047bb4705976b14253965df35bb8a8ddae12329a439)
        }

        {
            mstore(0xda0, 0x000000000000000000000000000000000f82ec9c4a1385d6b73ff2c9b3032a5c)
            mstore(0xdc0, 0x4936a017faa149bebbdba7d28f3bba6bc354710618ba9ed58caee40bec7e793f)
            mstore(0xde0, 0x000000000000000000000000000000001671f497143005025c86ca8187c10218)
            mstore(0xe00, 0xdbb7518f8d3beae1a24d70f5da1bc7bdb33837caef7e98e670861a04e53a19ca)
        }

        {
            mstore(0xe20, 0x000000000000000000000000000000000c280f076cb270469234511b43471766)
            mstore(0xe40, 0x2a11f5c6886e823bfa96e299145c1843004db6f26f0a219462b3d7fa27ab0f62)
            mstore(0xe60, 0x000000000000000000000000000000001692f371e62c5c6b19da09a00ca91ddc)
            mstore(0xe80, 0x6f439695bea5f432f757546147bed4e7e1c7d442eece9df3f5d54f83b307553b)
        }

        {
            mstore(0xea0, 0x000000000000000000000000000000000f8f320911b23fa02356ae6aea3b035f)
            mstore(0xec0, 0xddec0a37b3ec25c9d4b0ae21eefdfbca177a0a901739cd190c5b6ef04631775b)
            mstore(0xee0, 0x0000000000000000000000000000000005a9212878bab822e7d5fe5e1e0249cf)
            mstore(0xf00, 0xe73338b670e12f58224abd6ff1fa2ae3364fefa8a06e51371c9c109cd5e9cbf6)
        }

        {
            mstore(0xf20, 0x00000000000000000000000000000000145fb606c53742f20d7e564754282c02)
            mstore(0xf40, 0x3faf3ef72ec0763adda3e00ba3c255bd79ef297b7cd1e1d972e9aba55e04e449)
            mstore(0xf60, 0x0000000000000000000000000000000005f5ae1df69ab376e802e8abffeb6e4e)
            mstore(0xf80, 0xeee5970c2d8fb2046d7c9d5eaa6974315b39d99e451f116ded997e314dcd9083)
        }

        {
            mstore(0xfc0, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0xfe0, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x1000, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x1020, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }
mstore(0x1040, mod(calldataload(0x0), f_q))
mstore(0x1060, 12226310714665644107854727153062506819512778746739853225496972759771841268946)
{
                    mstore(0x1080, mload(0xfc0))
mstore(0x10a0, mload(0xfe0))
mstore(0x10c0, mload(0x1000))
mstore(0x10e0, mload(0x1020))
                }
mstore(0x1100, 1)
mstore(0x1120, mload(0x1040))

        {
            mstore(0x1140, 0)
            mstore(0x1160, 0)
            mstore(0x1180, 0)
            mstore(0x11a0, 0)
            calldatacopy(0x1150, 0x20, 0x30)
            calldatacopy(0x1190, 0x50, 0x30)
        }

        {
            mstore(0x11c0, 0)
            mstore(0x11e0, 0)
            mstore(0x1200, 0)
            mstore(0x1220, 0)
            calldatacopy(0x11d0, 0x80, 0x30)
            calldatacopy(0x1210, 0xb0, 0x30)
        }

        {
            mstore(0x1240, 0)
            mstore(0x1260, 0)
            mstore(0x1280, 0)
            mstore(0x12a0, 0)
            calldatacopy(0x1250, 0xe0, 0x30)
            calldatacopy(0x1290, 0x110, 0x30)
        }

        {
            mstore(0x12c0, 0)
            mstore(0x12e0, 0)
            mstore(0x1300, 0)
            mstore(0x1320, 0)
            calldatacopy(0x12d0, 0x140, 0x30)
            calldatacopy(0x1310, 0x170, 0x30)
        }

        {
            mstore(0x1340, 0)
            mstore(0x1360, 0)
            mstore(0x1380, 0)
            mstore(0x13a0, 0)
            calldatacopy(0x1350, 0x1a0, 0x30)
            calldatacopy(0x1390, 0x1d0, 0x30)
        }

        {
            mstore(0x13c0, 0)
            mstore(0x13e0, 0)
            mstore(0x1400, 0)
            mstore(0x1420, 0)
            calldatacopy(0x13d0, 0x200, 0x30)
            calldatacopy(0x1410, 0x230, 0x30)
        }

        {
            mstore(0x1440, 0)
            mstore(0x1460, 0)
            mstore(0x1480, 0)
            mstore(0x14a0, 0)
            calldatacopy(0x1450, 0x260, 0x30)
            calldatacopy(0x1490, 0x290, 0x30)
        }

        {
            mstore(0x14c0, 0)
            mstore(0x14e0, 0)
            mstore(0x1500, 0)
            mstore(0x1520, 0)
            calldatacopy(0x14d0, 0x2c0, 0x30)
            calldatacopy(0x1510, 0x2f0, 0x30)
        }
mstore(0x1540, keccak256(0x1060, 1248))
{
            let hash := mload(0x1540)
            mstore(0x1560, mod(hash, f_q))
            mstore(0x1580, hash)
        }

        {
            mstore(0x15a0, 0)
            mstore(0x15c0, 0)
            mstore(0x15e0, 0)
            mstore(0x1600, 0)
            calldatacopy(0x15b0, 0x320, 0x30)
            calldatacopy(0x15f0, 0x350, 0x30)
        }

        {
            mstore(0x1620, 0)
            mstore(0x1640, 0)
            mstore(0x1660, 0)
            mstore(0x1680, 0)
            calldatacopy(0x1630, 0x380, 0x30)
            calldatacopy(0x1670, 0x3b0, 0x30)
        }
mstore(0x16a0, keccak256(0x1580, 288))
{
            let hash := mload(0x16a0)
            mstore(0x16c0, mod(hash, f_q))
            mstore(0x16e0, hash)
        }
mstore8(5888, 1)
mstore(0x1700, keccak256(0x16e0, 33))
{
            let hash := mload(0x1700)
            mstore(0x1720, mod(hash, f_q))
            mstore(0x1740, hash)
        }

        {
            mstore(0x1760, 0)
            mstore(0x1780, 0)
            mstore(0x17a0, 0)
            mstore(0x17c0, 0)
            calldatacopy(0x1770, 0x3e0, 0x30)
            calldatacopy(0x17b0, 0x410, 0x30)
        }

        {
            mstore(0x17e0, 0)
            mstore(0x1800, 0)
            mstore(0x1820, 0)
            mstore(0x1840, 0)
            calldatacopy(0x17f0, 0x440, 0x30)
            calldatacopy(0x1830, 0x470, 0x30)
        }

        {
            mstore(0x1860, 0)
            mstore(0x1880, 0)
            mstore(0x18a0, 0)
            mstore(0x18c0, 0)
            calldatacopy(0x1870, 0x4a0, 0x30)
            calldatacopy(0x18b0, 0x4d0, 0x30)
        }

        {
            mstore(0x18e0, 0)
            mstore(0x1900, 0)
            mstore(0x1920, 0)
            mstore(0x1940, 0)
            calldatacopy(0x18f0, 0x500, 0x30)
            calldatacopy(0x1930, 0x530, 0x30)
        }
mstore(0x1960, keccak256(0x1740, 544))
{
            let hash := mload(0x1960)
            mstore(0x1980, mod(hash, f_q))
            mstore(0x19a0, hash)
        }

        {
            mstore(0x19c0, 0)
            mstore(0x19e0, 0)
            mstore(0x1a00, 0)
            mstore(0x1a20, 0)
            calldatacopy(0x19d0, 0x560, 0x30)
            calldatacopy(0x1a10, 0x590, 0x30)
        }

        {
            mstore(0x1a40, 0)
            mstore(0x1a60, 0)
            mstore(0x1a80, 0)
            mstore(0x1aa0, 0)
            calldatacopy(0x1a50, 0x5c0, 0x30)
            calldatacopy(0x1a90, 0x5f0, 0x30)
        }
mstore(0x1ac0, keccak256(0x19a0, 288))
{
            let hash := mload(0x1ac0)
            mstore(0x1ae0, mod(hash, f_q))
            mstore(0x1b00, hash)
        }

        {
            mstore(0x1b20, 0)
            mstore(0x1b40, 0)
            mstore(0x1b60, 0)
            mstore(0x1b80, 0)
            calldatacopy(0x1b30, 0x620, 0x30)
            calldatacopy(0x1b70, 0x650, 0x30)
        }

        {
            mstore(0x1ba0, 0)
            mstore(0x1bc0, 0)
            mstore(0x1be0, 0)
            mstore(0x1c00, 0)
            calldatacopy(0x1bb0, 0x680, 0x30)
            calldatacopy(0x1bf0, 0x6b0, 0x30)
        }

        {
            mstore(0x1c20, 0)
            mstore(0x1c40, 0)
            mstore(0x1c60, 0)
            mstore(0x1c80, 0)
            calldatacopy(0x1c30, 0x6e0, 0x30)
            calldatacopy(0x1c70, 0x710, 0x30)
        }

        {
            mstore(0x1ca0, 0)
            mstore(0x1cc0, 0)
            mstore(0x1ce0, 0)
            mstore(0x1d00, 0)
            calldatacopy(0x1cb0, 0x740, 0x30)
            calldatacopy(0x1cf0, 0x770, 0x30)
        }
mstore(0x1d20, keccak256(0x1b00, 544))
{
            let hash := mload(0x1d20)
            mstore(0x1d40, mod(hash, f_q))
            mstore(0x1d60, hash)
        }
mstore(0x1d80, mod(calldataload(0x7a0), f_q))
mstore(0x1da0, mod(calldataload(0x7c0), f_q))
mstore(0x1dc0, mod(calldataload(0x7e0), f_q))
mstore(0x1de0, mod(calldataload(0x800), f_q))
mstore(0x1e00, mod(calldataload(0x820), f_q))
mstore(0x1e20, mod(calldataload(0x840), f_q))
mstore(0x1e40, mod(calldataload(0x860), f_q))
mstore(0x1e60, mod(calldataload(0x880), f_q))
mstore(0x1e80, mod(calldataload(0x8a0), f_q))
mstore(0x1ea0, mod(calldataload(0x8c0), f_q))
mstore(0x1ec0, mod(calldataload(0x8e0), f_q))
mstore(0x1ee0, mod(calldataload(0x900), f_q))
mstore(0x1f00, mod(calldataload(0x920), f_q))
mstore(0x1f20, mod(calldataload(0x940), f_q))
mstore(0x1f40, mod(calldataload(0x960), f_q))
mstore(0x1f60, mod(calldataload(0x980), f_q))
mstore(0x1f80, mod(calldataload(0x9a0), f_q))
mstore(0x1fa0, mod(calldataload(0x9c0), f_q))
mstore(0x1fc0, mod(calldataload(0x9e0), f_q))
mstore(0x1fe0, mod(calldataload(0xa00), f_q))
mstore(0x2000, mod(calldataload(0xa20), f_q))
mstore(0x2020, mod(calldataload(0xa40), f_q))
mstore(0x2040, mod(calldataload(0xa60), f_q))
mstore(0x2060, mod(calldataload(0xa80), f_q))
mstore(0x2080, mod(calldataload(0xaa0), f_q))
mstore(0x20a0, mod(calldataload(0xac0), f_q))
mstore(0x20c0, mod(calldataload(0xae0), f_q))
mstore(0x20e0, mod(calldataload(0xb00), f_q))
mstore(0x2100, mod(calldataload(0xb20), f_q))
mstore(0x2120, mod(calldataload(0xb40), f_q))
mstore(0x2140, mod(calldataload(0xb60), f_q))
mstore(0x2160, mod(calldataload(0xb80), f_q))
mstore(0x2180, mod(calldataload(0xba0), f_q))
mstore(0x21a0, mod(calldataload(0xbc0), f_q))
mstore(0x21c0, mod(calldataload(0xbe0), f_q))
mstore(0x21e0, mod(calldataload(0xc00), f_q))
mstore(0x2200, mod(calldataload(0xc20), f_q))
mstore(0x2220, mod(calldataload(0xc40), f_q))
mstore(0x2240, mod(calldataload(0xc60), f_q))
mstore(0x2260, mod(calldataload(0xc80), f_q))
mstore(0x2280, mod(calldataload(0xca0), f_q))
mstore(0x22a0, mod(calldataload(0xcc0), f_q))
mstore(0x22c0, mod(calldataload(0xce0), f_q))
mstore(0x22e0, mod(calldataload(0xd00), f_q))
mstore(0x2300, mod(calldataload(0xd20), f_q))
mstore(0x2320, mod(calldataload(0xd40), f_q))
mstore(0x2340, mod(calldataload(0xd60), f_q))
mstore(0x2360, mod(calldataload(0xd80), f_q))
mstore(0x2380, mod(calldataload(0xda0), f_q))
mstore(0x23a0, mod(calldataload(0xdc0), f_q))
mstore(0x23c0, mod(calldataload(0xde0), f_q))
mstore(0x23e0, mod(calldataload(0xe00), f_q))
mstore(0x2400, mod(calldataload(0xe20), f_q))
mstore(0x2420, mod(calldataload(0xe40), f_q))
mstore(0x2440, keccak256(0x1d60, 1760))
{
            let hash := mload(0x2440)
            mstore(0x2460, mod(hash, f_q))
            mstore(0x2480, hash)
        }
mstore8(9376, 1)
mstore(0x24a0, keccak256(0x2480, 33))
{
            let hash := mload(0x24a0)
            mstore(0x24c0, mod(hash, f_q))
            mstore(0x24e0, hash)
        }

        {
            mstore(0x2500, 0)
            mstore(0x2520, 0)
            mstore(0x2540, 0)
            mstore(0x2560, 0)
            calldatacopy(0x2510, 0xe60, 0x30)
            calldatacopy(0x2550, 0xe90, 0x30)
        }
mstore(0x2580, keccak256(0x24e0, 160))
{
            let hash := mload(0x2580)
            mstore(0x25a0, mod(hash, f_q))
            mstore(0x25c0, hash)
        }
mstore(0x25e0, mod(calldataload(0xec0), f_q))
mstore(0x2600, mod(calldataload(0xee0), f_q))
mstore(0x2620, mod(calldataload(0xf00), f_q))
mstore(0x2640, mod(calldataload(0xf20), f_q))
mstore(0x2660, keccak256(0x25c0, 160))
{
            let hash := mload(0x2660)
            mstore(0x2680, mod(hash, f_q))
            mstore(0x26a0, hash)
        }

        {
            mstore(0x26c0, 0)
            mstore(0x26e0, 0)
            mstore(0x2700, 0)
            mstore(0x2720, 0)
            calldatacopy(0x26d0, 0xf40, 0x30)
            calldatacopy(0x2710, 0xf70, 0x30)
        }

        {
            mstore(0x2740, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x2760, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x2780, 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(0x27a0, 0x0000000000000000000000000000000000000000000000000000000000000000)
        }
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
mstore(0x7680, addmod(mload(0x25a0), sub(f_q, mload(0x5e60)), f_q))
mstore(0x76a0, mulmod(1, mload(0x7680), f_q))
mstore(0x76c0, addmod(mload(0x25a0), sub(f_q, mload(0x5ec0)), f_q))
mstore(0x76e0, mulmod(mload(0x76a0), mload(0x76c0), f_q))
mstore(0x7700, addmod(mload(0x5e60), sub(f_q, mload(0x5e80)), f_q))
mstore(0x7720, mulmod(1, mload(0x7700), f_q))
mstore(0x7740, addmod(mload(0x5e60), sub(f_q, mload(0x5ea0)), f_q))
mstore(0x7760, mulmod(mload(0x7720), mload(0x7740), f_q))
mstore(0x7780, addmod(mload(0x5e80), sub(f_q, mload(0x5e60)), f_q))
mstore(0x77a0, mulmod(1, mload(0x7780), f_q))
mstore(0x77c0, addmod(mload(0x5e80), sub(f_q, mload(0x5ea0)), f_q))
mstore(0x77e0, mulmod(mload(0x77a0), mload(0x77c0), f_q))
mstore(0x7800, addmod(mload(0x5ea0), sub(f_q, mload(0x5e60)), f_q))
mstore(0x7820, mulmod(1, mload(0x7800), f_q))
mstore(0x7840, addmod(mload(0x5ea0), sub(f_q, mload(0x5e80)), f_q))
mstore(0x7860, mulmod(mload(0x7820), mload(0x7840), f_q))
mstore(0x7880, addmod(mload(0x25a0), sub(f_q, mload(0x5e80)), f_q))
mstore(0x78a0, mulmod(mload(0x76a0), mload(0x7880), f_q))
mstore(0x78c0, addmod(mload(0x25a0), sub(f_q, mload(0x5ea0)), f_q))
mstore(0x78e0, mulmod(mload(0x78a0), mload(0x78c0), f_q))
{
            let prod := mload(0x7620)

                prod := mulmod(mload(0x7660), prod, f_q)
                mstore(0x7900, prod)
            
                prod := mulmod(mload(0x76e0), prod, f_q)
                mstore(0x7920, prod)
            
                prod := mulmod(mload(0x7760), prod, f_q)
                mstore(0x7940, prod)
            
                prod := mulmod(mload(0x77e0), prod, f_q)
                mstore(0x7960, prod)
            
                prod := mulmod(mload(0x7860), prod, f_q)
                mstore(0x7980, prod)
            
                prod := mulmod(mload(0x78e0), prod, f_q)
                mstore(0x79a0, prod)
            
                prod := mulmod(mload(0x7720), prod, f_q)
                mstore(0x79c0, prod)
            
                prod := mulmod(mload(0x77a0), prod, f_q)
                mstore(0x79e0, prod)
            
                prod := mulmod(mload(0x78a0), prod, f_q)
                mstore(0x7a00, prod)
            
                prod := mulmod(mload(0x76a0), prod, f_q)
                mstore(0x7a20, prod)
            
        }
mstore(0x7a60, 32)
mstore(0x7a80, 32)
mstore(0x7aa0, 32)
mstore(0x7ac0, mload(0x7a20))
mstore(0x7ae0, 52435875175126190479447740508185965837690552500527637822603658699938581184511)
mstore(0x7b00, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
success := and(eq(staticcall(gas(), 0x5, 0x7a60, 0xc0, 0x7a40, 0x20), 1), success)
{
            
            let inv := mload(0x7a40)
            let v
        
                    v := mload(0x76a0)
                    mstore(30368, mulmod(mload(0x7a00), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x78a0)
                    mstore(30880, mulmod(mload(0x79e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x77a0)
                    mstore(30624, mulmod(mload(0x79c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x7720)
                    mstore(30496, mulmod(mload(0x79a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x78e0)
                    mstore(30944, mulmod(mload(0x7980), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x7860)
                    mstore(30816, mulmod(mload(0x7960), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x77e0)
                    mstore(30688, mulmod(mload(0x7940), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x7760)
                    mstore(30560, mulmod(mload(0x7920), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x76e0)
                    mstore(30432, mulmod(mload(0x7900), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x7660)
                    mstore(30304, mulmod(mload(0x7620), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x7620, inv)

        }
mstore(0x7b20, mulmod(1, mload(0x76c0), f_q))
mstore(0x7b40, mulmod(mload(0x75a0), mload(0x7b20), f_q))
mstore(0x7b60, mulmod(mload(0x7b40), mload(0x7620), f_q))
mstore(0x7b80, addmod(0, mload(0x7b60), f_q))
mstore(0x7ba0, mulmod(mload(0x75e0), mload(0x76a0), f_q))
mstore(0x7bc0, mulmod(mload(0x7ba0), mload(0x7660), f_q))
mstore(0x7be0, addmod(mload(0x7b80), mload(0x7bc0), f_q))
mstore(0x7c00, addmod(mload(0x2640), sub(f_q, mload(0x7be0)), f_q))
mstore(0x7c20, mulmod(mload(0x7c00), mload(0x76e0), f_q))
mstore(0x7c40, mulmod(0, mload(0x24c0), f_q))
mstore(0x7c60, addmod(mload(0x7c40), mload(0x7c20), f_q))
mstore(0x7c80, mulmod(1, mload(0x7880), f_q))
mstore(0x7ca0, mulmod(mload(0x7c80), mload(0x78c0), f_q))
mstore(0x7cc0, mulmod(mload(0x74e0), mload(0x7ca0), f_q))
mstore(0x7ce0, mulmod(mload(0x7cc0), mload(0x7760), f_q))
mstore(0x7d00, addmod(0, mload(0x7ce0), f_q))
mstore(0x7d20, mulmod(mload(0x76a0), mload(0x78c0), f_q))
mstore(0x7d40, mulmod(mload(0x7520), mload(0x7d20), f_q))
mstore(0x7d60, mulmod(mload(0x7d40), mload(0x77e0), f_q))
mstore(0x7d80, addmod(mload(0x7d00), mload(0x7d60), f_q))
mstore(0x7da0, mulmod(mload(0x7560), mload(0x78a0), f_q))
mstore(0x7dc0, mulmod(mload(0x7da0), mload(0x7860), f_q))
mstore(0x7de0, addmod(mload(0x7d80), mload(0x7dc0), f_q))
mstore(0x7e00, addmod(mload(0x2620), sub(f_q, mload(0x7de0)), f_q))
mstore(0x7e20, mulmod(mload(0x7e00), mload(0x78e0), f_q))
mstore(0x7e40, mulmod(mload(0x7c60), mload(0x24c0), f_q))
mstore(0x7e60, addmod(mload(0x7e40), mload(0x7e20), f_q))
mstore(0x7e80, mulmod(mload(0x73a0), mload(0x7c80), f_q))
mstore(0x7ea0, mulmod(mload(0x7e80), mload(0x7720), f_q))
mstore(0x7ec0, addmod(0, mload(0x7ea0), f_q))
mstore(0x7ee0, mulmod(mload(0x73e0), mload(0x76a0), f_q))
mstore(0x7f00, mulmod(mload(0x7ee0), mload(0x77a0), f_q))
mstore(0x7f20, addmod(mload(0x7ec0), mload(0x7f00), f_q))
mstore(0x7f40, addmod(mload(0x2600), sub(f_q, mload(0x7f20)), f_q))
mstore(0x7f60, mulmod(mload(0x7f40), mload(0x78a0), f_q))
mstore(0x7f80, mulmod(mload(0x7e60), mload(0x24c0), f_q))
mstore(0x7fa0, addmod(mload(0x7f80), mload(0x7f60), f_q))
mstore(0x7fc0, addmod(mload(0x25e0), sub(f_q, mload(0x7160)), f_q))
mstore(0x7fe0, mulmod(mload(0x7fc0), mload(0x76a0), f_q))
mstore(0x8000, mulmod(mload(0x7fa0), mload(0x24c0), f_q))
mstore(0x8020, addmod(mload(0x8000), mload(0x7fe0), f_q))
mstore(0x8040, mulmod(mload(0x2680), mload(0x2680), f_q))
mstore(0x8060, mulmod(mload(0x8040), mload(0x2680), f_q))
mstore(0x8080, mulmod(mload(0x8060), mload(0x2680), f_q))
mstore(0x80a0, mulmod(mload(0x8080), mload(0x2680), f_q))
mstore(0x80c0, mulmod(mload(0x6360), 1, f_q))
mstore(0x80e0, mulmod(mload(0x6380), 1, f_q))
mstore(0x8100, mulmod(mload(0x63a0), 1, f_q))
mstore(0x8120, mulmod(mload(0x63c0), 1, f_q))
mstore(0x8140, mulmod(mload(0x63e0), 1, f_q))
mstore(0x8160, mulmod(mload(0x6400), 1, f_q))
mstore(0x8180, mulmod(mload(0x6420), 1, f_q))
mstore(0x81a0, mulmod(mload(0x6440), 1, f_q))
mstore(0x81c0, mulmod(mload(0x6460), 1, f_q))
mstore(0x81e0, mulmod(mload(0x6480), 1, f_q))
mstore(0x8200, mulmod(mload(0x64a0), 1, f_q))
mstore(0x8220, mulmod(mload(0x64c0), 1, f_q))
mstore(0x8240, mulmod(mload(0x64e0), 1, f_q))
mstore(0x8260, mulmod(mload(0x6500), 1, f_q))
mstore(0x8280, mulmod(mload(0x6520), 1, f_q))
mstore(0x82a0, mulmod(mload(0x6540), 1, f_q))
mstore(0x82c0, mulmod(mload(0x6560), 1, f_q))
mstore(0x82e0, mulmod(mload(0x6580), 1, f_q))
mstore(0x8300, mulmod(mload(0x65a0), 1, f_q))
mstore(0x8320, mulmod(mload(0x65c0), 1, f_q))
mstore(0x8340, mulmod(mload(0x65e0), 1, f_q))
mstore(0x8360, mulmod(mload(0x6600), 1, f_q))
mstore(0x8380, mulmod(mload(0x6620), 1, f_q))
mstore(0x83a0, mulmod(mload(0x6640), 1, f_q))
mstore(0x83c0, mulmod(mload(0x6660), 1, f_q))
mstore(0x83e0, mulmod(mload(0x6680), 1, f_q))
mstore(0x8400, mulmod(mload(0x66a0), 1, f_q))
mstore(0x8420, mulmod(mload(0x66c0), 1, f_q))
mstore(0x8440, mulmod(mload(0x66e0), 1, f_q))
mstore(0x8460, mulmod(mload(0x6700), 1, f_q))
mstore(0x8480, mulmod(mload(0x6720), 1, f_q))
mstore(0x84a0, mulmod(mload(0x6740), 1, f_q))
mstore(0x84c0, mulmod(mload(0x6760), 1, f_q))
mstore(0x84e0, mulmod(mload(0x6780), 1, f_q))
mstore(0x8500, mulmod(mload(0x67a0), 1, f_q))
mstore(0x8520, mulmod(mload(0x67c0), 1, f_q))
mstore(0x8540, mulmod(mload(0x67e0), 1, f_q))
mstore(0x8560, mulmod(mload(0x6800), 1, f_q))
mstore(0x8580, mulmod(mload(0x6820), 1, f_q))
mstore(0x85a0, mulmod(1, mload(0x2680), f_q))
mstore(0x85c0, mulmod(mload(0x6360), mload(0x2680), f_q))
mstore(0x85e0, mulmod(mload(0x6380), mload(0x2680), f_q))
mstore(0x8600, mulmod(mload(0x63a0), mload(0x2680), f_q))
mstore(0x8620, mulmod(mload(0x63c0), mload(0x2680), f_q))
mstore(0x8640, mulmod(1, mload(0x8040), f_q))
mstore(0x8660, mulmod(mload(0x6360), mload(0x8040), f_q))
mstore(0x8680, mulmod(1, mload(0x8060), f_q))
mstore(0x86a0, mulmod(1, mload(0x8080), f_q))
mstore(0x86c0, mulmod(mload(0x25e0), 1, f_q))
mstore(0x86e0, addmod(0, mload(0x86c0), f_q))
mstore(0x8700, mulmod(mload(0x2600), mload(0x2680), f_q))
mstore(0x8720, addmod(mload(0x86e0), mload(0x8700), f_q))
mstore(0x8740, mulmod(mload(0x2620), mload(0x8040), f_q))
mstore(0x8760, addmod(mload(0x8720), mload(0x8740), f_q))
mstore(0x8780, mulmod(mload(0x2640), mload(0x8060), f_q))
mstore(0x87a0, addmod(mload(0x8760), mload(0x8780), f_q))
mstore(0x87c0, mulmod(mload(0x8020), mload(0x8080), f_q))
mstore(0x87e0, addmod(mload(0x87a0), mload(0x87c0), f_q))
mstore(0x8800, mulmod(1, mload(0x25a0), f_q))

        {
            mstore(0x8820, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f)
            mstore(0x8840, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)
            mstore(0x8860, 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4)
            mstore(0x8880, 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
        }
{
                    mstore(0x88a0, mload(0x8820))
mstore(0x88c0, mload(0x8840))
mstore(0x88e0, mload(0x8860))
mstore(0x8900, mload(0x8880))
                }
mstore(0x8920, sub(f_q, mload(0x87e0)))
success := and(eq(staticcall(gas(), 0xc, 0x88a0, 0xa0, 0x88a0, 0x80), 1), success)
{
                    mstore(0x8940, mload(0x88a0))
mstore(0x8960, mload(0x88c0))
mstore(0x8980, mload(0x88e0))
mstore(0x89a0, mload(0x8900))
                }
{
                    mstore(0x89c0, mload(0xfc0))
mstore(0x89e0, mload(0xfe0))
mstore(0x8a00, mload(0x1000))
mstore(0x8a20, mload(0x1020))
                }
success := and(eq(staticcall(gas(), 0xb, 0x8940, 0x100, 0x8940, 0x80), 1), success)
{
                    mstore(0x8a40, mload(0x12c0))
mstore(0x8a60, mload(0x12e0))
mstore(0x8a80, mload(0x1300))
mstore(0x8aa0, mload(0x1320))
                }
mstore(0x8ac0, mload(0x80c0))
success := and(eq(staticcall(gas(), 0xc, 0x8a40, 0xa0, 0x8a40, 0x80), 1), success)
{
                    mstore(0x8ae0, mload(0x8940))
mstore(0x8b00, mload(0x8960))
mstore(0x8b20, mload(0x8980))
mstore(0x8b40, mload(0x89a0))
                }
{
                    mstore(0x8b60, mload(0x8a40))
mstore(0x8b80, mload(0x8a60))
mstore(0x8ba0, mload(0x8a80))
mstore(0x8bc0, mload(0x8aa0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x8ae0, 0x100, 0x8ae0, 0x80), 1), success)
{
                    mstore(0x8be0, mload(0x1340))
mstore(0x8c00, mload(0x1360))
mstore(0x8c20, mload(0x1380))
mstore(0x8c40, mload(0x13a0))
                }
mstore(0x8c60, mload(0x80e0))
success := and(eq(staticcall(gas(), 0xc, 0x8be0, 0xa0, 0x8be0, 0x80), 1), success)
{
                    mstore(0x8c80, mload(0x8ae0))
mstore(0x8ca0, mload(0x8b00))
mstore(0x8cc0, mload(0x8b20))
mstore(0x8ce0, mload(0x8b40))
                }
{
                    mstore(0x8d00, mload(0x8be0))
mstore(0x8d20, mload(0x8c00))
mstore(0x8d40, mload(0x8c20))
mstore(0x8d60, mload(0x8c40))
                }
success := and(eq(staticcall(gas(), 0xb, 0x8c80, 0x100, 0x8c80, 0x80), 1), success)
{
                    mstore(0x8d80, mload(0x13c0))
mstore(0x8da0, mload(0x13e0))
mstore(0x8dc0, mload(0x1400))
mstore(0x8de0, mload(0x1420))
                }
mstore(0x8e00, mload(0x8100))
success := and(eq(staticcall(gas(), 0xc, 0x8d80, 0xa0, 0x8d80, 0x80), 1), success)
{
                    mstore(0x8e20, mload(0x8c80))
mstore(0x8e40, mload(0x8ca0))
mstore(0x8e60, mload(0x8cc0))
mstore(0x8e80, mload(0x8ce0))
                }
{
                    mstore(0x8ea0, mload(0x8d80))
mstore(0x8ec0, mload(0x8da0))
mstore(0x8ee0, mload(0x8dc0))
mstore(0x8f00, mload(0x8de0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x8e20, 0x100, 0x8e20, 0x80), 1), success)
{
                    mstore(0x8f20, mload(0x1440))
mstore(0x8f40, mload(0x1460))
mstore(0x8f60, mload(0x1480))
mstore(0x8f80, mload(0x14a0))
                }
mstore(0x8fa0, mload(0x8120))
success := and(eq(staticcall(gas(), 0xc, 0x8f20, 0xa0, 0x8f20, 0x80), 1), success)
{
                    mstore(0x8fc0, mload(0x8e20))
mstore(0x8fe0, mload(0x8e40))
mstore(0x9000, mload(0x8e60))
mstore(0x9020, mload(0x8e80))
                }
{
                    mstore(0x9040, mload(0x8f20))
mstore(0x9060, mload(0x8f40))
mstore(0x9080, mload(0x8f60))
mstore(0x90a0, mload(0x8f80))
                }
success := and(eq(staticcall(gas(), 0xb, 0x8fc0, 0x100, 0x8fc0, 0x80), 1), success)
{
                    mstore(0x90c0, mload(0x14c0))
mstore(0x90e0, mload(0x14e0))
mstore(0x9100, mload(0x1500))
mstore(0x9120, mload(0x1520))
                }
mstore(0x9140, mload(0x8140))
success := and(eq(staticcall(gas(), 0xc, 0x90c0, 0xa0, 0x90c0, 0x80), 1), success)
{
                    mstore(0x9160, mload(0x8fc0))
mstore(0x9180, mload(0x8fe0))
mstore(0x91a0, mload(0x9000))
mstore(0x91c0, mload(0x9020))
                }
{
                    mstore(0x91e0, mload(0x90c0))
mstore(0x9200, mload(0x90e0))
mstore(0x9220, mload(0x9100))
mstore(0x9240, mload(0x9120))
                }
success := and(eq(staticcall(gas(), 0xb, 0x9160, 0x100, 0x9160, 0x80), 1), success)
{
                    mstore(0x9260, mload(0x1620))
mstore(0x9280, mload(0x1640))
mstore(0x92a0, mload(0x1660))
mstore(0x92c0, mload(0x1680))
                }
mstore(0x92e0, mload(0x8160))
success := and(eq(staticcall(gas(), 0xc, 0x9260, 0xa0, 0x9260, 0x80), 1), success)
{
                    mstore(0x9300, mload(0x9160))
mstore(0x9320, mload(0x9180))
mstore(0x9340, mload(0x91a0))
mstore(0x9360, mload(0x91c0))
                }
{
                    mstore(0x9380, mload(0x9260))
mstore(0x93a0, mload(0x9280))
mstore(0x93c0, mload(0x92a0))
mstore(0x93e0, mload(0x92c0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x9300, 0x100, 0x9300, 0x80), 1), success)
{
                    mstore(0x9400, mload(0x19c0))
mstore(0x9420, mload(0x19e0))
mstore(0x9440, mload(0x1a00))
mstore(0x9460, mload(0x1a20))
                }
mstore(0x9480, mload(0x8180))
success := and(eq(staticcall(gas(), 0xc, 0x9400, 0xa0, 0x9400, 0x80), 1), success)
{
                    mstore(0x94a0, mload(0x9300))
mstore(0x94c0, mload(0x9320))
mstore(0x94e0, mload(0x9340))
mstore(0x9500, mload(0x9360))
                }
{
                    mstore(0x9520, mload(0x9400))
mstore(0x9540, mload(0x9420))
mstore(0x9560, mload(0x9440))
mstore(0x9580, mload(0x9460))
                }
success := and(eq(staticcall(gas(), 0xb, 0x94a0, 0x100, 0x94a0, 0x80), 1), success)
{
                    mstore(0x95a0, mload(0x6a0))
mstore(0x95c0, mload(0x6c0))
mstore(0x95e0, mload(0x6e0))
mstore(0x9600, mload(0x700))
                }
mstore(0x9620, mload(0x81a0))
success := and(eq(staticcall(gas(), 0xc, 0x95a0, 0xa0, 0x95a0, 0x80), 1), success)
{
                    mstore(0x9640, mload(0x94a0))
mstore(0x9660, mload(0x94c0))
mstore(0x9680, mload(0x94e0))
mstore(0x96a0, mload(0x9500))
                }
{
                    mstore(0x96c0, mload(0x95a0))
mstore(0x96e0, mload(0x95c0))
mstore(0x9700, mload(0x95e0))
mstore(0x9720, mload(0x9600))
                }
success := and(eq(staticcall(gas(), 0xb, 0x9640, 0x100, 0x9640, 0x80), 1), success)
{
                    mstore(0x9740, mload(0x420))
mstore(0x9760, mload(0x440))
mstore(0x9780, mload(0x460))
mstore(0x97a0, mload(0x480))
                }
mstore(0x97c0, mload(0x81c0))
success := and(eq(staticcall(gas(), 0xc, 0x9740, 0xa0, 0x9740, 0x80), 1), success)
{
                    mstore(0x97e0, mload(0x9640))
mstore(0x9800, mload(0x9660))
mstore(0x9820, mload(0x9680))
mstore(0x9840, mload(0x96a0))
                }
{
                    mstore(0x9860, mload(0x9740))
mstore(0x9880, mload(0x9760))
mstore(0x98a0, mload(0x9780))
mstore(0x98c0, mload(0x97a0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x97e0, 0x100, 0x97e0, 0x80), 1), success)
{
                    mstore(0x98e0, mload(0x4a0))
mstore(0x9900, mload(0x4c0))
mstore(0x9920, mload(0x4e0))
mstore(0x9940, mload(0x500))
                }
mstore(0x9960, mload(0x81e0))
success := and(eq(staticcall(gas(), 0xc, 0x98e0, 0xa0, 0x98e0, 0x80), 1), success)
{
                    mstore(0x9980, mload(0x97e0))
mstore(0x99a0, mload(0x9800))
mstore(0x99c0, mload(0x9820))
mstore(0x99e0, mload(0x9840))
                }
{
                    mstore(0x9a00, mload(0x98e0))
mstore(0x9a20, mload(0x9900))
mstore(0x9a40, mload(0x9920))
mstore(0x9a60, mload(0x9940))
                }
success := and(eq(staticcall(gas(), 0xb, 0x9980, 0x100, 0x9980, 0x80), 1), success)
{
                    mstore(0x9a80, mload(0x520))
mstore(0x9aa0, mload(0x540))
mstore(0x9ac0, mload(0x560))
mstore(0x9ae0, mload(0x580))
                }
mstore(0x9b00, mload(0x8200))
success := and(eq(staticcall(gas(), 0xc, 0x9a80, 0xa0, 0x9a80, 0x80), 1), success)
{
                    mstore(0x9b20, mload(0x9980))
mstore(0x9b40, mload(0x99a0))
mstore(0x9b60, mload(0x99c0))
mstore(0x9b80, mload(0x99e0))
                }
{
                    mstore(0x9ba0, mload(0x9a80))
mstore(0x9bc0, mload(0x9aa0))
mstore(0x9be0, mload(0x9ac0))
mstore(0x9c00, mload(0x9ae0))
                }
success := and(eq(staticcall(gas(), 0xb, 0x9b20, 0x100, 0x9b20, 0x80), 1), success)
{
                    mstore(0x9c20, mload(0x5a0))
mstore(0x9c40, mload(0x5c0))
mstore(0x9c60, mload(0x5e0))
mstore(0x9c80, mload(0x600))
                }
mstore(0x9ca0, mload(0x8220))
success := and(eq(staticcall(gas(), 0xc, 0x9c20, 0xa0, 0x9c20, 0x80), 1), success)
{
                    mstore(0x9cc0, mload(0x9b20))
mstore(0x9ce0, mload(0x9b40))
mstore(0x9d00, mload(0x9b60))
mstore(0x9d20, mload(0x9b80))
                }
{
                    mstore(0x9d40, mload(0x9c20))
mstore(0x9d60, mload(0x9c40))
mstore(0x9d80, mload(0x9c60))
mstore(0x9da0, mload(0x9c80))
                }
success := and(eq(staticcall(gas(), 0xb, 0x9cc0, 0x100, 0x9cc0, 0x80), 1), success)
{
                    mstore(0x9dc0, mload(0x620))
mstore(0x9de0, mload(0x640))
mstore(0x9e00, mload(0x660))
mstore(0x9e20, mload(0x680))
                }
mstore(0x9e40, mload(0x8240))
success := and(eq(staticcall(gas(), 0xc, 0x9dc0, 0xa0, 0x9dc0, 0x80), 1), success)
{
                    mstore(0x9e60, mload(0x9cc0))
mstore(0x9e80, mload(0x9ce0))
mstore(0x9ea0, mload(0x9d00))
mstore(0x9ec0, mload(0x9d20))
                }
{
                    mstore(0x9ee0, mload(0x9dc0))
mstore(0x9f00, mload(0x9de0))
mstore(0x9f20, mload(0x9e00))
mstore(0x9f40, mload(0x9e20))
                }
success := and(eq(staticcall(gas(), 0xb, 0x9e60, 0x100, 0x9e60, 0x80), 1), success)
{
                    mstore(0x9f60, mload(0x220))
mstore(0x9f80, mload(0x240))
mstore(0x9fa0, mload(0x260))
mstore(0x9fc0, mload(0x280))
                }
mstore(0x9fe0, mload(0x8260))
success := and(eq(staticcall(gas(), 0xc, 0x9f60, 0xa0, 0x9f60, 0x80), 1), success)
{
                    mstore(0xa000, mload(0x9e60))
mstore(0xa020, mload(0x9e80))
mstore(0xa040, mload(0x9ea0))
mstore(0xa060, mload(0x9ec0))
                }
{
                    mstore(0xa080, mload(0x9f60))
mstore(0xa0a0, mload(0x9f80))
mstore(0xa0c0, mload(0x9fa0))
mstore(0xa0e0, mload(0x9fc0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xa000, 0x100, 0xa000, 0x80), 1), success)
{
                    mstore(0xa100, mload(0x2a0))
mstore(0xa120, mload(0x2c0))
mstore(0xa140, mload(0x2e0))
mstore(0xa160, mload(0x300))
                }
mstore(0xa180, mload(0x8280))
success := and(eq(staticcall(gas(), 0xc, 0xa100, 0xa0, 0xa100, 0x80), 1), success)
{
                    mstore(0xa1a0, mload(0xa000))
mstore(0xa1c0, mload(0xa020))
mstore(0xa1e0, mload(0xa040))
mstore(0xa200, mload(0xa060))
                }
{
                    mstore(0xa220, mload(0xa100))
mstore(0xa240, mload(0xa120))
mstore(0xa260, mload(0xa140))
mstore(0xa280, mload(0xa160))
                }
success := and(eq(staticcall(gas(), 0xb, 0xa1a0, 0x100, 0xa1a0, 0x80), 1), success)
{
                    mstore(0xa2a0, mload(0x320))
mstore(0xa2c0, mload(0x340))
mstore(0xa2e0, mload(0x360))
mstore(0xa300, mload(0x380))
                }
mstore(0xa320, mload(0x82a0))
success := and(eq(staticcall(gas(), 0xc, 0xa2a0, 0xa0, 0xa2a0, 0x80), 1), success)
{
                    mstore(0xa340, mload(0xa1a0))
mstore(0xa360, mload(0xa1c0))
mstore(0xa380, mload(0xa1e0))
mstore(0xa3a0, mload(0xa200))
                }
{
                    mstore(0xa3c0, mload(0xa2a0))
mstore(0xa3e0, mload(0xa2c0))
mstore(0xa400, mload(0xa2e0))
mstore(0xa420, mload(0xa300))
                }
success := and(eq(staticcall(gas(), 0xb, 0xa340, 0x100, 0xa340, 0x80), 1), success)
{
                    mstore(0xa440, mload(0x3a0))
mstore(0xa460, mload(0x3c0))
mstore(0xa480, mload(0x3e0))
mstore(0xa4a0, mload(0x400))
                }
mstore(0xa4c0, mload(0x82c0))
success := and(eq(staticcall(gas(), 0xc, 0xa440, 0xa0, 0xa440, 0x80), 1), success)
{
                    mstore(0xa4e0, mload(0xa340))
mstore(0xa500, mload(0xa360))
mstore(0xa520, mload(0xa380))
mstore(0xa540, mload(0xa3a0))
                }
{
                    mstore(0xa560, mload(0xa440))
mstore(0xa580, mload(0xa460))
mstore(0xa5a0, mload(0xa480))
mstore(0xa5c0, mload(0xa4a0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xa4e0, 0x100, 0xa4e0, 0x80), 1), success)
{
                    mstore(0xa5e0, mload(0x720))
mstore(0xa600, mload(0x740))
mstore(0xa620, mload(0x760))
mstore(0xa640, mload(0x780))
                }
mstore(0xa660, mload(0x82e0))
success := and(eq(staticcall(gas(), 0xc, 0xa5e0, 0xa0, 0xa5e0, 0x80), 1), success)
{
                    mstore(0xa680, mload(0xa4e0))
mstore(0xa6a0, mload(0xa500))
mstore(0xa6c0, mload(0xa520))
mstore(0xa6e0, mload(0xa540))
                }
{
                    mstore(0xa700, mload(0xa5e0))
mstore(0xa720, mload(0xa600))
mstore(0xa740, mload(0xa620))
mstore(0xa760, mload(0xa640))
                }
success := and(eq(staticcall(gas(), 0xb, 0xa680, 0x100, 0xa680, 0x80), 1), success)
{
                    mstore(0xa780, mload(0x7a0))
mstore(0xa7a0, mload(0x7c0))
mstore(0xa7c0, mload(0x7e0))
mstore(0xa7e0, mload(0x800))
                }
mstore(0xa800, mload(0x8300))
success := and(eq(staticcall(gas(), 0xc, 0xa780, 0xa0, 0xa780, 0x80), 1), success)
{
                    mstore(0xa820, mload(0xa680))
mstore(0xa840, mload(0xa6a0))
mstore(0xa860, mload(0xa6c0))
mstore(0xa880, mload(0xa6e0))
                }
{
                    mstore(0xa8a0, mload(0xa780))
mstore(0xa8c0, mload(0xa7a0))
mstore(0xa8e0, mload(0xa7c0))
mstore(0xa900, mload(0xa7e0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xa820, 0x100, 0xa820, 0x80), 1), success)
{
                    mstore(0xa920, mload(0x820))
mstore(0xa940, mload(0x840))
mstore(0xa960, mload(0x860))
mstore(0xa980, mload(0x880))
                }
mstore(0xa9a0, mload(0x8320))
success := and(eq(staticcall(gas(), 0xc, 0xa920, 0xa0, 0xa920, 0x80), 1), success)
{
                    mstore(0xa9c0, mload(0xa820))
mstore(0xa9e0, mload(0xa840))
mstore(0xaa00, mload(0xa860))
mstore(0xaa20, mload(0xa880))
                }
{
                    mstore(0xaa40, mload(0xa920))
mstore(0xaa60, mload(0xa940))
mstore(0xaa80, mload(0xa960))
mstore(0xaaa0, mload(0xa980))
                }
success := and(eq(staticcall(gas(), 0xb, 0xa9c0, 0x100, 0xa9c0, 0x80), 1), success)
{
                    mstore(0xaac0, mload(0x8a0))
mstore(0xaae0, mload(0x8c0))
mstore(0xab00, mload(0x8e0))
mstore(0xab20, mload(0x900))
                }
mstore(0xab40, mload(0x8340))
success := and(eq(staticcall(gas(), 0xc, 0xaac0, 0xa0, 0xaac0, 0x80), 1), success)
{
                    mstore(0xab60, mload(0xa9c0))
mstore(0xab80, mload(0xa9e0))
mstore(0xaba0, mload(0xaa00))
mstore(0xabc0, mload(0xaa20))
                }
{
                    mstore(0xabe0, mload(0xaac0))
mstore(0xac00, mload(0xaae0))
mstore(0xac20, mload(0xab00))
mstore(0xac40, mload(0xab20))
                }
success := and(eq(staticcall(gas(), 0xb, 0xab60, 0x100, 0xab60, 0x80), 1), success)
{
                    mstore(0xac60, mload(0x920))
mstore(0xac80, mload(0x940))
mstore(0xaca0, mload(0x960))
mstore(0xacc0, mload(0x980))
                }
mstore(0xace0, mload(0x8360))
success := and(eq(staticcall(gas(), 0xc, 0xac60, 0xa0, 0xac60, 0x80), 1), success)
{
                    mstore(0xad00, mload(0xab60))
mstore(0xad20, mload(0xab80))
mstore(0xad40, mload(0xaba0))
mstore(0xad60, mload(0xabc0))
                }
{
                    mstore(0xad80, mload(0xac60))
mstore(0xada0, mload(0xac80))
mstore(0xadc0, mload(0xaca0))
mstore(0xade0, mload(0xacc0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xad00, 0x100, 0xad00, 0x80), 1), success)
{
                    mstore(0xae00, mload(0x9a0))
mstore(0xae20, mload(0x9c0))
mstore(0xae40, mload(0x9e0))
mstore(0xae60, mload(0xa00))
                }
mstore(0xae80, mload(0x8380))
success := and(eq(staticcall(gas(), 0xc, 0xae00, 0xa0, 0xae00, 0x80), 1), success)
{
                    mstore(0xaea0, mload(0xad00))
mstore(0xaec0, mload(0xad20))
mstore(0xaee0, mload(0xad40))
mstore(0xaf00, mload(0xad60))
                }
{
                    mstore(0xaf20, mload(0xae00))
mstore(0xaf40, mload(0xae20))
mstore(0xaf60, mload(0xae40))
mstore(0xaf80, mload(0xae60))
                }
success := and(eq(staticcall(gas(), 0xb, 0xaea0, 0x100, 0xaea0, 0x80), 1), success)
{
                    mstore(0xafa0, mload(0xa20))
mstore(0xafc0, mload(0xa40))
mstore(0xafe0, mload(0xa60))
mstore(0xb000, mload(0xa80))
                }
mstore(0xb020, mload(0x83a0))
success := and(eq(staticcall(gas(), 0xc, 0xafa0, 0xa0, 0xafa0, 0x80), 1), success)
{
                    mstore(0xb040, mload(0xaea0))
mstore(0xb060, mload(0xaec0))
mstore(0xb080, mload(0xaee0))
mstore(0xb0a0, mload(0xaf00))
                }
{
                    mstore(0xb0c0, mload(0xafa0))
mstore(0xb0e0, mload(0xafc0))
mstore(0xb100, mload(0xafe0))
mstore(0xb120, mload(0xb000))
                }
success := and(eq(staticcall(gas(), 0xb, 0xb040, 0x100, 0xb040, 0x80), 1), success)
{
                    mstore(0xb140, mload(0xaa0))
mstore(0xb160, mload(0xac0))
mstore(0xb180, mload(0xae0))
mstore(0xb1a0, mload(0xb00))
                }
mstore(0xb1c0, mload(0x83c0))
success := and(eq(staticcall(gas(), 0xc, 0xb140, 0xa0, 0xb140, 0x80), 1), success)
{
                    mstore(0xb1e0, mload(0xb040))
mstore(0xb200, mload(0xb060))
mstore(0xb220, mload(0xb080))
mstore(0xb240, mload(0xb0a0))
                }
{
                    mstore(0xb260, mload(0xb140))
mstore(0xb280, mload(0xb160))
mstore(0xb2a0, mload(0xb180))
mstore(0xb2c0, mload(0xb1a0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xb1e0, 0x100, 0xb1e0, 0x80), 1), success)
{
                    mstore(0xb2e0, mload(0xb20))
mstore(0xb300, mload(0xb40))
mstore(0xb320, mload(0xb60))
mstore(0xb340, mload(0xb80))
                }
mstore(0xb360, mload(0x83e0))
success := and(eq(staticcall(gas(), 0xc, 0xb2e0, 0xa0, 0xb2e0, 0x80), 1), success)
{
                    mstore(0xb380, mload(0xb1e0))
mstore(0xb3a0, mload(0xb200))
mstore(0xb3c0, mload(0xb220))
mstore(0xb3e0, mload(0xb240))
                }
{
                    mstore(0xb400, mload(0xb2e0))
mstore(0xb420, mload(0xb300))
mstore(0xb440, mload(0xb320))
mstore(0xb460, mload(0xb340))
                }
success := and(eq(staticcall(gas(), 0xb, 0xb380, 0x100, 0xb380, 0x80), 1), success)
{
                    mstore(0xb480, mload(0xba0))
mstore(0xb4a0, mload(0xbc0))
mstore(0xb4c0, mload(0xbe0))
mstore(0xb4e0, mload(0xc00))
                }
mstore(0xb500, mload(0x8400))
success := and(eq(staticcall(gas(), 0xc, 0xb480, 0xa0, 0xb480, 0x80), 1), success)
{
                    mstore(0xb520, mload(0xb380))
mstore(0xb540, mload(0xb3a0))
mstore(0xb560, mload(0xb3c0))
mstore(0xb580, mload(0xb3e0))
                }
{
                    mstore(0xb5a0, mload(0xb480))
mstore(0xb5c0, mload(0xb4a0))
mstore(0xb5e0, mload(0xb4c0))
mstore(0xb600, mload(0xb4e0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xb520, 0x100, 0xb520, 0x80), 1), success)
{
                    mstore(0xb620, mload(0xc20))
mstore(0xb640, mload(0xc40))
mstore(0xb660, mload(0xc60))
mstore(0xb680, mload(0xc80))
                }
mstore(0xb6a0, mload(0x8420))
success := and(eq(staticcall(gas(), 0xc, 0xb620, 0xa0, 0xb620, 0x80), 1), success)
{
                    mstore(0xb6c0, mload(0xb520))
mstore(0xb6e0, mload(0xb540))
mstore(0xb700, mload(0xb560))
mstore(0xb720, mload(0xb580))
                }
{
                    mstore(0xb740, mload(0xb620))
mstore(0xb760, mload(0xb640))
mstore(0xb780, mload(0xb660))
mstore(0xb7a0, mload(0xb680))
                }
success := and(eq(staticcall(gas(), 0xb, 0xb6c0, 0x100, 0xb6c0, 0x80), 1), success)
{
                    mstore(0xb7c0, mload(0xca0))
mstore(0xb7e0, mload(0xcc0))
mstore(0xb800, mload(0xce0))
mstore(0xb820, mload(0xd00))
                }
mstore(0xb840, mload(0x8440))
success := and(eq(staticcall(gas(), 0xc, 0xb7c0, 0xa0, 0xb7c0, 0x80), 1), success)
{
                    mstore(0xb860, mload(0xb6c0))
mstore(0xb880, mload(0xb6e0))
mstore(0xb8a0, mload(0xb700))
mstore(0xb8c0, mload(0xb720))
                }
{
                    mstore(0xb8e0, mload(0xb7c0))
mstore(0xb900, mload(0xb7e0))
mstore(0xb920, mload(0xb800))
mstore(0xb940, mload(0xb820))
                }
success := and(eq(staticcall(gas(), 0xb, 0xb860, 0x100, 0xb860, 0x80), 1), success)
{
                    mstore(0xb960, mload(0xd20))
mstore(0xb980, mload(0xd40))
mstore(0xb9a0, mload(0xd60))
mstore(0xb9c0, mload(0xd80))
                }
mstore(0xb9e0, mload(0x8460))
success := and(eq(staticcall(gas(), 0xc, 0xb960, 0xa0, 0xb960, 0x80), 1), success)
{
                    mstore(0xba00, mload(0xb860))
mstore(0xba20, mload(0xb880))
mstore(0xba40, mload(0xb8a0))
mstore(0xba60, mload(0xb8c0))
                }
{
                    mstore(0xba80, mload(0xb960))
mstore(0xbaa0, mload(0xb980))
mstore(0xbac0, mload(0xb9a0))
mstore(0xbae0, mload(0xb9c0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xba00, 0x100, 0xba00, 0x80), 1), success)
{
                    mstore(0xbb00, mload(0xda0))
mstore(0xbb20, mload(0xdc0))
mstore(0xbb40, mload(0xde0))
mstore(0xbb60, mload(0xe00))
                }
mstore(0xbb80, mload(0x8480))
success := and(eq(staticcall(gas(), 0xc, 0xbb00, 0xa0, 0xbb00, 0x80), 1), success)
{
                    mstore(0xbba0, mload(0xba00))
mstore(0xbbc0, mload(0xba20))
mstore(0xbbe0, mload(0xba40))
mstore(0xbc00, mload(0xba60))
                }
{
                    mstore(0xbc20, mload(0xbb00))
mstore(0xbc40, mload(0xbb20))
mstore(0xbc60, mload(0xbb40))
mstore(0xbc80, mload(0xbb60))
                }
success := and(eq(staticcall(gas(), 0xb, 0xbba0, 0x100, 0xbba0, 0x80), 1), success)
{
                    mstore(0xbca0, mload(0xe20))
mstore(0xbcc0, mload(0xe40))
mstore(0xbce0, mload(0xe60))
mstore(0xbd00, mload(0xe80))
                }
mstore(0xbd20, mload(0x84a0))
success := and(eq(staticcall(gas(), 0xc, 0xbca0, 0xa0, 0xbca0, 0x80), 1), success)
{
                    mstore(0xbd40, mload(0xbba0))
mstore(0xbd60, mload(0xbbc0))
mstore(0xbd80, mload(0xbbe0))
mstore(0xbda0, mload(0xbc00))
                }
{
                    mstore(0xbdc0, mload(0xbca0))
mstore(0xbde0, mload(0xbcc0))
mstore(0xbe00, mload(0xbce0))
mstore(0xbe20, mload(0xbd00))
                }
success := and(eq(staticcall(gas(), 0xb, 0xbd40, 0x100, 0xbd40, 0x80), 1), success)
{
                    mstore(0xbe40, mload(0xea0))
mstore(0xbe60, mload(0xec0))
mstore(0xbe80, mload(0xee0))
mstore(0xbea0, mload(0xf00))
                }
mstore(0xbec0, mload(0x84c0))
success := and(eq(staticcall(gas(), 0xc, 0xbe40, 0xa0, 0xbe40, 0x80), 1), success)
{
                    mstore(0xbee0, mload(0xbd40))
mstore(0xbf00, mload(0xbd60))
mstore(0xbf20, mload(0xbd80))
mstore(0xbf40, mload(0xbda0))
                }
{
                    mstore(0xbf60, mload(0xbe40))
mstore(0xbf80, mload(0xbe60))
mstore(0xbfa0, mload(0xbe80))
mstore(0xbfc0, mload(0xbea0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xbee0, 0x100, 0xbee0, 0x80), 1), success)
{
                    mstore(0xbfe0, mload(0xf20))
mstore(0xc000, mload(0xf40))
mstore(0xc020, mload(0xf60))
mstore(0xc040, mload(0xf80))
                }
mstore(0xc060, mload(0x84e0))
success := and(eq(staticcall(gas(), 0xc, 0xbfe0, 0xa0, 0xbfe0, 0x80), 1), success)
{
                    mstore(0xc080, mload(0xbee0))
mstore(0xc0a0, mload(0xbf00))
mstore(0xc0c0, mload(0xbf20))
mstore(0xc0e0, mload(0xbf40))
                }
{
                    mstore(0xc100, mload(0xbfe0))
mstore(0xc120, mload(0xc000))
mstore(0xc140, mload(0xc020))
mstore(0xc160, mload(0xc040))
                }
success := and(eq(staticcall(gas(), 0xb, 0xc080, 0x100, 0xc080, 0x80), 1), success)
{
                    mstore(0xc180, mload(0x1b20))
mstore(0xc1a0, mload(0x1b40))
mstore(0xc1c0, mload(0x1b60))
mstore(0xc1e0, mload(0x1b80))
                }
mstore(0xc200, mload(0x8500))
success := and(eq(staticcall(gas(), 0xc, 0xc180, 0xa0, 0xc180, 0x80), 1), success)
{
                    mstore(0xc220, mload(0xc080))
mstore(0xc240, mload(0xc0a0))
mstore(0xc260, mload(0xc0c0))
mstore(0xc280, mload(0xc0e0))
                }
{
                    mstore(0xc2a0, mload(0xc180))
mstore(0xc2c0, mload(0xc1a0))
mstore(0xc2e0, mload(0xc1c0))
mstore(0xc300, mload(0xc1e0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xc220, 0x100, 0xc220, 0x80), 1), success)
{
                    mstore(0xc320, mload(0x1ba0))
mstore(0xc340, mload(0x1bc0))
mstore(0xc360, mload(0x1be0))
mstore(0xc380, mload(0x1c00))
                }
mstore(0xc3a0, mload(0x8520))
success := and(eq(staticcall(gas(), 0xc, 0xc320, 0xa0, 0xc320, 0x80), 1), success)
{
                    mstore(0xc3c0, mload(0xc220))
mstore(0xc3e0, mload(0xc240))
mstore(0xc400, mload(0xc260))
mstore(0xc420, mload(0xc280))
                }
{
                    mstore(0xc440, mload(0xc320))
mstore(0xc460, mload(0xc340))
mstore(0xc480, mload(0xc360))
mstore(0xc4a0, mload(0xc380))
                }
success := and(eq(staticcall(gas(), 0xb, 0xc3c0, 0x100, 0xc3c0, 0x80), 1), success)
{
                    mstore(0xc4c0, mload(0x1c20))
mstore(0xc4e0, mload(0x1c40))
mstore(0xc500, mload(0x1c60))
mstore(0xc520, mload(0x1c80))
                }
mstore(0xc540, mload(0x8540))
success := and(eq(staticcall(gas(), 0xc, 0xc4c0, 0xa0, 0xc4c0, 0x80), 1), success)
{
                    mstore(0xc560, mload(0xc3c0))
mstore(0xc580, mload(0xc3e0))
mstore(0xc5a0, mload(0xc400))
mstore(0xc5c0, mload(0xc420))
                }
{
                    mstore(0xc5e0, mload(0xc4c0))
mstore(0xc600, mload(0xc4e0))
mstore(0xc620, mload(0xc500))
mstore(0xc640, mload(0xc520))
                }
success := and(eq(staticcall(gas(), 0xb, 0xc560, 0x100, 0xc560, 0x80), 1), success)
{
                    mstore(0xc660, mload(0x1ca0))
mstore(0xc680, mload(0x1cc0))
mstore(0xc6a0, mload(0x1ce0))
mstore(0xc6c0, mload(0x1d00))
                }
mstore(0xc6e0, mload(0x8560))
success := and(eq(staticcall(gas(), 0xc, 0xc660, 0xa0, 0xc660, 0x80), 1), success)
{
                    mstore(0xc700, mload(0xc560))
mstore(0xc720, mload(0xc580))
mstore(0xc740, mload(0xc5a0))
mstore(0xc760, mload(0xc5c0))
                }
{
                    mstore(0xc780, mload(0xc660))
mstore(0xc7a0, mload(0xc680))
mstore(0xc7c0, mload(0xc6a0))
mstore(0xc7e0, mload(0xc6c0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xc700, 0x100, 0xc700, 0x80), 1), success)
{
                    mstore(0xc800, mload(0x1a40))
mstore(0xc820, mload(0x1a60))
mstore(0xc840, mload(0x1a80))
mstore(0xc860, mload(0x1aa0))
                }
mstore(0xc880, mload(0x8580))
success := and(eq(staticcall(gas(), 0xc, 0xc800, 0xa0, 0xc800, 0x80), 1), success)
{
                    mstore(0xc8a0, mload(0xc700))
mstore(0xc8c0, mload(0xc720))
mstore(0xc8e0, mload(0xc740))
mstore(0xc900, mload(0xc760))
                }
{
                    mstore(0xc920, mload(0xc800))
mstore(0xc940, mload(0xc820))
mstore(0xc960, mload(0xc840))
mstore(0xc980, mload(0xc860))
                }
success := and(eq(staticcall(gas(), 0xb, 0xc8a0, 0x100, 0xc8a0, 0x80), 1), success)
{
                    mstore(0xc9a0, mload(0x1140))
mstore(0xc9c0, mload(0x1160))
mstore(0xc9e0, mload(0x1180))
mstore(0xca00, mload(0x11a0))
                }
mstore(0xca20, mload(0x85a0))
success := and(eq(staticcall(gas(), 0xc, 0xc9a0, 0xa0, 0xc9a0, 0x80), 1), success)
{
                    mstore(0xca40, mload(0xc8a0))
mstore(0xca60, mload(0xc8c0))
mstore(0xca80, mload(0xc8e0))
mstore(0xcaa0, mload(0xc900))
                }
{
                    mstore(0xcac0, mload(0xc9a0))
mstore(0xcae0, mload(0xc9c0))
mstore(0xcb00, mload(0xc9e0))
mstore(0xcb20, mload(0xca00))
                }
success := and(eq(staticcall(gas(), 0xb, 0xca40, 0x100, 0xca40, 0x80), 1), success)
{
                    mstore(0xcb40, mload(0x11c0))
mstore(0xcb60, mload(0x11e0))
mstore(0xcb80, mload(0x1200))
mstore(0xcba0, mload(0x1220))
                }
mstore(0xcbc0, mload(0x85c0))
success := and(eq(staticcall(gas(), 0xc, 0xcb40, 0xa0, 0xcb40, 0x80), 1), success)
{
                    mstore(0xcbe0, mload(0xca40))
mstore(0xcc00, mload(0xca60))
mstore(0xcc20, mload(0xca80))
mstore(0xcc40, mload(0xcaa0))
                }
{
                    mstore(0xcc60, mload(0xcb40))
mstore(0xcc80, mload(0xcb60))
mstore(0xcca0, mload(0xcb80))
mstore(0xccc0, mload(0xcba0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xcbe0, 0x100, 0xcbe0, 0x80), 1), success)
{
                    mstore(0xcce0, mload(0x1240))
mstore(0xcd00, mload(0x1260))
mstore(0xcd20, mload(0x1280))
mstore(0xcd40, mload(0x12a0))
                }
mstore(0xcd60, mload(0x85e0))
success := and(eq(staticcall(gas(), 0xc, 0xcce0, 0xa0, 0xcce0, 0x80), 1), success)
{
                    mstore(0xcd80, mload(0xcbe0))
mstore(0xcda0, mload(0xcc00))
mstore(0xcdc0, mload(0xcc20))
mstore(0xcde0, mload(0xcc40))
                }
{
                    mstore(0xce00, mload(0xcce0))
mstore(0xce20, mload(0xcd00))
mstore(0xce40, mload(0xcd20))
mstore(0xce60, mload(0xcd40))
                }
success := and(eq(staticcall(gas(), 0xb, 0xcd80, 0x100, 0xcd80, 0x80), 1), success)
{
                    mstore(0xce80, mload(0x1860))
mstore(0xcea0, mload(0x1880))
mstore(0xcec0, mload(0x18a0))
mstore(0xcee0, mload(0x18c0))
                }
mstore(0xcf00, mload(0x8600))
success := and(eq(staticcall(gas(), 0xc, 0xce80, 0xa0, 0xce80, 0x80), 1), success)
{
                    mstore(0xcf20, mload(0xcd80))
mstore(0xcf40, mload(0xcda0))
mstore(0xcf60, mload(0xcdc0))
mstore(0xcf80, mload(0xcde0))
                }
{
                    mstore(0xcfa0, mload(0xce80))
mstore(0xcfc0, mload(0xcea0))
mstore(0xcfe0, mload(0xcec0))
mstore(0xd000, mload(0xcee0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xcf20, 0x100, 0xcf20, 0x80), 1), success)
{
                    mstore(0xd020, mload(0x18e0))
mstore(0xd040, mload(0x1900))
mstore(0xd060, mload(0x1920))
mstore(0xd080, mload(0x1940))
                }
mstore(0xd0a0, mload(0x8620))
success := and(eq(staticcall(gas(), 0xc, 0xd020, 0xa0, 0xd020, 0x80), 1), success)
{
                    mstore(0xd0c0, mload(0xcf20))
mstore(0xd0e0, mload(0xcf40))
mstore(0xd100, mload(0xcf60))
mstore(0xd120, mload(0xcf80))
                }
{
                    mstore(0xd140, mload(0xd020))
mstore(0xd160, mload(0xd040))
mstore(0xd180, mload(0xd060))
mstore(0xd1a0, mload(0xd080))
                }
success := and(eq(staticcall(gas(), 0xb, 0xd0c0, 0x100, 0xd0c0, 0x80), 1), success)
{
                    mstore(0xd1c0, mload(0x1760))
mstore(0xd1e0, mload(0x1780))
mstore(0xd200, mload(0x17a0))
mstore(0xd220, mload(0x17c0))
                }
mstore(0xd240, mload(0x8640))
success := and(eq(staticcall(gas(), 0xc, 0xd1c0, 0xa0, 0xd1c0, 0x80), 1), success)
{
                    mstore(0xd260, mload(0xd0c0))
mstore(0xd280, mload(0xd0e0))
mstore(0xd2a0, mload(0xd100))
mstore(0xd2c0, mload(0xd120))
                }
{
                    mstore(0xd2e0, mload(0xd1c0))
mstore(0xd300, mload(0xd1e0))
mstore(0xd320, mload(0xd200))
mstore(0xd340, mload(0xd220))
                }
success := and(eq(staticcall(gas(), 0xb, 0xd260, 0x100, 0xd260, 0x80), 1), success)
{
                    mstore(0xd360, mload(0x17e0))
mstore(0xd380, mload(0x1800))
mstore(0xd3a0, mload(0x1820))
mstore(0xd3c0, mload(0x1840))
                }
mstore(0xd3e0, mload(0x8660))
success := and(eq(staticcall(gas(), 0xc, 0xd360, 0xa0, 0xd360, 0x80), 1), success)
{
                    mstore(0xd400, mload(0xd260))
mstore(0xd420, mload(0xd280))
mstore(0xd440, mload(0xd2a0))
mstore(0xd460, mload(0xd2c0))
                }
{
                    mstore(0xd480, mload(0xd360))
mstore(0xd4a0, mload(0xd380))
mstore(0xd4c0, mload(0xd3a0))
mstore(0xd4e0, mload(0xd3c0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xd400, 0x100, 0xd400, 0x80), 1), success)
{
                    mstore(0xd500, mload(0x15a0))
mstore(0xd520, mload(0x15c0))
mstore(0xd540, mload(0x15e0))
mstore(0xd560, mload(0x1600))
                }
mstore(0xd580, mload(0x8680))
success := and(eq(staticcall(gas(), 0xc, 0xd500, 0xa0, 0xd500, 0x80), 1), success)
{
                    mstore(0xd5a0, mload(0xd400))
mstore(0xd5c0, mload(0xd420))
mstore(0xd5e0, mload(0xd440))
mstore(0xd600, mload(0xd460))
                }
{
                    mstore(0xd620, mload(0xd500))
mstore(0xd640, mload(0xd520))
mstore(0xd660, mload(0xd540))
mstore(0xd680, mload(0xd560))
                }
success := and(eq(staticcall(gas(), 0xb, 0xd5a0, 0x100, 0xd5a0, 0x80), 1), success)
{
                    mstore(0xd6a0, mload(0x2500))
mstore(0xd6c0, mload(0x2520))
mstore(0xd6e0, mload(0x2540))
mstore(0xd700, mload(0x2560))
                }
mstore(0xd720, mload(0x86a0))
success := and(eq(staticcall(gas(), 0xc, 0xd6a0, 0xa0, 0xd6a0, 0x80), 1), success)
{
                    mstore(0xd740, mload(0xd5a0))
mstore(0xd760, mload(0xd5c0))
mstore(0xd780, mload(0xd5e0))
mstore(0xd7a0, mload(0xd600))
                }
{
                    mstore(0xd7c0, mload(0xd6a0))
mstore(0xd7e0, mload(0xd6c0))
mstore(0xd800, mload(0xd6e0))
mstore(0xd820, mload(0xd700))
                }
success := and(eq(staticcall(gas(), 0xb, 0xd740, 0x100, 0xd740, 0x80), 1), success)
{
                    mstore(0xd840, mload(0x26c0))
mstore(0xd860, mload(0x26e0))
mstore(0xd880, mload(0x2700))
mstore(0xd8a0, mload(0x2720))
                }
mstore(0xd8c0, mload(0x8800))
success := and(eq(staticcall(gas(), 0xc, 0xd840, 0xa0, 0xd840, 0x80), 1), success)
{
                    mstore(0xd8e0, mload(0xd740))
mstore(0xd900, mload(0xd760))
mstore(0xd920, mload(0xd780))
mstore(0xd940, mload(0xd7a0))
                }
{
                    mstore(0xd960, mload(0xd840))
mstore(0xd980, mload(0xd860))
mstore(0xd9a0, mload(0xd880))
mstore(0xd9c0, mload(0xd8a0))
                }
success := and(eq(staticcall(gas(), 0xb, 0xd8e0, 0x100, 0xd8e0, 0x80), 1), success)

        {
            mstore(0xd9e0, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f)
            mstore(0xda00, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)
            mstore(0xda20, 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4)
            mstore(0xda40, 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
        }
{
                    mstore(0xda60, mload(0xd8e0))
mstore(0xda80, mload(0xd900))
mstore(0xdaa0, mload(0xd920))
mstore(0xdac0, mload(0xd940))
                }
mstore(0xdae0, 0x00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051)
mstore(0xdb00, 0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8)
mstore(0xdb20, 0x0000000000000000000000000000000013e02b6052719f607dacd3a088274f65)
mstore(0xdb40, 0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e)
mstore(0xdb60, 0x000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a)
mstore(0xdb80, 0xadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801)
mstore(0xdba0, 0x000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99)
mstore(0xdbc0, 0xcb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be)
{
                    mstore(0xdbe0, mload(0x26c0))
mstore(0xdc00, mload(0x26e0))
mstore(0xdc20, mload(0x2700))
mstore(0xdc40, mload(0x2720))
                }
mstore(0xdc60, 0x0000000000000000000000000000000003c7c80cf801193266282fc3e51212bc)
mstore(0xdc80, 0xaccde1b03aeeb93f58e51eacc4734d1bfbe65abafdf5e46f6dcd4aed7f682afb)
mstore(0xdca0, 0x000000000000000000000000000000000cfc788b7bc9142a04f1d1ec5678ea2a)
mstore(0xdcc0, 0x314a3987883799bf25c86a9f38037969503c4d87feeea3b8636792c96a902cc8)
mstore(0xdce0, 0x000000000000000000000000000000000f21b3cae4d057649e10b28445e8c477)
mstore(0xdd00, 0xc0a17595de53e85c6afe8b4042f207938dd14f1572140c7d171a670e4cdb4cb4)
mstore(0xdd20, 0x0000000000000000000000000000000015ed0fd0d24e235a13599b6f2aea2033)
mstore(0xdd40, 0x2f02610e0ca3ef35eeb9f0560c9ccc522e276b8f52408f09f61f4ac65d11e157)
success := and(eq(staticcall(gas(), 0xf, 0xda60, 0x300, 0xda60, 0x20), 1), success)
success := and(eq(mload(0xda60), 1), success)

            // Revert if anything fails
            if iszero(success) { revert(0, 0) }

            // Return empty bytes on success
            return(0, 0)

        }
    }
}
        