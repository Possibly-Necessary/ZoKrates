// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x067e10dad26bc4e7eabf1bac6145daac63f3be13de57001796edaea1ae255b55), uint256(0x0ad290d17e9692bea8a86705ee5fe2f869181cf88f88d7d30062f65885fda61f));
        vk.beta = Pairing.G2Point([uint256(0x236e2e6d0a82ece3c7cbae4c0fb9d0ea34f592c8346a2953f4b6f57ba5734101), uint256(0x19aff43de7f672e25044bbcc9ee8d7f171118b036262ee95a97484f45634ba28)], [uint256(0x2ed7943cbdb54bc91f9603140f489728cd442cabbbc539b5c3ad14b0065ebfc0), uint256(0x246454b477cfe4c961259c1a552f0143fe13ce39ac61e54a01563ae39fb18102)]);
        vk.gamma = Pairing.G2Point([uint256(0x0be9d1cb30a7b4d8c935e04409d7700c327b4296534adcf0f59d4a66dc76e4d7), uint256(0x0c5ba701398b3ada97eaf9434a2358fc2d901ba146f38aabfe092956cc375ecd)], [uint256(0x0fe1741e17c90bdcdbc064ef31a97f538ad6d927d83f96c2eed3daa588fd8fda), uint256(0x15aeccfa7c460ffbc1d5bb2beff9170eb3deb486d379c79fa1e85ca5cd20601a)]);
        vk.delta = Pairing.G2Point([uint256(0x0d592917de9ef7e8c0727b14bd3f1624dffa6a33210e214c0c19de910dec3bd1), uint256(0x240eda68cffcd3f42804255cedf83c7c7cfb01ac566cad9c9ca1fc4f36cb6f4c)], [uint256(0x22e266cbcbecaf2ad55c24a3ab659d23a11aebcbf7d05375380cc2a168e0cfae), uint256(0x1f5ffb063b59963026598906bd89c7376e31ceaca9d2d19d1fc0de8fd9c15451)]);
        vk.gamma_abc = new Pairing.G1Point[](6);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2b2d8f4dd662f15be8f4a17d5e5e713dbcc7caa3db27a507b601840e19d65c5c), uint256(0x1dbfb80195068f77feb8bf5e5f1c6c018251c7014e4eaebdf4f9cae1f14d20a5));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x12e5c7a8e12a7ef06b7ede7e49a34bdee6ac2b067d1907e10186c9eaa3b091d1), uint256(0x03d3de9a62f14c74baa02899b589b4d65556bd272eb1dafc43842190c181db6b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x03b2da4ba59d34965f5b96d0cec082846e0cbbf97298d2c6be3f30b66dbd0fb0), uint256(0x0bfddf0fb62a996dc329785bb72fb98becc82b86bc69c910982e0fe12ee0a1ed));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x253e3ecb9aa7b0ec41fc9896c14f1b3d134aa80250cb9eea3f3a223ff186de82), uint256(0x048af934b903b61db0d34d030a6d6ccd971d3f9e3d5aae1b042dded95a5df930));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x01b48a42ce907e3b6cfd829cbae1ec4b4bc935cce799b568df97a2cf0f436a19), uint256(0x2d12a0a4a6edd91e2aa27b619de9e4f7a0cad1e509aab23be96093e7108b8342));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x175eb728f6d1033309764efcfcd8b6f7fc91d053b82d078ea9932e38babd79e8), uint256(0x1e4acee5187ce7730355b65e7902a2b2a3fbe6c133866fe4db4126ce541ab6a0));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[5] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](5);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
