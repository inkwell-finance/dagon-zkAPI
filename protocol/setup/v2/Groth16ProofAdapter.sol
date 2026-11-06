// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title Groth16ProofAdapter
/// @notice Circuit-specific zkAPI v2 verifier generated from the selected setup.
contract Groth16ProofAdapter is IZkApiProofAdapter {
    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant BASE_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point { uint256 x; uint256 y; }
    // Coordinates use arkworks order: c0 (real), then c1 (imaginary).
    struct G2Point { uint256[2] x; uint256[2] y; }
    struct Proof { G1Point a; G2Point b; G1Point c; }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[12] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            uint256(inputs.requestTime),
            uint256(inputs.solvencyBound),
            inputs.requestNullifier,
            inputs.authorizationTag,
            inputs.anonymousCommitmentX,
            inputs.anonymousCommitmentY
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyRequest(values, parsed)) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[16] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.registration,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            inputs.clearanceSigningKeyX,
            inputs.clearanceSigningKeyY,
            (uint256(inputs.noteId) << 192) | (uint256(inputs.depositAmount) << 64) | uint256(inputs.expiryTs),
            uint256(inputs.finalBalance),
            uint256(uint160(inputs.destination)),
            inputs.withdrawalNullifier,
            inputs.hasClearance ? uint256(1) : uint256(0),
            inputs.nextNullifier,
            uint256(inputs.conceded),
            uint256(inputs.validUntil)
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyWithdrawal(values, parsed)) revert Errors.InvalidProof();
    }

    function _verifyRequest(uint256[12] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _requestIc(0);
        for (uint256 i = 0; i < 12; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_requestIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _requestAlpha(), _requestBeta(),
            accumulator, _requestGamma(),
            proof.c, _requestDelta()
        );
    }

    function _verifyWithdrawal(uint256[16] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _withdrawalIc(0);
        for (uint256 i = 0; i < 16; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_withdrawalIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _withdrawalAlpha(), _withdrawalBeta(),
            accumulator, _withdrawalGamma(),
            proof.c, _withdrawalDelta()
        );
    }

    function _decodeProof(bytes calldata encoded) private pure returns (Proof memory proof, bool valid) {
        if (encoded.length != 256) return (proof, false);
        uint256[8] memory words;
        assembly ("memory-safe") {
            let start := encoded.offset
            mstore(words, calldataload(start))
            mstore(add(words, 0x20), calldataload(add(start, 0x20)))
            mstore(add(words, 0x40), calldataload(add(start, 0x40)))
            mstore(add(words, 0x60), calldataload(add(start, 0x60)))
            mstore(add(words, 0x80), calldataload(add(start, 0x80)))
            mstore(add(words, 0xa0), calldataload(add(start, 0xa0)))
            mstore(add(words, 0xc0), calldataload(add(start, 0xc0)))
            mstore(add(words, 0xe0), calldataload(add(start, 0xe0)))
        }
        for (uint256 i = 0; i < 8; ++i) if (words[i] >= BASE_MODULUS) return (proof, false);
        proof.a = G1Point(words[0], words[1]);
        proof.b = G2Point([words[2], words[3]], [words[4], words[5]]);
        proof.c = G1Point(words[6], words[7]);
        return (proof, true);
    }

    function _negate(G1Point memory point) private pure returns (G1Point memory) {
        if (point.x == 0 && point.y == 0) return G1Point(0, 0);
        return G1Point(point.x, BASE_MODULUS - (point.y % BASE_MODULUS));
    }

    function _add(G1Point memory a, G1Point memory b) private view returns (G1Point memory result, bool ok) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        assembly ("memory-safe") { ok := staticcall(gas(), 6, input, 0x80, result, 0x40) }
    }

    function _scalarMul(G1Point memory point, uint256 scalar)
        private view returns (G1Point memory result, bool ok)
    {
        uint256[3] memory input = [point.x, point.y, scalar];
        assembly ("memory-safe") { ok := staticcall(gas(), 7, input, 0x60, result, 0x40) }
    }

    function _pairing(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) private view returns (bool) {
        uint256[24] memory input;
        _writePair(input, 0, a1, a2);
        _writePair(input, 6, b1, b2);
        _writePair(input, 12, c1, c2);
        _writePair(input, 18, d1, d2);
        uint256[1] memory output;
        bool ok;
        assembly ("memory-safe") { ok := staticcall(gas(), 8, input, 0x300, output, 0x20) }
        return ok && output[0] == 1;
    }

    function _writePair(uint256[24] memory input, uint256 offset, G1Point memory g1, G2Point memory g2)
        private pure
    {
        input[offset] = g1.x;
        input[offset + 1] = g1.y;
        // EIP-197 expects the imaginary coefficient before the real coefficient.
        input[offset + 2] = g2.x[1];
        input[offset + 3] = g2.x[0];
        input[offset + 4] = g2.y[1];
        input[offset + 5] = g2.y[0];
    }

    function _requestAlpha() private pure returns (G1Point memory) {
        return G1Point(0x13ed877d060fe5cb155d3c01803757c290a2bb3419490f96ec4221a0422e0385, 0x18360b240a562717634cbf28f42895269fbda7a4b1709c07df839b5cb81e51f9);
    }

    function _requestBeta() private pure returns (G2Point memory) {
        return G2Point([0x23a6d75d19a992ab204a578e199934c0dc1d70218695fa8825d67ac21d95be47, 0x1f8d7b49b7ad3ac06c484a2f0effaa09bfe19b4b3530ed1c79ca5ea4ad43b2e9], [0x159adbb9ffb9740acd532e37b158035362e997eee15c64c98c32926fab490c37, 0x1f36e26d65084ec13b694ce9996a03ac0f48d41227ddaa78d791e29d53ab36c7]);
    }

    function _requestGamma() private pure returns (G2Point memory) {
        return G2Point([0x226f8efff02fcaa6eac19a7a983e11e3dfab7e80bddc966c356c3d8bdfaa2dc0, 0x0b972827a839433e151c8654f3127e95ff329cfc8dfff998e5cae8bc3bea0be9], [0x01ddb35fff6d48da444ed0fdce95be7b4e00be222817dbb944d9602d601389da, 0x2666402ac191a45a25bd140aa1fcef6f2ffd4ae94e2cdfc99c7004f2a3054327]);
    }

    function _requestDelta() private pure returns (G2Point memory) {
        return G2Point([0x240774ea31062b35534c59c042d64ad932eab91656e212552bd9ca3ef979fa6b, 0x075ce2732f8ae12cd734b9f91b5373147817988abb802ca46a1399784f3c44d0], [0x081b884e96640c48848c93b9051b55ae43f8347d2b473c7c375445c48c4db218, 0x2ebd8758a56e2d6385b40460a11b009f213f863e3495cb48b584c384393b77ca]);
    }

    function _requestIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x1ff38d135a726f2846031deaf3f1e276d534d795d9b8fbe88b468a583c17e56c, 0x0901e8e70ccb844afe07c6eb5f93ea9f04643f1967a7b11e98023c02a2e6db65);
        if (index == 1) return G1Point(0x21bc2684a31b540e12b9c594e2b9ceb257448e6afd359b6911abfb975fb9b827, 0x1f914cc50f01df44aeff29af54b807dfcf378f4238d245e10985901eacae3245);
        if (index == 2) return G1Point(0x190161425e00d4b27f88936c20c6d9c9fcb41c37b97ae9dd1955d7b7779886de, 0x0dc358f735d2742d899252e0cd7e21a8570d1852cf2dd728676f98785c95a52b);
        if (index == 3) return G1Point(0x2ff3275740b9a916717cdd9926fb4e1d442aa57e98e77bdfaeb83abb79e3b8ef, 0x0a07667c7d6f091c35046f399920cd84c8e0b93ef43c8af7f89de12e08902697);
        if (index == 4) return G1Point(0x20c2a70ef5b7eb91cef68c2b8fbdbd50f3d13a775c5db77d2879343eae734699, 0x24d0dbdb4d4c35beddba019df608b093d5b2c8191ecba52c005a43acdd6af546);
        if (index == 5) return G1Point(0x0d3a2e39c834b5a3f49dc00a0d59c36ce72c9eae92a0fcf81b26fa4213218e0b, 0x2bf5692ceff369b5ad32db5c8ac35ddd9255e1ee2ffbed4a4cc0382067b90218);
        if (index == 6) return G1Point(0x06e303fc7aeef6ee1953152ddf1fa6762f5e9e99b8d69c4e719ee05e08d1e038, 0x000944be83c38d15d920086a8a7d7b93c4b619cea6c04e505e1f8be8e52f0a99);
        if (index == 7) return G1Point(0x0e9a382b2498b70e57f66cd6ab82e8572281335ad5c5a4997353c1f46237972d, 0x29e5aa70c61e5ff57ad91684cd038e3f82e7e438cc1fc0a26fc7ea0b7744e0c8);
        if (index == 8) return G1Point(0x2b9a9d10abe0336c3d3f43efb491de6633b2f5b84a3b9a71fa863527258626fc, 0x019b24cf9292226042a9c456cb39d9169a5ae7ef2cd1780f8cee09d11a57aedd);
        if (index == 9) return G1Point(0x10935c94629749b0947b890e682cc4f604e5ed4438738be31ea343e5c04c9cab, 0x2551aff0cf2a612bebdd622342a7901f1be977f061ed81be5bde69e31312d443);
        if (index == 10) return G1Point(0x0fa0a8e7e6b699681ca1c763688ca209c40286eef12c799068ecda41be4aa394, 0x19b372cab103a3429b5622f39a671783a2c46f337e0eeb930fc71719da6d7205);
        if (index == 11) return G1Point(0x0d2a3ac6ee7a33c26c4b1c33e35e5d74d857cc5432f62e3486f2e992c132f396, 0x04e652ddde3ff3ee417c1964040eb42eb217534901493e5e9af094b7030d091b);
        if (index == 12) return G1Point(0x0f1a6171befc14f66b2a9f36ccc1f5d164cbe7ed0b0dbe316dec9e871d1239f5, 0x072e968e0d0f8ebcef99fa15b1716a9343d39651273793bcde3d4dc51f68692f);
        revert Errors.InvalidProof();
    }

    function _withdrawalAlpha() private pure returns (G1Point memory) {
        return G1Point(0x098b0a2ee701b908c119e46d5afe161fd38e7f7af50db91fb3e4a5425182164e, 0x04ef6421df9c6554b5cef3eb326cac299b764e70b691da607040629cc4052f7a);
    }

    function _withdrawalBeta() private pure returns (G2Point memory) {
        return G2Point([0x15b11044d81ff413d58c29b437f297a6914eec07d301c9f5c2ac497fac7f21a1, 0x1fa272ae0b1d61069b697c48fb2c4c487d33ff448a59e55565cf4c94f5684066], [0x127cfb18eb22d186cc87867cce4e36029de6c120eb907a48c001bade6346f9e0, 0x1eb0d3b0920ba425e484ecc3a8779e138703e455af77c763be9d4dc25b51424e]);
    }

    function _withdrawalGamma() private pure returns (G2Point memory) {
        return G2Point([0x039e9f8fa5496afe038e2fbee6a3d76fd3cf04ca613146bbc2d7649a526f2834, 0x0df427e545aea37c88f5fc0b3a4f0255af8cf030f90f926f063b9dd087abeca9], [0x1deaa62c928e76f1d544a4c44e78bcee93995d1e0afbf7f1a45e60c5e0ae591e, 0x22a1b41f6a4713b9966be35cc1d6c25166d3626786f91b09fd5656de1a600483]);
    }

    function _withdrawalDelta() private pure returns (G2Point memory) {
        return G2Point([0x0c0b0c886a16a3b7c0db8ea7f82f8d214f8b587fd5db47a3b661746906be4658, 0x17252fae8b090220675ba65c424ca3fc740d78a51968593c8519ccf33a16f3f2], [0x042b49809eff94ee200e710069f5bfe882bc2da2dc68a35f23927e199f0edbe2, 0x18d64af837c9c050d863453b9714db3e5d66f2a601eea1f430339704979e1bdd]);
    }

    function _withdrawalIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x173deb9e1c05bf060519025d400677fba61f3838643618d725d55c65d664db85, 0x02fef5e57ffbbf3864198366b2e4caafc0eb34726ba9c7cc4a213216285f4379);
        if (index == 1) return G1Point(0x07b72f808f890b9636bc0b7b10df4e9834b48f710722edc4664e09a7108c04d7, 0x1a04d05dc7de5e7cdcc310e5cf029dc708739450f5a99b68dbdff8ddddaaf144);
        if (index == 2) return G1Point(0x03311f8bae9c0e6858f733b15e1b2e4ecaec6dcfd9b8009565b170f11f51d0d0, 0x1b8146d6872788c6af7f4a66c5798088896df2b647992d80608faed5dbc4725d);
        if (index == 3) return G1Point(0x22927a087acf169b4926ac389653942cc24db8701c5cb86ded8f56f64abd6d1e, 0x2e066be5122a855d97847ea7550cb305ada3bea48d6c245c1bf0ef9f0aa245ba);
        if (index == 4) return G1Point(0x12c66447a6ab3c1dadc9abe645d8da8ccd48efce841cc49c5c80c0d0d55d69e1, 0x23c8095a61d9df017e207d003c0306a40d074b3890001096c4858f1956d690bd);
        if (index == 5) return G1Point(0x2ca5f4c406d214064e83dfa942d0d17ae026bf50782dafa09e4a533bbd73e371, 0x1ed9491bba83e55fbb843935c1530cf0867f06e2eb599471cfaffa9e6428ed3f);
        if (index == 6) return G1Point(0x27cf09d03f17e7ce9a2f663f0739719bda3e27a3abe53a696b3d1bfbd13c7657, 0x2099911ef749ee45a9e77217fd188f84bd5429daf1ba7fc2930f0fad4ec3908d);
        if (index == 7) return G1Point(0x106bcbbda20997f461b874c97c3bfeb15dba24ce8659d943c81995891303cabd, 0x064ba1ea4613945752deb3bdb2de65281cf0e0175110bec4af7d06c45f80137b);
        if (index == 8) return G1Point(0x114129196d25b0001bf41bfcd7650ba34575c3a01702048dd958c9977c43296a, 0x2fddbbd19f4b38b5f556c4ab57b0655f80c8c31db2b0cdfbbf78c5c8d0c69028);
        if (index == 9) return G1Point(0x2a6929f599d5146e0cecbbb10a96586f0ab1d3ef143e8bf39687d22276abc6eb, 0x2035653a502c638aae3092e369aba11d395646e253d21aeeb4ace015828938b0);
        if (index == 10) return G1Point(0x18b21776882f888b4052812dac3287be2d85378c193be70f923bcb6b88d718c1, 0x2ce010a517a8e6a629448afc9e2ec011433d5be445c11920e79f6aa6d593ebe7);
        if (index == 11) return G1Point(0x21075f87b89fa65e9c722dbf12518f6a4c692e89b727007065816fbab391a5fb, 0x04b2f3ccec9a3d55e762e0a9c00d870ad2ab50eccff5b3c61c46d898896f6583);
        if (index == 12) return G1Point(0x076b7ffb64163f6c1acd92d4285f53e7ba4a5518a4d1a99a86c7fe292c0f3ab1, 0x0595e0ffa52d1f17244796a91b19a0fb776a4143e53d4917ab01e2bd486f8eed);
        if (index == 13) return G1Point(0x02cf05fcb9fd2d7284852d65dd9a324f9a2a4ea836a0e18c35f7684dd55fde5d, 0x1a442e3dc134aca9b8add2c9c5798991a20a3794460b69636e7e7b6c913512a6);
        if (index == 14) return G1Point(0x0075c4510a727ffffa93989fa3eb0d660d515a8ac4ec3e7a7ce0a1e8d415af6e, 0x14c3956ad65391e1639c5a272c1485f77330c30ebc12575ca177b5edbb6d37bb);
        if (index == 15) return G1Point(0x07b063019cee3f2ff46fff3bcbb244c42110161abdffa26e838b777b1e5e1f77, 0x2826843e3a9f57a6b83d8443d990c744613df7fc8a891a9f52516f140cfe1188);
        if (index == 16) return G1Point(0x2f4615fe2efc2fbbe7d6242254756dd316bce2e203212e0749eedcd9a97b5ab8, 0x2ab7873e86e3697412b15bf142b72d6e74ade86cac92da79042d8cc83b728906);
        revert Errors.InvalidProof();
    }
}
