// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.8.0;

interface IL1Messanger {
    function sendToL1(bytes memory _message) external returns (bytes32);
}

interface IAccountCodeStorage {
    function getRawCodeHash(address _address) external view returns (bytes32 codeHash);
}

uint160 constant SYSTEM_CONTRACTS_OFFSET = 0x8000; // 2^15
IL1Messanger constant L1_MESSANGER = IL1Messanger(address(SYSTEM_CONTRACTS_OFFSET + 0x08));
IAccountCodeStorage constant ACCOUNT_CODE_STORAGE = IAccountCodeStorage(address(SYSTEM_CONTRACTS_OFFSET + 0x02));
address constant CODE_ADDRESS_CALL_ADDRESS = address((1 << 16) - 2);

library Helper {
    function sendMessageToL1(bytes memory _message) internal returns (bytes32) {
        return L1_MESSANGER.sendToL1(_message);
    }

    function getCodeAddress() internal view returns (address addr) {
        address callAddr = CODE_ADDRESS_CALL_ADDRESS;
        assembly {
            addr := staticcall(0, callAddr, 0, 0xFFFF, 0, 0)
        }
    }

    function hashL2Bytecode(bytes memory _bytecode) internal pure returns (bytes32 hashedBytecode) {
        // Note that the length of the bytecode must be provided in 32-byte words.
        require(_bytecode.length % 32 == 0, "pq");

        uint256 bytecodeLenInWords = _bytecode.length / 32;
        require(bytecodeLenInWords < 2 ** 16, "pp"); // bytecode length must be less than 2^16 words
        require(bytecodeLenInWords % 2 == 1, "ps"); // bytecode length in words must be odd
        hashedBytecode = sha256(_bytecode) & 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        // Setting the version of the hash
        hashedBytecode = (hashedBytecode | bytes32(uint256(1 << 248)));
        // Setting the length
        hashedBytecode = hashedBytecode | bytes32(bytecodeLenInWords << 224);
    }

    function getRawCodeHash(address _addr) internal view returns (bytes32) {
        return ACCOUNT_CODE_STORAGE.getRawCodeHash(_addr);
    }
}
