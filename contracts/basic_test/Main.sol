// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.8.0;

import "./Helper.sol";
import "./ReentrancyGuard.sol";
import "./HeapLibrary.sol";
// import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

address constant addressForBurning = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

/// @author Matter Labs
contract Main is ReentrancyGuard {
    event ContractCreated(address indexed contractAddress, address indexed creatorAddress);

    event ERC20Deployed(address indexed tokenAddress, string name, string symbol, uint8 decimals, uint256 indexed id);

    event HeapUpdated(bytes indexed data, uint256);

    struct SignatureTestData {
        bytes32 hash;
        bytes signature;
        address addr;
    }

    using HeapLibrary for HeapLibrary.Heap;

    address public creator;
    uint256 public id;
    bytes4 public lastCalledFunction;
    uint256 public lastTimestamp;
    address public lastTxOrigin;
    uint256 public lastPulledBlockNumber;
    uint256 public savedChainId;
    uint256 public savedGasPrice;
    uint256 public savedBlockGasLimit;
    address public savedCoinbase;
    uint256 public savedDifficulty; 
    uint256 public lastPulledMsgValue;
    HeapLibrary.Heap heap;

    constructor() {
        require(address(this).code.length == 0);
        require(address(this).codehash == keccak256(""));

        (bool success, bytes memory data) = address(this).call(abi.encodeCall(Main.getter, ()));
        require(success);
        require(data.length == 0);
    }

    receive() external payable nonReentrant {
        address codeAddress = Helper.getCodeAddress();
        require(codeAddress == address(this), "in delegate call");

        // Make common checks before processing the function
        commonChecks();

        // Test storage read/write, and hashes
        heapTest();

        // Test keccak works along buffer bounds
        keccakBoundsTest();

        uint256 heapSizeBefore = heap.getSize();
        require(heapSizeBefore != 0, "Heap should not be empty");

        // Test of rollback storage
        try this.failedHeapTest() {
            revert("heap test should failed");
        } catch {
            require(heap.getSize() == heapSizeBefore, "Heap should not be modified");
        }

        // Test of rollback L1 messaging
        try this.failedSendingL1Messages() {
            revert("sending l1 messages test should failed");
        } catch {

        }

        // Test a couple of ecrecover calls.
        ecrecoverTest();

        (bool s, ) = addressForBurning.call{value: msg.value}("");
        require(s, "failed transfer call");
    }

    function commonChecks() public payable {
        // require(tx.origin == msg.sender);
        require(msg.data.length == 0);
        

        if (block.number > 0) {
            blockhash(block.number - 1);
            blockhash(block.number + 1000);
        }

        savedDifficulty = block.difficulty;
        savedCoinbase = block.coinbase;
        savedBlockGasLimit = block.gaslimit;
        savedGasPrice = tx.gasprice;
        savedChainId = block.chainid;
        lastTimestamp = block.timestamp;
        lastTxOrigin = tx.origin;
        lastCalledFunction = msg.sig;
        lastPulledBlockNumber = block.number;
        lastPulledMsgValue = msg.value;
    }

    function heapTest() public {
        uint256 gasLeftBefore = gasleft();

        bytes memory data = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard...";
        for(uint256 i=0;i<4; i++) {
            bytes32 weirdHash = keccak256(data) ^ sha256(data);
            data = bytes.concat(data, weirdHash);
            heap.push(uint256(weirdHash));
            
            Helper.sendMessageToL1(data);
        }

        heap.pop();

        uint256 gasLeftAfter = gasleft();

        require(gasLeftAfter < gasLeftBefore, "Some error message");

        emit HeapUpdated(data, gasLeftBefore - gasLeftAfter);
    }

    function keccakBoundsTest() public {
        // 135 chars
        bytes memory preLimitData = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // 136 chars
        bytes memory limitData = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // 137 chars
        bytes memory overLimitData = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        keccak256(preLimitData);
        keccak256(limitData);
        keccak256(overLimitData);
    }

    function getter() external pure returns(bytes4) {
        return this.getter.selector;
    }

    // Should fails
    function failedHeapTest() external {
        while(true) {
            heap.pop();
        }
    }

    // Should fails
    function failedSendingL1Messages() external {
        bytes32 weirdHash1 = keccak256("Test message 1");
        bytes32 weirdHash2 = weirdHash1 ^ sha256("Test message 2");
        
        bytes memory data = bytes.concat(weirdHash1, weirdHash2);

        Helper.sendMessageToL1(data);

        revert();
    }

    function ecrecoverTest() public pure {
        // success recovering address

        SignatureTestData memory data1 = SignatureTestData({
            addr: 0x7f8b3B04BF34618f4a1723FBa96B5Db211279a2B,
            hash: 0x14431339128bd25f2c7f93baa611e367472048757f4ad67f6d71a5ca0da550f5,
            signature: hex"51e4dbbbcebade695a3f0fdf10beb8b5f83fda161e1a3105a14c41168bf3dce046eabf35680328e26ef4579caf8aeb2cf9ece05dbf67a4f3d1f28c7b1d0e35461C"
        });

        SignatureTestData memory data2 = SignatureTestData({
            addr: 0x0865a77D4d68c7e3cdD219D431CfeE9271905074,
            hash: 0xe0682fd4a26032afff3b18053a0c33d2a6c465c0e19cb1e4c10eb0a949f2827c,
            signature: hex"c46cdc50a66f4d07c6e9a127a7277e882fb21bcfb5b068f2b58c7f7283993b790bdb5f0ac79d1a7efdc255f399a045038c1b433e9d06c1b1abd58a5fcaab33f11C"
        });
        
        _ecrecoverOneTest(data1);
        _ecrecoverOneTest(data2);

        // ecrecover with msg.hash == 0

        SignatureTestData memory data3 = SignatureTestData({
            addr: 0x9E1599e110cEEF4F15e8Ee706AD9Cd4a5b8eC6ED,
            hash: 0x0,
            signature: hex"9b37e91445e92b1423354825aa33d841d83cacfdd895d316ae88dabc317369962e385d648e3be194d45fbb1f7229ef10c5b7ee1c7c30145aa4ddf9380eab5a031C"
        });

        _ecrecoverOneTest(data3);

        // failed to recover address (address == 0)

        SignatureTestData memory data4 = SignatureTestData({
            addr: address(0),
            hash: 0xdd69e9950f52dddcbc6751fdbb6949787cc1b84ac4020ab0617ec8ad950e554a,
            signature: hex"b00986d8bb52ee7acb06cabfa6c2c099d8904c7c8d56707a267ddbafd7aed0704068f5b5e6c4b442e83fcb7b6290520ebb5e077cd10d3bd86cf431ca4b6401621b"
        });

        _ecrecoverOneTest(data4);
    }

    function _ecrecoverOneTest(SignatureTestData memory _data) internal pure {
        bytes memory signature = _data.signature;
		require(signature.length == 65);
		uint8 v;
		bytes32 r;
		bytes32 s;

		assembly {
			r := mload(add(signature, 0x20))
			s := mload(add(signature, 0x40))
			v := and(mload(add(signature, 0x41)), 0xff)
		}
		require(v == 27 || v == 28);

		require(_data.addr == ecrecover(_data.hash, v, r, s));
	}
}
