// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity 0.8.24;

import "./Helper.sol";
import "./ReentrancyGuard.sol";
import "./HeapLibrary.sol";
// import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

address constant addressForBurning = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

address constant P256_VERIFY_ADDRESS = address(0x100);
address constant CODE_ORACLE_ADDR = 0x0000000000000000000000000000000000008012;
address constant EC_ADD_ADDR = 0x0000000000000000000000000000000000000006;
address constant EC_MUL_ADDR = 0x0000000000000000000000000000000000000007;


/// @author Matter Labs
contract Main is ReentrancyGuard {
    event ContractCreated(address indexed contractAddress, address indexed creatorAddress);

    event ERC20Deployed(address indexed tokenAddress, string name, string symbol, uint8 decimals, uint256 indexed id);

    event HeapUpdated(bytes indexed data, uint256);

    struct EcrecoverSignatureTestData {
        bytes32 hash;
        bytes signature;
        address addr;
    }

    using HeapLibrary for HeapLibrary.Heap;

    // This is just a storage value with slot key `0`. It is used by the tests for transient storage. 
    uint256 internal storageValueKey0;

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


        // Test a couple of secp256Verify calls.
        secp256VerifyTest();


        // Test transient storage.
        testTransientStore();

        // Test code oracle
        testCodeOracle();

        // Test code oracle reusing bytecode from code decommitment
        testCodeOracleResuingBytecode();

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

        EcrecoverSignatureTestData memory data1 = EcrecoverSignatureTestData({
            addr: 0x7f8b3B04BF34618f4a1723FBa96B5Db211279a2B,
            hash: 0x14431339128bd25f2c7f93baa611e367472048757f4ad67f6d71a5ca0da550f5,
            signature: hex"51e4dbbbcebade695a3f0fdf10beb8b5f83fda161e1a3105a14c41168bf3dce046eabf35680328e26ef4579caf8aeb2cf9ece05dbf67a4f3d1f28c7b1d0e35461C"
        });

        EcrecoverSignatureTestData memory data2 = EcrecoverSignatureTestData({
            addr: 0x0865a77D4d68c7e3cdD219D431CfeE9271905074,
            hash: 0xe0682fd4a26032afff3b18053a0c33d2a6c465c0e19cb1e4c10eb0a949f2827c,
            signature: hex"c46cdc50a66f4d07c6e9a127a7277e882fb21bcfb5b068f2b58c7f7283993b790bdb5f0ac79d1a7efdc255f399a045038c1b433e9d06c1b1abd58a5fcaab33f11C"
        });
        
        _ecrecoverOneTest(data1);
        _ecrecoverOneTest(data2);

        // ecrecover with msg.hash == 0

        EcrecoverSignatureTestData memory data3 = EcrecoverSignatureTestData({
            addr: 0x9E1599e110cEEF4F15e8Ee706AD9Cd4a5b8eC6ED,
            hash: 0x0,
            signature: hex"9b37e91445e92b1423354825aa33d841d83cacfdd895d316ae88dabc317369962e385d648e3be194d45fbb1f7229ef10c5b7ee1c7c30145aa4ddf9380eab5a031C"
        });

        _ecrecoverOneTest(data3);

        // failed to recover address (address == 0)

        EcrecoverSignatureTestData memory data4 = EcrecoverSignatureTestData({
            addr: address(0),
            hash: 0xdd69e9950f52dddcbc6751fdbb6949787cc1b84ac4020ab0617ec8ad950e554a,
            signature: hex"b00986d8bb52ee7acb06cabfa6c2c099d8904c7c8d56707a267ddbafd7aed0704068f5b5e6c4b442e83fcb7b6290520ebb5e077cd10d3bd86cf431ca4b6401621b"
        });

        _ecrecoverOneTest(data4);


        // Should recover correctly malleable signatures

        EcrecoverSignatureTestData memory data5 = EcrecoverSignatureTestData({
            addr: address(0x7cad5049A2bcA031c6E4558c9029e3663Adc948E),
            hash: bytes32(uint256(100477317730243874162981143148734960184526648924501832359736878627087072867386)),
            signature: hex"aceaa17ffb7bfafe15e2c026801400564854c9839a1665b65f18b228dd55ebcdc5619cde9ca3df8b16a8b5731a6ab66e527ab0dc3caf319d46fd40f832fce34a1c"
        });

        _ecrecoverOneTest(data5);
    }

    function secp256VerifyTest() public view {
        bytes32 GROUP_SIZE = bytes32(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551);
        uint256 P256_GROUP_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

        bytes32 correctHash = 0xf6eebeabe0878b4ee116ec0ebdf389b56447e991c0573bf27634fd372f98a3c4;
        bytes32 correctX = 0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83;
        bytes32 correctY = 0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9;
        bytes32 correctR = 0x7086a4f1ad84caa4b058746fcb521cb5618158d1cf9c4c5b79c6e60b61da409a;
        bytes32 correctS = 0xd2a2e4606a2fa5639c7f97e86d218c88525ba4e3114ba2ce87b0d3507514c265;

        bytes32[] memory input = new bytes32[](5);
        input[0] = correctHash;
        input[1] = correctR;
        input[2] = correctS;
        input[3] = correctX;
        input[4] = correctY;

        _secp256VerifyTest(input, true);

        // Testing providing 0 values
        for(uint256 i = 0; i < 5; i++) {
            bytes32 prev = input[i];
            input[i] = 0;
            _secp256VerifyTest(input, false);
            input[i] = prev;
        }

        // Testing large r/s
        for(uint256 i = 1; i <= 2; i++) {
            bytes32 prev = input[i];
            input[i] = GROUP_SIZE;
            _secp256VerifyTest(input, false);
            input[i] = prev;
        }

        // Testing incorrect x/y (i.e. not a valid point on the curve)
        for(uint256 i = 3; i <= 4; i++) {
            bytes32 prev = input[i];
            input[i] = bytes32(uint256(0x01));
            _secp256VerifyTest(input, false);
            input[i] = prev;
        }

        // Check malleability
        input[2] = bytes32(P256_GROUP_ORDER - uint256(correctS));

        _secp256VerifyTest(input, true);
    }

    function _ecrecoverOneTest(EcrecoverSignatureTestData memory _data) internal pure {
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

    function _secp256VerifyTest(bytes32[] memory _input, bool _expectedSuccess) internal view {
        bytes memory data = abi.encodePacked(_input);

        (bool success, bytes memory _result) = P256_VERIFY_ADDRESS.staticcall(data);

        // The call itself must be always succesful, the difference is only in whether
        // the `_result` is empty or not
        require(success, "P256 Verify has failed");

        if (_expectedSuccess) {
            bool internalSuccess = abi.decode(_result, (bool));
            require(internalSuccess, "P256 Verify should have succeeded, but failed");
        } else {
            require(_result.length == 0, "P256 Verify should have failed, but succeeded");               
        }
    }

    // This test aims to check that the tstore/sstore are writing into separate spaces.
    function testTrasientAndNonTransientStore() external {
        storageValueKey0 = 100;

        uint256 x;

        uint256 storedVal;
        uint256 tStoredVal;
        assembly {
            tstore(0, 1)

            storedVal := sload(0)
            tStoredVal := tload(0)
        }

        require(storedVal == 100, "Stored value should be 100");
        require(tStoredVal == 1, "Transient stored value should be 1");
    }


    uint256 constant TSTORE_TEST_KEY = 0xff;

    // We have to use the `shouldRevert` variable since otherwise the function will be optimized
    // to never do the write in the first place
    function tStoreAndRevert(uint256 value, bool shouldRevert) external {
        uint256 key = TSTORE_TEST_KEY;
        assembly {
            tstore(key, value)
        }

        if(shouldRevert) {
            revert("This method always reverts");
        }
    }

    // We have to use a variable since otherwise the function will be optimized
    // to never do the write in the first place
    function assertTValue(uint256 expectedValue) external {
        uint256 key = TSTORE_TEST_KEY;
        uint256 realValue;
        assembly {
            realValue := tload(key)
        }

        require(realValue == expectedValue, "The value in transient storage is not what was expected");
    }

    function testTstoreRollback() external {
        // Firstly, write the 1000 to the transient storage
        this.tStoreAndRevert(1000, false);

        // Now call and ignore the error
        (bool success, ) = (address(this)).call(abi.encodeWithSignature("tStoreAndRevert(uint256,bool)", uint256(500), true));
        require(!success, "The call should have failed");
        
        this.assertTValue(1000);
    }

    function testTransientStore() public {
        this.testTrasientAndNonTransientStore();
        this.testTstoreRollback();
    }

    function queryCodeOracle(bytes32 _versionedHash) internal returns (uint256 gasUsed) {
        uint256 gasBefore = gasleft();

        // Call the code oracle
        (bool success, bytes memory returnedBytecode) = CODE_ORACLE_ADDR.staticcall(abi.encodePacked(_versionedHash));

        gasUsed = gasBefore - gasleft();

        // Check the result
        require(success, "CodeOracle call failed");
    
        require(Helper.hashL2Bytecode(returnedBytecode) == _versionedHash, "Returned bytecode does not match the expected hash");
    }

    function queryCodeOracleNoCopy(bytes32 _versionedHash) internal returns (uint256 gasUsed) {
        bytes memory callData = abi.encodePacked(_versionedHash);
        uint256 gasBefore = gasleft();

        // Call the code oracle
        bool success;
        assembly {
            success := staticcall(
                gas(), // gas
                CODE_ORACLE_ADDR, // destination
                add(callData, 0x20), // input
                mload(callData), // input size
                0, // output
                0 // output size
            )
        }

        gasUsed = gasBefore - gasleft();

        // Check the result
        require(success, "CodeOracle call failed");    
    }

    function testCodeOracle() public {
        // We assume that no other test before this one will access `EC_ADD_ADDR` & so it was not decommitted
        // before.
        bytes32 bytecodeHash = Helper.getRawCodeHash(EC_ADD_ADDR);

        // Step 0: we call the code oracle with zero hash. It will fail, but the purpose 
        // of it is to decommit the CodeOracle contract itself, to ensure that the test results wont be affected by it.
        CODE_ORACLE_ADDR.staticcall(abi.encodePacked(bytes32(0)));
      
        uint256 gasUsed1 = queryCodeOracle(bytecodeHash);
        uint256 gasUsed2 = queryCodeOracle(bytecodeHash);
        uint256 gasUsed3 = queryCodeOracle(bytecodeHash);

        require(gasUsed1 > gasUsed2, "Decommitment cost wasnt amortized");
        require(gasUsed2 == gasUsed3, "Decommitment cost wasnt equal between two calls");
    }

    // Here we test that the code oracle will work fine with reusing an already decommitted bytecode
    function testCodeOracleResuingBytecode() public {
        // This is just a dummy call, it should fail, but it also should require us to decommit EC_MUL
        // precompile's bytecode.
        EC_MUL_ADDR.staticcall{gas: 1000}(""); 

        bytes32 bytecodeHash = Helper.getRawCodeHash(EC_MUL_ADDR);

        // Step 0: we call the code oracle with zero hash. It will fail, but the purpose 
        uint256 gasUsed1 = queryCodeOracleNoCopy(bytecodeHash);
        uint256 gasUsed2 = queryCodeOracleNoCopy(bytecodeHash);

        // The contract has already been decommitted before, so the costs should be same.
        require(gasUsed1 == gasUsed2, "Decommitment cost wasnt amortized");
    }
}
