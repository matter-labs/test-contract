// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity 0.8.24;

import "./Helper.sol";
import "./ReentrancyGuard.sol";
import "./HeapLibrary.sol";
// import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

address constant addressForBurning = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

address constant P256_VERIFY_ADDRESS = address(0x100);
address constant CODE_ORACLE_ADDR = 0x0000000000000000000000000000000000008012;
address constant MODEXP_ADDR = 0x0000000000000000000000000000000000000005;
address constant EC_ADD_ADDR = 0x0000000000000000000000000000000000000006;
address constant EC_MUL_ADDR = 0x0000000000000000000000000000000000000007;
address constant EC_PAIRING_ADDR = 0x0000000000000000000000000000000000000008;


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

    // Here we set base, exp and mod to 32 bytes, 
    // since we support only up to 32 bytes for them in circuits.
    struct ModexpTestCase {
        bytes32 base;       
        bytes32 exp;    
        bytes32 mod;
        bytes32 expect;       // Expected result (base ^ exp) % mod 
        bool expectedSuccess; // Whether the test case should succeed
    }
    
    struct ECAddTestCase {
        bytes32[2] p1;        // Point 1 (x, y)
        bytes32[2] p2;        // Point 2 (x, y)
        bytes32[2] expect;    // Expected result (x, y)
        bool expectedSuccess; // Whether the test case should succeed
    }

    struct ECMulTestCase {
        bytes32[2] p;         // Point (x, y)
        bytes32 s;            // Scalar
        bytes32[2] expect;    // Expected result (x, y)
        bool expectedSuccess; // Whether the test case should succeed
    }

    struct ECPairingTestCase {
        bytes32[2][] p1;      // G1 points (x, y)
        bytes32[4][] p2;      // G2 points (x, y) - twisted
        bool expect;          // Expected result
        bool expectedSuccess; // Whether the test case should succeed
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

        modexpTests();
        ecAddTests();
        ecMulTests();
        ecPairingTests();

        // Test transient storage.
        testTransientStore();

        // Test code oracle
        testCodeOracle();

        // Test code oracle reusing bytecode from code decommitment
        testCodeOracleReusingBytecode();

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

    function modexpTests() public view {
        ModexpTestCase [] memory testCases = new ModexpTestCase[](1);

        // Test case 1: Valid input points and expected result
        testCases[0] = ModexpTestCase({
            base: bytes32(0x8f3b7d5c187f8abbe0581dab5a37644febd35ea6d4fe3213288f9d63ab82a6b1),
            exp: bytes32(0xafa9888e351dfdefd862945b0da33c9ea1de907ae830292438df1fa184447777), 
            mod: bytes32(0xc7e38934b1501e64e5c0bd0ab35b3354520b6e88b81a1f063c37007c65b7efd5),
            expect: bytes32(0x45682b037d21d235bd0ed6103ce2674e5c8e983a88bfd09c847a6324e77c1ad6),
            expectedSuccess: true
        });

        for (uint256 i = 0; i < testCases.length; i++) {
            _runModexpTestCase(testCases[i]);
        }
    }

    function ecAddTests() public view {
        ECAddTestCase[] memory testCases = new ECAddTestCase[](1);

        // Test case 1: Valid input points and expected result
        testCases[0] = ECAddTestCase({
            p1: [
                bytes32(0x099C07C9DD1107B9C9B0836DA7ECFB7202D10BEA1B8D1E88BC51CA476F23D91D), // x1
                bytes32(0x28351E12F9219537FC8D6CAC7C6444BD7980390D0D3E203FE0D8C1B0D8119950)  // y1
            ],
            p2: [
                bytes32(0x21E177A985C3DB8EF1D670629972C007AE90C78FB16E3011DE1D08F5A44CB655), // x2
                bytes32(0x0BD68A7CAA07F6ADBECBF06FB1F09D32B7BED1369A2A58058D1521BEBD8272AC)  // y2
            ],
            expect: [
                bytes32(0x25BEBA7AB903D641D77E5801CA4D69A7A581359959C5D2621301DDDAFB145044), // result_x
                bytes32(0x19EE7A5CE8338BBCF4F74C3D3EC79D3635E837CB723EE6A0FA99269E3C6D7E23)  // result_y
            ],
            expectedSuccess: true
        });

        for (uint256 i = 0; i < testCases.length; i++) {
            _runEcAddTestCase(testCases[i]);
        }
    }

    function ecMulTests() public view {
        ECMulTestCase[] memory testCases = new ECMulTestCase[](1);

        // Test case 1: Valid input points and expected result
        testCases[0] = ECMulTestCase({
            p: [
                bytes32(0x1F2A9FD8AB833C4F85ED209B187229ED51C510329CDA700BD1BB6E3483290C4C), // x
                bytes32(0x0F518AE296ED6CF2C9E1449B4AEC256054C8AF11FD339E89377E4037575A156E)  // y
            ],
            s: bytes32(0x1E2DAB676985FDC3E228CFBCE8AB56BC92F95D354644FAAA56DFC895661AFCAE), // scalar
            expect: [
                bytes32(0x18FB38035EF9A864E189211019D1319170D90F16DA429D564EF71B1F72A45033), // result_x
                bytes32(0x29A541100C87B605110364DB832E9929693132F6E65B9FE1C72EC05075A89D35)  // result_y
            ],
            expectedSuccess: true
        });

        for (uint256 i = 0; i < testCases.length; i++) {
            _runEcMulTestCase(testCases[i]);
        }
    }

    function ecPairingTests() public view {
        ECPairingTestCase[] memory testCases = new ECPairingTestCase[](1);

        // Test case 1: Valid input points and expected result
        testCases[0] = ECPairingTestCase({
            p1: new bytes32[2][](2) , // G1 points (two pairs of x and y)
            p2: new bytes32[4][](2) , // G2 points (two sets of four twisted coords)
            expect: true,            // Expected result from test case
            expectedSuccess: true    // Whether the call should succeed
        });

        // Fill in the p1 G1 points (x, y)
        testCases[0].p1[0] = [
            bytes32(0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da),
            bytes32(0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6)
        ];

        testCases[0].p1[1] = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000001),
            bytes32(0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45)
        ];

        // Fill in the p2 G2 points (twisted coordinates)
        testCases[0].p2[0] = [
            bytes32(0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc),
            bytes32(0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9),
            bytes32(0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90),
            bytes32(0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e)
        ];

        testCases[0].p2[1] = [
            bytes32(0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4),
            bytes32(0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7),
            bytes32(0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2),
            bytes32(0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc)
        ];

        for (uint256 i = 0; i < testCases.length; i++) {
            _runEcPairingTestCase(testCases[i]);
        }
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

    function _runModexpTestCase(ModexpTestCase memory testCase) internal view {
        bytes32 length = bytes32(uint256(0x20));

        bytes memory input = abi.encodePacked(
            length, length, length, 
            testCase.base, testCase.exp, testCase.mod
        );

        (bool success, bytes memory result) = MODEXP_ADDR.staticcall(input);
        
        require(success == testCase.expectedSuccess, "MODEXP precompile call success status mismatch");

        if (success) {
            bytes32 actual = abi.decode(result, (bytes32));
            require(actual == testCase.expect, "MODEXP result mismatch");
        }
    }

    function _runEcAddTestCase(ECAddTestCase memory testCase) internal view {
        bytes memory input = abi.encodePacked(testCase.p1[0], testCase.p1[1], testCase.p2[0], testCase.p2[1]);

        (bool success, bytes memory result) = EC_ADD_ADDR.staticcall(input);
        
        require(success == testCase.expectedSuccess, "ECADD precompile call success status mismatch");

        if (success) {
            (bytes32 actualX, bytes32 actualY) = abi.decode(result, (bytes32, bytes32));
            require(actualX == testCase.expect[0] && actualY == testCase.expect[1], "ECADD result mismatch");
        }
    }

    function _runEcMulTestCase(ECMulTestCase memory testCase) internal view {
        bytes memory input = abi.encodePacked(testCase.p[0], testCase.p[1], testCase.s);

        (bool success, bytes memory result) = EC_MUL_ADDR.staticcall(input);
        
        require(success == testCase.expectedSuccess, "ECMUL precompile call success status mismatch");

        if (success) {
            (bytes32 actualX, bytes32 actualY) = abi.decode(result, (bytes32, bytes32));
            require(actualX == testCase.expect[0] && actualY == testCase.expect[1], "ECMUL result mismatch");
        }
    }

    function _runEcPairingTestCase(ECPairingTestCase memory testCase) internal view {
        bytes memory input;
        require(testCase.p1.length == testCase.p2.length, "G1 and G2 amounts must match");

        for (uint256 i = 0; i < testCase.p1.length; i++) {
            input = abi.encodePacked(input, 
                testCase.p1[i][0], testCase.p1[i][1],
                testCase.p2[i][0], testCase.p2[i][1], testCase.p2[i][2], testCase.p2[i][3]
            );
        }

        (bool success, bytes memory result) = EC_PAIRING_ADDR.staticcall(input);
        
        require(success == testCase.expectedSuccess, "ECPAIRING precompile call success status mismatch");

        if (success) {
            bool actual = abi.decode(result, (bool));
            require(actual == testCase.expect, "ECPAIRING result mismatch");
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
    function testCodeOracleReusingBytecode() public {
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
