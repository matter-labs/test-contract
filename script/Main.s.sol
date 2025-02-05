// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Main} from "../contracts/basic_test/Main.sol";

contract CounterScript is Script {
    Main public mainContract;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        mainContract = new Main();
        uint256 amountToSend = 1 ether;
        console.log(gasleft());
        address(mainContract).call{value: amountToSend, gas: 800_000_000}("");

        vm.stopBroadcast();
    }
}
