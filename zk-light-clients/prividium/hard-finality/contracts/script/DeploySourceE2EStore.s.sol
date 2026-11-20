// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {LocalE2EStore} from "./LocalE2EStore.sol";

contract DeploySourceE2EStore is Script {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        LocalE2EStore store = new LocalE2EStore();
        vm.stopBroadcast();
        console2.log("LocalE2EStore", address(store));
    }
}
