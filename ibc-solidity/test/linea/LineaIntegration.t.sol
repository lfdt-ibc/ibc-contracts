// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

// solhint-disable no-empty-blocks

import { Integration2Suite } from "../solidity-ibc/integration/suites/Integration2Suite.sol";
import { Integration3Suite } from "../solidity-ibc/integration/suites/Integration3Suite.sol";
import { IFTIntegrationSuite } from "../solidity-ibc/integration/suites/IFTIntegrationSuite.sol";
import { WithMaruSim } from "./utils/MaruSimDriver.sol";
import { WithFreshChains } from "../solidity-ibc/integration/drivers/LightClientDriverTest.sol";

// The integration suites on Linea light clients tracking single-validator Maru sim chains. Every relayed packet is
// proven with account and storage proofs against a sealed beacon block, so fuzz runs are capped to keep the suites
// fast.

/// forge-config: default.fuzz.runs = 256
contract Integration2LineaTest is Integration2Suite, WithMaruSim, WithFreshChains { }

/// forge-config: default.fuzz.runs = 256
contract Integration3LineaTest is Integration3Suite, WithMaruSim, WithFreshChains { }

/// forge-config: default.fuzz.runs = 256
contract IFTIntegrationLineaTest is IFTIntegrationSuite, WithMaruSim, WithFreshChains { }
