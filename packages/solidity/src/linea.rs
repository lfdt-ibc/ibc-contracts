// SPDX-License-Identifier: Apache-2.0

pub mod linea_light_client {
    #[cfg(feature = "rpc")]
    alloy_sol_types::sol!(
        #[sol(rpc)]
        #[allow(clippy::nursery, clippy::too_many_arguments)]
        LineaLightClient,
        "../../ibc-solidity/abi/bytecode/LineaLightClient.json"
    );

    #[cfg(not(feature = "rpc"))]
    alloy_sol_types::sol!(
        LineaLightClient,
        "../../ibc-solidity/abi/LineaLightClient.json"
    );
}
