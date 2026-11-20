// SPDX-License-Identifier: MIT
pragma solidity >=0.8.24 <0.9.0;

/// @notice Exact interface shape from sp1-contracts v6.1.1, commit
/// d3629729c3216eb51bd4859d027a8eb729399fa4.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
