// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// Proxy Contract
contract OwnbitMultiSigProxy {
    address public constant implementation = 0xC013dA3eca3E73Cf4aEA2DC3a9EcaE78f151DFb1; // ETH v20
    // address public constant implementation = 0xB4aB532C4fbeDfFbC2dA258ee2447F4e08536697; // BSC v20
    // address public constant implementation = 0x24f89A7237ac1D48799A8bCA8Bde284728Cf5fd4; // BASE v20
    // address public constant implementation = 0x5129c56D7737BD441b48De2447a705893f1B9F36; // POLYGON v20
    // address public constant implementation = 0x89e816865646d5a88a8F38518a3964a6C31ae5F4; // ARB v20

    /// @param _owners          initial owners (admins)
    /// @param _signers         initial signers (for spending)
    /// @param _weights         weights for signers, aligned with _signers
    /// @param _ownerRequired   owner approvals required for config changes
    /// @param _signRequired    weighted threshold required for spending
    constructor(
        address[] memory _owners,
        address[] memory _signers,
        uint256[] memory _weights,
        uint256 _ownerRequired,
        uint256 _signRequired
    ) {
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address[],address[],uint256[],uint256,uint256)",
            _owners,
            _signers,
            _weights,
            _ownerRequired,
            _signRequired
        );

        (bool success, bytes memory returndata) = implementation.delegatecall(initData);
        require(success, _getRevertMsg(returndata));
    }

    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // bubble up revert reason from implementation initialize (optional helper)
    function _getRevertMsg(bytes memory _returnData) private pure returns (string memory) {
        if (_returnData.length < 68) return "Initialization failed";
        assembly {
            _returnData := add(_returnData, 0x04)
        }
        return abi.decode(_returnData, (string));
    }
}
