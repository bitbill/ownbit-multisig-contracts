pragma solidity >=0.8.0 <0.9.0;

// Proxy Contract
contract OwnbitMultiSigProxy {
    address public constant implementation = 0x8ff6eBD112577E471530D175Ce151F1DcBDC4B8a; //ETH,BSC,BASE,ARB v10
    //address public constant implementation = 0xAd63df1c78AaddC3Ee033308671Ed59ee19E20a8; //ETH,BSC,BASE,ARB v11

    constructor(address[] memory _owners, uint _required) {
        require(implementation.code.length > 0, "Implementation has no code");
        bytes memory initData = abi.encodeWithSignature("initialize(address[],uint256)", _owners, _required);
        (bool success, ) = implementation.delegatecall(initData);
        require(success, "Initialization failed");
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
}

