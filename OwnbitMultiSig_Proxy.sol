pragma solidity >=0.8.0 <0.9.0;

// Proxy Contract
contract OwnbitMultiSigProxy {
    //address public constant implementation = 0x95Ca2f7959f8848795dFB0868C1b0c59Dd4E9330; //ETH v6
    //address public constant implementation = 0x89e816865646d5a88a8F38518a3964a6C31ae5F4; //ETH v8

    //address public constant implementation = 0x9EEC8fEB5FA0AC2040c8D924ec97E363B199bf13; //BSC v6
    //address public constant implementation = 0x6E3F24A9037005e1F07E2a6CD0634f54Eb23783e; //BSC v8

    //address public constant implementation = 0x32A0eb7e2Aa3077BB128ccb97c9a8d8465e08380; //BASE v6
    //address public constant implementation = 0x618Fc2D736Da1B9240a5cB539d9B5EA2D27Adb32; //BASE v8

    //address public constant implementation = 0xDA627E231aC2F74ad120D3D55d5699bF95583825; //POLYGON v6
    //address public constant implementation = 0x0ed8D552968319f1038C4baA827DEF45c2e0817e; //POLYGON v8

    address public constant implementation = 0xDC6F2BED9E5dE58a511DB4EAa11b10F075e8394C; //ARB v6
    //address public constant implementation = 0x88d9Ad7f36077e2096Ab48547a65a10fAFC2ADBC; //ARB v8
    

    constructor(address[] memory _owners, uint _required) {
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

