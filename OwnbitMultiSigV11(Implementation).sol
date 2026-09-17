pragma solidity >=0.8.0 <0.9.0;

// This is the ETH/ERC20/NFT multisig contract for Ownbit.
//
// For 2-of-3 multisig, to authorize a spend, two signtures must be provided by 2 of the 3 owners.
// To generate the message to be signed, provide the destination address and
// spend amount (in wei) to the generateMessageToSign method.
// The signatures must be provided as the (v, r, s) hex-encoded coordinates.
// The S coordinate must be 0x00 or 0x01 corresponding to 0x1b and 0x1c, respectively.
//
// WARNING: The generated message is only valid until the next spend is executed.
//          after that, a new message will need to be calculated.
//
//
// Accident Protection MultiSig, rules:
//
// Participants must keep themselves active by submitting transactions. 
// Not submitting any transaction within 416 days will be treated as wallet lost (i.e. accident happened), 
// other participants can still spend the assets as along as: valid signing count >= Min(mininual required count, active owners).
//
// INFO: This contract is ERC20/ERC721/ERC1155 compatible.
// This contract can both receive ETH, ERC20 and NFT (ERC721/ERC1155) tokens.
// Last update time: 2026-09-07 (SpendFailed event on inner-call failure).
// Previous:         2026-09-06 (WalletConnect / ERC-1271 extension; CHAINID constant replaced by block.chainid).
// Single source for every EVM chain.
// copyright@ownbit.io

// Proxy Storage Contract
contract ProxyStorage {
    mapping(address => uint256) public ownerActiveTimeMap;  //uint256 is the active timestamp(in secs) of this owner
    address[] public owners;         //owners
    uint public required;              // Number of required signatures
    uint public spendNonce;                 // Replay protection counter
}

contract OwnbitMultiSigImplementation is ProxyStorage {
    
  uint constant public MAX_OWNER_COUNT = 9;
  uint constant public MAX_INACTIVE_TIME = 416 days; 

  // An event sent when funds are received.
  event Funded(address from, uint value);
  
  // An event sent when an spendAny is executed.
  event Spent(address to, uint value);

  // An event sent when signatures were valid (nonce advanced) but the inner call failed.
  event SpendFailed(address to, uint value, bytes reason);

  modifier validRequirement(uint ownerCount, uint _required) {
    require (ownerCount <= MAX_OWNER_COUNT
            && _required <= ownerCount
            && _required >= 1);
    _;
  }

  //called by proxy
  function initialize(address[] memory _owners, uint _required) public validRequirement(_owners.length, _required) {
    require(owners.length == 0, "Already initialized");
    for (uint i = 0; i < _owners.length; i++) {
      //onwer should be distinct, and non-zero
      if (ownerActiveTimeMap[_owners[i]] > 0 || _owners[i] == address(0x0)) {
        revert();
      }
      ownerActiveTimeMap[_owners[i]] = block.timestamp;
      owners.push(_owners[i]);
    }
    required = _required;
  }

  receive() external payable {
    emit Funded(msg.sender, msg.value);
  }
  
  // @dev Returns list of owners.
  // @return List of owner addresses.
  function getOwners() public view returns (address[] memory) {
    return owners;
  }
    
  function getSpendNonce() public view returns (uint256) {
    return spendNonce;
  }
    
  function getRequired() public view returns (uint) {
    return required;
  }
  
  //return the active timestamp of this owner
  function getOwnerActiveTime(address addr) public view returns (uint256) {
    return ownerActiveTimeMap[addr];
  }

  // Generates the message to sign given the output destination address and amount.
  // includes this contract's address and a nonce for replay protection.
  // One option to independently verify: https://leventozturk.com/engineering/sha3/ and select keccak
  function generateMessageToSign(address destination, uint256 value, bytes memory data) private view returns (bytes32) {
    //the sequence must match generateMultiSigV3 in JS
    //CHANGED: CHAINID constant -> block.chainid (same position, same bytes on the chain it was deployed for).
    bytes32 message = keccak256(abi.encodePacked(address(this), destination, value, data, spendNonce, block.chainid));
    return message;
  }
  
  function _messageToRecover(address destination, uint256 value, bytes memory data) private view returns (bytes32) {
    bytes32 hashedUnsignedMessage = generateMessageToSign(destination, value, data);
    bytes memory prefix = "\x19Ethereum Signed Message:\n32";
    return keccak256(abi.encodePacked(prefix, hashedUnsignedMessage));
  }
  
  //destination can be a normal address or a contract address, such as ERC20 contract address.
  //value is the wei transferred to the destination.
  //data for transfer ether: 0x
  //data for transfer erc20 example: 0xa9059cbb000000000000000000000000ac6342a7efb995d63cc91db49f6023e95873d25000000000000000000000000000000000000000000000000000000000000003e8
  //data for transfer erc721 example: 0x42842e0e00000000000000000000000097b65ad59c8c96f2dd786751e6279a1a6d34a4810000000000000000000000006cb33e7179860d24635c66850f1f6a5d4f8eee6d0000000000000000000000000000000000000000000000000000000000042134
  //data can contain any data to be executed. 
  //WalletConnect eth_sendTransaction maps here: destination = tx.to, value = tx.value, data = tx.data.
  //spendNonce ALWAYS advances once signatures are valid, even if the inner call fails.
  //Clients must check for Spent / SpendFailed, not the outer tx status.
  function spend(address destination, uint256 value, uint8[] memory vs, bytes32[] memory rs, bytes32[] memory ss, bytes calldata data) external {
    require(destination != address(this), "Not allow sending to yourself");
    require(_validSignature(destination, value, vs, rs, ss, data), "invalid signatures");
    spendNonce = spendNonce + 1;
    //transfer tokens from this contract to the destination address
    (bool sent, bytes memory ret) = destination.call{value: value}(data);
    if (sent) {
        emit Spent(destination, value);
    } else {
        emit SpendFailed(destination, value, ret);
    }
  }
  
  //send a tx from the owner address to active the owner
  //Allow the owner to transfer some ETH, although this is not necessary.
  function active() external payable {
    require(ownerActiveTimeMap[msg.sender] > 0, "Not an owner");
    ownerActiveTimeMap[msg.sender] = block.timestamp;
  }
  
  function getRequiredWithoutInactive() public view returns (uint) {
    uint activeOwner = 0;  
    for (uint i = 0; i < owners.length; i++) {
        //if the owner is active
        if (ownerActiveTimeMap[owners[i]] + MAX_INACTIVE_TIME >= block.timestamp) {
            activeOwner++;
        }
    }
    //active owners still equal or greater then required
    if (activeOwner >= required) {
        return required;
    }
    //active less than required, all active must sign
    if (activeOwner >= 1) {
        return activeOwner;
    }
    //at least one sign.
    return 1;
  }

  // Confirm that the signature triplets (v1, r1, s1) (v2, r2, s2) ...
  // authorize a spend of this contract's funds to the given destination address.
  function _validSignature(address destination, uint256 value, uint8[] memory vs, bytes32[] memory rs, bytes32[] memory ss, bytes memory data) private returns (bool) {
    require(vs.length == rs.length);
    require(rs.length == ss.length);
    require(vs.length <= owners.length);
    require(vs.length >= getRequiredWithoutInactive());
    bytes32 message = _messageToRecover(destination, value, data);
    address[] memory addrs = new address[](vs.length);
    for (uint i = 0; i < vs.length; i++) {
        //recover the address associated with the public key from elliptic curve signature or return zero on error 
        addrs[i] = ecrecover(message, vs[i]+27, rs[i], ss[i]);
    }
    require(_distinctOwners(addrs));
    _updateActiveTime(addrs); //update addrs' active timestamp
    
    //check again, this is important to prevent inactive owners from stealing the money.
    require(vs.length >= getRequiredWithoutInactive(), "Active owners updated after the call, please call active() before calling spend.");
    
    return true;
  }
  
  // Confirm the addresses as distinct owners of this contract.
  function _distinctOwners(address[] memory addrs) private view returns (bool) {
    if (addrs.length > owners.length) {
        return false;
    }
    for (uint i = 0; i < addrs.length; i++) {
        //> 0 means one of the owner
        if (ownerActiveTimeMap[addrs[i]] == 0) {
            return false;
        }
        //address should be distinct
        for (uint j = 0; j < i; j++) {
            if (addrs[i] == addrs[j]) {
                return false;
            }
        }
    }
    return true;
  }
  
  //update the active block number for those owners
  function _updateActiveTime(address[] memory addrs) private {
    for (uint i = 0; i < addrs.length; i++) {
        //only update active timestamp for owners
        if (ownerActiveTimeMap[addrs[i]] > 0) {
            ownerActiveTimeMap[addrs[i]] = block.timestamp;
        }
    }
  }

  //support ERC721 safeTransferFrom
  function onERC721Received(address _operator, address _from, uint256 _tokenId, bytes calldata _data) external returns(bytes4) {
      return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
  }

  function onERC1155Received(address _operator, address _from, uint256 _id, uint256 _value, bytes calldata _data) external returns(bytes4) {
      return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
  }

  // =========================================================================
  //  WalletConnect / ERC-1271 extension (added 2026-09).
  //  Nothing above this block changed except CHAINID -> block.chainid and the
  //  SpendFailed event in spend().
  //
  //  dApp signatures are NEVER made over the raw dApp digest. The client MUST wrap:
  //      wrapped = getMessageHash(dappDigest)
  //  and every owner signs `wrapped`. isValidSignature() re-derives it, so a dApp cannot
  //  obtain (via personal_sign / eth_sign / eth_signTypedData) a signature that is also a
  //  valid spend() authorisation, and 1271 signatures are bound to this wallet + chain.
  //  Client MUST reject eth_sign.
  //
  //  Aggregate signature encoding: r1(32)||s1(32)||v1(1)||r2(32)||s2(32)||v2(1)|| ...
  //  v may be 0/1 or 27/28. High-s is rejected.
  // =========================================================================
  uint constant public WALLETCONNECT_VERSION = 1;

  bytes4 constant private ERC1271_MAGICVALUE = 0x1626ba7e;
  bytes4 constant private ERC1271_INVALID    = 0xffffffff;
  uint constant private SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
  bytes32 constant private EIP712_DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
  bytes32 constant private OWNBIT_MSG_TYPEHASH    = keccak256("OwnbitMessage(bytes32 message)");

  // Old contracts don't have this; client uses it to detect WalletConnect support and
  // whether chainId is part of the spend hash on ETH.
  function getWalletConnectVersion() external pure returns (uint) {
    return WALLETCONNECT_VERSION;
  }

  function getChainId() external view returns (uint) {
    return block.chainid;
  }

  // ERC-165: IERC165, IERC1271, IERC721Receiver, IERC1155Receiver
  function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
    return interfaceId == 0x01ffc9a7
        || interfaceId == 0x1626ba7e
        || interfaceId == 0x150b7a02
        || interfaceId == 0x4e2312e0;
  }

  // ERC-1155 batch receiver (was missing; safeBatchTransferFrom into the wallet used to revert)
  function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure returns (bytes4) {
    return 0xbc197c81; // bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))
  }

  function domainSeparator() public view returns (bytes32) {
    return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, block.chainid, address(this)));
  }

  // The digest owners must actually sign for a dApp-supplied hash. Never sign `hash` directly.
  function getMessageHash(bytes32 hash) public view returns (bytes32) {
    return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(OWNBIT_MSG_TYPEHASH, hash))));
  }

  function isValidSignature(bytes32 hash, bytes calldata signatures) external view returns (bytes4) {
    return _isValidAggregateSignature(getMessageHash(hash), signatures) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
  }

  function _recoverPacked(bytes32 signingHash, bytes calldata signatures, uint offset) private pure returns (address) {
    bytes32 r; bytes32 s; uint8 v;
    assembly {
      r := calldataload(add(signatures.offset, offset))
      s := calldataload(add(add(signatures.offset, offset), 32))
      v := byte(0, calldataload(add(add(signatures.offset, offset), 64)))
    }
    if (v == 0 || v == 1) v += 27;
    if (v != 27 && v != 28) return address(0);
    if (uint(s) > SECP256K1N_HALF) return address(0);
    return ecrecover(signingHash, v, r, s);
  }

  // Accident-protection rule, mirrored from _validSignature():
  //   1) sigCount >= current effective threshold
  //   2) recover distinct owners
  //   3) VIRTUALLY re-activate them (view cannot write ownerActiveTimeMap)
  //   4) sigCount >= threshold recomputed after re-activation
  // Step 4 is what stops an inactive owner from exploiting the lowered threshold.
  // Owners who only sign dApp messages must still call active() to stay active on-chain.
  function _isValidAggregateSignature(bytes32 signingHash, bytes calldata signatures) private view returns (bool) {
    if (required == 0) return false; // uninitialised proxy
    if (signatures.length == 0 || signatures.length % 65 != 0) return false;
    uint sigCount = signatures.length / 65;
    if (sigCount > owners.length || sigCount < getRequiredWithoutInactive()) return false;

    address[] memory recovered = new address[](sigCount);
    for (uint i = 0; i < sigCount; i++) {
      address a = _recoverPacked(signingHash, signatures, i * 65);
      if (a == address(0) || ownerActiveTimeMap[a] == 0) return false;
      for (uint j = 0; j < i; j++) {
        if (recovered[j] == a) return false;
      }
      recovered[i] = a;
    }
    return sigCount >= _requiredAfterVirtualRefresh(recovered);
  }

  function _requiredAfterVirtualRefresh(address[] memory signers) private view returns (uint) {
    uint activeOwner = 0;
    for (uint i = 0; i < owners.length; i++) {
      address o = owners[i];
      bool isActive = ownerActiveTimeMap[o] + MAX_INACTIVE_TIME >= block.timestamp;
      if (!isActive) {
        for (uint j = 0; j < signers.length; j++) {
          if (signers[j] == o) { isActive = true; break; }
        }
      }
      if (isActive) activeOwner++;
    }
    if (activeOwner >= required) return required;
    if (activeOwner >= 1) return activeOwner;
    return 1;
  }
}
