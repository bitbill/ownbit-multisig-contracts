// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/// @title Ownbit Multisig (Enterprise + Weighted Signers)
/// @notice ETH/ERC20/ERC721/ERC1155 supported via generic call data
/// @dev Features:
///   - Weighted Signers for spending
///   - Owners as admins (1 vote each, no weight)
///   - Separate thresholds: signRequired (for spending), ownerRequired (for configuration changes)
///   - Distinct nonces for spending and configuration changes
///   - ChangeOwners / ChangeSigners functions controlled by Owners
///   - ERC-1271 (WalletConnect) — see extension block at the end
/// last update: 2026-09-07 (spend(): inner-call failure no longer reverts, nonce always advances, SpendFailed emitted)
/// previous:    2026-09-06 (WalletConnect / ERC-1271 extension; CHAINID constant replaced by block.chainid)

contract ProxyStorage {
    // ---------- Signers (for spending) ----------
    mapping(address => bool) public isSigner;
    mapping(address => uint256) public signerWeight; // weight per signer
    address[] public signers;
    uint256 public signRequired; // threshold for spending

    // ---------- Owners (admins, for configuration changes) ----------
    mapping(address => bool) public isOwner;
    address[] public owners;
    uint256 public ownerRequired; // threshold for configuration changes (by headcount)

    // ---------- Nonces ----------
    uint256 public spendNonce;   // spend replay protection
    uint256 public configNonce;  // config change replay protection
}

contract OwnbitMultiSigImplementation is ProxyStorage {
    uint256 public constant MAX_OWNER_COUNT  = 7;
    uint256 public constant MAX_SIGNER_COUNT = 9;  

    // ---- Events ----
    event Funded(address indexed from, uint256 value);
    event Spent(address indexed to, uint256 value, bytes data);
    event SpendFailed(address indexed to, uint256 value, bytes data, bytes reason);
    event OwnersChanged(address[] owners, uint256 ownerRequired);
    event SignersChanged(address[] signers, uint256[] weights, uint256 signRequired);

    // ---- Modifiers ----
    modifier validOwnerRequirement(uint256 ownerCount, uint256 _ownerRequired) {
        require(ownerCount > 0 && ownerCount <= MAX_OWNER_COUNT, "invalid owner count");
        require(_ownerRequired >= 1 && _ownerRequired <= ownerCount, "invalid ownerRequired");
        _;
    }

    modifier validSignerRequirement(
        address[] memory _signers,
        uint256[] memory _weights,
        uint256 _signRequired
    ) {
        require(_signers.length > 0 && _signers.length <= MAX_SIGNER_COUNT, "invalid signer count");
        require(_signers.length == _weights.length, "weights length mismatch");
        uint256 total = 0;
        for (uint256 i = 0; i < _weights.length; i++) {
            require(_weights[i] >= 1, "weight must >= 1");
            total += _weights[i];
        }
        require(_signRequired >= 1 && _signRequired <= total, "invalid signRequired");
        _;
    }

    // ---- Initialization ----
    /// @param _owners initial owners (admins, 1 vote each)
    /// @param _signers initial signers (for spending)
    /// @param _weights weights for each signer (>=1, aligned with _signers)
    /// @param _ownerRequired threshold for owner approvals
    /// @param _signRequired threshold for signer weighted approvals
    function initialize(
        address[] memory _owners,
        address[] memory _signers,
        uint256[] memory _weights,
        uint256 _ownerRequired,
        uint256 _signRequired
    )
        public
        validOwnerRequirement(_owners.length, _ownerRequired)
        validSignerRequirement(_signers, _weights, _signRequired)
    {
        require(owners.length == 0 && signers.length == 0, "already initialized");

        // initialize owners
        for (uint256 i = 0; i < _owners.length; i++) {
            address o = _owners[i];
            require(o != address(0), "zero owner");
            for (uint256 j = 0; j < i; j++) require(o != _owners[j], "duplicate owner");
            isOwner[o] = true;
            owners.push(o);
        }
        ownerRequired = _ownerRequired;

        // initialize signers + weights
        for (uint256 i = 0; i < _signers.length; i++) {
            address s = _signers[i];
            require(s != address(0), "zero signer");
            for (uint256 j = 0; j < i; j++) require(s != _signers[j], "duplicate signer");
            isSigner[s] = true;
            signerWeight[s] = _weights[i];
            signers.push(s);
        }
        signRequired = _signRequired;
    }

    // ---- Receive ETH ----
    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    // ---- Views ----
    function getOwners() external view returns (address[] memory) { return owners; }
    function getSigners() external view returns (address[] memory) { return signers; }
    function getSignerWeights() external view returns (uint256[] memory ws) {
        ws = new uint256[](signers.length);
        for (uint256 i = 0; i < signers.length; i++) {
            ws[i] = signerWeight[signers[i]];
        }
    }
    function getSignRequired() external view returns (uint256) { return signRequired; }
    function getOwnerRequired() external view returns (uint256) { return ownerRequired; }
    function getSpendNonce() external view returns (uint256) { return spendNonce; }
    function getConfigNonce() external view returns (uint256) { return configNonce; }

    // ------------------------------------------------------------------------
    //                        Spending (weighted signers)
    // ------------------------------------------------------------------------

    function _spendMessage(
        address destination,
        uint256 value,
        bytes memory data
    ) private view returns (bytes32) {
        //CHANGED: CHAINID constant -> block.chainid (same position, same bytes on the chain it was deployed for).
        return keccak256(abi.encodePacked(
            address(this),
            destination,
            value,
            data,
            spendNonce,
            block.chainid
        ));
    }

    function _toEthSigned(bytes32 msgHash) private pure returns (bytes32) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        return keccak256(abi.encodePacked(prefix, msgHash));
    }

    //destination can be a normal address or a contract address, such as ERC20 contract address.
    //value is the wei transferred to the destination.
    //data for transfer ether: 0x
    //data for transfer erc20 example: 0xa9059cbb000000000000000000000000ac6342a7efb995d63cc91db49f6023e95873d25000000000000000000000000000000000000000000000000000000000000003e8
    //data for transfer erc721 example: 0x42842e0e00000000000000000000000097b65ad59c8c96f2dd786751e6279a1a6d34a4810000000000000000000000006cb33e7179860d24635c66850f1f6a5d4f8eee6d0000000000000000000000000000000000000000000000000000000000042134
    //data can contain any data to be executed. 
    //WalletConnect eth_sendTransaction maps here: destination = tx.to, value = tx.value, data = tx.data.
    /// @notice Spend funds if accumulated signer weight >= signRequired
    /// @dev spendNonce ALWAYS advances once signatures are valid, even if the inner call fails
    ///      (keeps pre-signed nonce queues moving). Clients must check for Spent / SpendFailed,
    ///      not the outer tx status.
    function spend(
        address destination,
        uint256 value,
        uint8[] memory vs,
        bytes32[] memory rs,
        bytes32[] memory ss,
        bytes calldata data
    ) external {
        require(destination != address(this), "cannot send to self");
        require(vs.length == rs.length && rs.length == ss.length, "sig length mismatch");
        require(vs.length > 0 && vs.length <= signers.length, "invalid sig count");

        bytes32 m = _toEthSigned(_spendMessage(destination, value, data));
        uint256 accWeight = _verifySignerSigsAndAccumulate(m, vs, rs, ss);
        require(accWeight >= signRequired, "insufficient signer weight");

        spendNonce += 1;

        (bool sent, bytes memory ret) = destination.call{value: value}(data);
        if (sent) {
            emit Spent(destination, value, data);
        } else {
            emit SpendFailed(destination, value, data, ret);
        }
    }

    /// @dev verify signer signatures and accumulate weight, ensuring uniqueness
    function _verifySignerSigsAndAccumulate(
        bytes32 message,
        uint8[] memory vs,
        bytes32[] memory rs,
        bytes32[] memory ss
    ) private view returns (uint256 accWeight) {
        address[] memory addrs = new address[](vs.length);
        for (uint256 i = 0; i < vs.length; i++) {
            address a = ecrecover(message, vs[i]+27, rs[i], ss[i]);
            require(a != address(0), "ecrecover failed");
            require(isSigner[a], "not signer");
            for (uint256 j = 0; j < i; j++) require(a != addrs[j], "duplicate signer");
            addrs[i] = a;
            accWeight += signerWeight[a];
        }
    }

    // ------------------------------------------------------------------------
    //                        Configuration Changes (Owners)
    // ------------------------------------------------------------------------

    function _ownersChangeMessage(
        address[] memory newOwners,
        uint256 newOwnerRequired
    ) private view returns (bytes32) {
        bytes memory ownersPacked;
        for (uint i = 0; i < newOwners.length; i++) {
            ownersPacked = bytes.concat(ownersPacked, bytes20(newOwners[i]));  
        }
        return keccak256(abi.encodePacked(
            uint256(1), // domain = 1  (change owners)
            address(this),
            ownersPacked,
            newOwnerRequired,
            configNonce,
            block.chainid
        ));
    }

    function _signersChangeMessage(
        address[] memory newSigners,
        uint256[] memory newWeights,
        uint256 newSignRequired
    ) private view returns (bytes32) {
        bytes memory signersPacked;
        for (uint i = 0; i < newSigners.length; i++) {
            signersPacked = bytes.concat(signersPacked, bytes20(newSigners[i]));
        }
        bytes memory weightsPacked;
        for (uint i = 0; i < newWeights.length; i++) {
            weightsPacked = bytes.concat(weightsPacked, bytes32(newWeights[i]));
        }
        return keccak256(abi.encodePacked(
            uint256(2), // domain = 2  (change signers)
            address(this),
            signersPacked,
            weightsPacked,
            newSignRequired,
            configNonce,
            block.chainid
        ));
    }

    /// @dev verify owner signatures (headcount based)
    function _verifyOwnerSigsCount(
        bytes32 message,
        uint8[] memory vs,
        bytes32[] memory rs,
        bytes32[] memory ss
    ) private view returns (uint256 count) {
        require(vs.length == rs.length && rs.length == ss.length, "sig length mismatch");
        require(vs.length > 0 && vs.length <= owners.length, "invalid sig count");
        address[] memory addrs = new address[](vs.length);
        for (uint256 i = 0; i < vs.length; i++) {
            address a = ecrecover(_toEthSigned(message), vs[i]+27, rs[i], ss[i]);
            require(a != address(0), "ecrecover failed");
            require(isOwner[a], "not owner");
            for (uint256 j = 0; j < i; j++) require(a != addrs[j], "duplicate owner");
            addrs[i] = a;
            count += 1;
        }
    }

    /// @notice Change Owners (admins)
    function changeOwners(
        address[] calldata newOwners,
        uint256 newOwnerRequired,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) external validOwnerRequirement(newOwners.length, newOwnerRequired) {
        bytes32 m = _ownersChangeMessage(newOwners, newOwnerRequired);
        uint256 ok = _verifyOwnerSigsCount(m, vs, rs, ss);
        require(ok >= ownerRequired, "insufficient owner approvals");

        _resetOwners(newOwners);
        ownerRequired = newOwnerRequired;
        configNonce += 1;

        emit OwnersChanged(newOwners, newOwnerRequired);
    }

    /// @notice Change Signers (weights + threshold)
    function changeSigners(
        address[] calldata newSigners,
        uint256[] calldata newWeights,
        uint256 newSignRequired,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    )
        external
        validSignerRequirement(newSigners, newWeights, newSignRequired)
    {
        bytes32 m = _signersChangeMessage(newSigners, newWeights, newSignRequired);
        uint256 ok = _verifyOwnerSigsCount(m, vs, rs, ss);
        require(ok >= ownerRequired, "insufficient owner approvals");

        _resetSigners(newSigners, newWeights);
        signRequired = newSignRequired;
        configNonce += 1;

        emit SignersChanged(newSigners, newWeights, newSignRequired);
    }

    // ---- internal resets ----
    function _resetOwners(address[] memory newOwners) internal {
        for (uint256 i = 0; i < owners.length; i++) {
            isOwner[owners[i]] = false;
        }
        delete owners;
        for (uint256 i = 0; i < newOwners.length; i++) {
            address o = newOwners[i];
            require(o != address(0), "zero owner");
            for (uint256 j = 0; j < i; j++) require(o != newOwners[j], "duplicate owner");
            isOwner[o] = true;
            owners.push(o);
        }
    }

    function _resetSigners(address[] memory newSigners, uint256[] memory newWeights) internal {
        for (uint256 i = 0; i < signers.length; i++) {
            address s = signers[i];
            isSigner[s] = false;
            signerWeight[s] = 0;
        }
        delete signers;
        for (uint256 i = 0; i < newSigners.length; i++) {
            address a = newSigners[i];
            require(a != address(0), "zero signer");
            for (uint256 j = 0; j < i; j++) require(a != newSigners[j], "duplicate signer");
            isSigner[a] = true;
            signerWeight[a] = newWeights[i];
            signers.push(a);
        }
    }

    // ---- ERC721 / ERC1155 hooks ----
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
    }

    // =========================================================================
    //  WalletConnect / ERC-1271 extension (added 2026-09).
    //  Nothing above this block changed except CHAINID -> block.chainid and the
    //  spend() failure handling (no revert, SpendFailed event).
    //
    //  dApp signatures are NEVER made over the raw dApp digest. The client MUST wrap:
    //      wrapped = getMessageHash(dappDigest)
    //  and every signer signs `wrapped`. isValidSignature() re-derives it, so a dApp cannot
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

    // The digest signers must actually sign for a dApp-supplied hash. Never sign `hash` directly.
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

    // Enterprise rule: accumulated weight of distinct signers >= signRequired.
    function _isValidAggregateSignature(bytes32 signingHash, bytes calldata signatures) private view returns (bool) {
        if (signRequired == 0) return false; // uninitialised proxy
        if (signatures.length == 0 || signatures.length % 65 != 0) return false;
        uint sigCount = signatures.length / 65;
        if (sigCount > signers.length) return false;

        address[] memory recovered = new address[](sigCount);
        uint accWeight = 0;
        for (uint i = 0; i < sigCount; i++) {
            address a = _recoverPacked(signingHash, signatures, i * 65);
            if (a == address(0) || !isSigner[a]) return false;
            for (uint j = 0; j < i; j++) {
                if (recovered[j] == a) return false;
            }
            recovered[i] = a;
            accWeight += signerWeight[a];
        }
        return accWeight >= signRequired;
    }
}
