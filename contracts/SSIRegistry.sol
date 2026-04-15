// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * SSIRegistry - On-Chain Audit Trail for SSI Healthcare
 * 
 * Functions:
 * 
 *   WRITE:
 *   1. registerDID(string did)           — Any wallet registers a DID (steps 1-3)
 *   2. storeCredential(bytes32, ...)     — Issuer stores credential hash (step 4)
 *                                           Auth: msg.sender == DID registrant
 *   3. revokeCredential(bytes32)         — Issuer revokes a credential
 *                                           Auth: msg.sender == issuer DID registrant
 * 
 *   READ:
 *   4. getDIDInfo(string did)            — Check DID exists + who registered it (step 8)
 *   5. getCredential(bytes32 hash)       — Full credential record + revocation status (step 8)
 *   6. isRevoked(bytes32 hash)           — Quick revocation check
 *   7. getDIDsByOwner(address)           — List DIDs by wallet
 *   8. getCredentialCount()              — Total credentials stored
 * 
 * What this contract does NOT do:
 *   - No on-chain verification logic (done off-chain via ZKP, steps 5-9)
 *   - No claim processing or payment logic
 */
contract SSIRegistry {

    // ═══════════════════════════════════════
    // STRUCTS
    // ═══════════════════════════════════════

    struct DIDRecord {
        bool exists;
        address registrant;
        uint256 registeredAt;
    }

    struct CredentialRecord {
        bool exists;
        uint256 storedAt;
        string issuerDID;
        string subjectDID;
        string credentialType;
        bool revoked;
        uint256 revokedAt;
    }

    // ═══════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════

    mapping(string => DIDRecord) private dids;
    mapping(address => string[]) private ownerDIDs;
    mapping(bytes32 => CredentialRecord) private credentials;
    uint256 public credentialCount;

    // ═══════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════

    event DIDRegistered(
        string indexed did,
        address indexed registrant,
        uint256 timestamp
    );

    event CredentialStored(
        bytes32 indexed credentialHash,
        string issuerDID,
        string subjectDID,
        string credentialType,
        uint256 timestamp
    );

    event CredentialRevoked(
        bytes32 indexed credentialHash,
        uint256 timestamp
    );

    // ═══════════════════════════════════════
    // WRITE: DID REGISTRATION (Steps 1-3)
    // ═══════════════════════════════════════

    function registerDID(string memory did) public returns (bool) {
        require(!dids[did].exists, "DID already registered");
        require(bytes(did).length > 0, "DID cannot be empty");

        dids[did] = DIDRecord({
            exists: true,
            registrant: msg.sender,
            registeredAt: block.timestamp
        });

        ownerDIDs[msg.sender].push(did);

        emit DIDRegistered(did, msg.sender, block.timestamp);
        return true;
    }

    // ═══════════════════════════════════════
    // WRITE: CREDENTIAL STORAGE (Step 4)
    // ═══════════════════════════════════════

    function storeCredential(
        bytes32 credentialHash,
        string memory issuerDID,
        string memory subjectDID,
        string memory credentialType
    ) public returns (bool) {
        require(!credentials[credentialHash].exists, "Credential hash already stored");
        require(dids[issuerDID].exists, "Issuer DID not registered");
        require(dids[subjectDID].exists, "Subject DID not registered");
        require(
            msg.sender == dids[issuerDID].registrant,
            "Only the DID registrant can store credentials for this DID"
        );

        credentials[credentialHash] = CredentialRecord({
            exists: true,
            storedAt: block.timestamp,
            issuerDID: issuerDID,
            subjectDID: subjectDID,
            credentialType: credentialType,
            revoked: false,
            revokedAt: 0
        });

        credentialCount++;

        emit CredentialStored(
            credentialHash, issuerDID, subjectDID, credentialType, block.timestamp
        );

        return true;
    }

    // ═══════════════════════════════════════
    // WRITE: CREDENTIAL REVOCATION
    // ═══════════════════════════════════════

    function revokeCredential(bytes32 credentialHash) public returns (bool) {
        CredentialRecord storage cred = credentials[credentialHash];

        require(cred.exists, "Credential does not exist");
        require(!cred.revoked, "Credential already revoked");
        require(
            msg.sender == dids[cred.issuerDID].registrant,
            "Only the issuer can revoke this credential"
        );

        cred.revoked = true;
        cred.revokedAt = block.timestamp;

        emit CredentialRevoked(credentialHash, block.timestamp);
        return true;
    }

    // ═══════════════════════════════════════
    // READ FUNCTIONS
    // ═══════════════════════════════════════

    function getDIDInfo(string memory did) public view returns (
        bool exists,
        address registrant,
        uint256 registeredAt
    ) {
        DIDRecord storage record = dids[did];
        return (record.exists, record.registrant, record.registeredAt);
    }

    function getDIDsByOwner(address owner) public view returns (string[] memory) {
        return ownerDIDs[owner];
    }

    function getCredential(bytes32 credentialHash) public view returns (
        bool exists,
        uint256 storedAt,
        string memory issuerDID,
        string memory subjectDID,
        string memory credentialType,
        bool revoked,
        uint256 revokedAt
    ) {
        CredentialRecord storage record = credentials[credentialHash];
        return (
            record.exists,
            record.storedAt,
            record.issuerDID,
            record.subjectDID,
            record.credentialType,
            record.revoked,
            record.revokedAt
        );
    }

    function isRevoked(bytes32 credentialHash) public view returns (
        bool revoked,
        uint256 revokedAt
    ) {
        CredentialRecord storage record = credentials[credentialHash];
        require(record.exists, "Credential does not exist");
        return (record.revoked, record.revokedAt);
    }

    function getCredentialCount() public view returns (uint256) {
        return credentialCount;
    }
}
