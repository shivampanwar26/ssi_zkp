# SSI Healthcare - Blockchain Enabled Billing System

A Self-Sovereign Identity (SSI) system that combines the Veramo framework with the Ethereum blockchain and Zero-Knowledge Proofs (ZKPs) for decentralized identity and privacy-preserving credential management in healthcare scenarios.

## 🌟 Features

### Core SSI Features
- **Decentralized Identifiers (DIDs)**: Each agent has a unique, cryptographically verifiable identity.
- **Verifiable Credentials (VCs)**: Issue, hold, and verify tamper-proof credentials.
- **Secure Wallets**: Individual encrypted wallets for each agent.
- **Connection Management**: Establish trust relationships between agents.
- **Schema Validation**: Predefined schemas for healthcare credentials (e.g., Medical Bills, Insurance Policies).

### Blockchain Features
- **Ethereum Integration**: All DIDs and credentials are anchored on the Ethereum blockchain.
- **Immutable Records**: Credentials recorded on-chain cannot be tampered with.
- **On-Chain Revocation**: Revoke credentials directly on the blockchain.
- **Transparent Verification**: Anyone can verify credentials against the blockchain.
- **Ethereum Wallets**: Each agent has an Ethereum address for blockchain interactions.
- **Smart Contract Registry**: Custom `SSIRegistry` contract manages all SSI operations.

### Zero-Knowledge Proofs (ZKPs)
- **Groth16 SnarkJS**: Patients can generate cryptographic proofs to show that a medical bill stringently satisfies their policy (e.g., amount bounds, active coverage, valid diagnoses) without fully revealing the sensitive data to the insurer.
- **Tamper Resistance**: Proofs rely on robust HMAC-bound integrity and freshness verification.

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    SSI Agent System                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Hospital   │  │   Patient    │  │   Insurer    │       │
│  │   Agent      │  │   Agent      │  │   Agent      │       │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤       │
│  │ DID (Veramo) │  │ DID (Veramo) │  │ DID (Veramo) │       │
│  │ ETH Wallet   │  │ ETH Wallet   │  │ ETH Wallet   │       │
│  │ Credentials  │  │ Credentials  │  │ Credentials  │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
│         │                 │                 │               │
└─────────┼─────────────────┼─────────────────┼───────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
 ┌──────────────────────────────────────────────────────────┐
 │               Ethereum Blockchain (Sepolia)              │
 ├──────────────────────────────────────────────────────────┤
 │  ┌────────────────────────────────────────────────────┐  │
 │  │             SSIRegistry Smart Contract             │  │
 │  ├────────────────────────────────────────────────────┤  │
 │  │ • DID Registry             • Credential Registry   │  │
 │  │ • Revocation Management    • Verifications         │  │
 │  └────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

- **Node.js**: >= 18.0.0 (required for specific fetch/crypto APIs)
- **OS**: Linux, macOS, or WSL (Windows Subsystem for Linux) recommended for `bash` compatibility.
- **Rust/Cargo**: (Optional but recommended to compile ZKP circuits).
- **Ethereum wallet** with testnet ETH (for Sepolia deployment).
- **Alchemy or Infura account** (for RPC access).

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository_url>
cd ssi-blockchain-project

# Install dependencies
npm install

# Copy environment template (if available)
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` file with your settings:

```dotenv
# Alchemy / Infura API (for Sepolia)
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY

# Private Key (DO NOT SHARE!)
PRIVATE_KEY=your_private_key_here

# Etherscan verification
ETHERSCAN_API_KEY=your_etherscan_api_key

# Blockchain Network (sepolia, localhost, mainnet)
BLOCKCHAIN_NETWORK=sepolia

# Master encryption keys and other setup details
# ...
```

### 3. Compile ZKP Circuits (Crucial)

Before running the application, you **MUST** run the trusted setup and compile the `.circom` circuits:

```bash
cd src/circuits
chmod +x setup.sh
./setup.sh
```

This will compile `medical_credential.circom` and generate the required `.wasm` file, `proving.zkey`, and `vk.json` into `src/circuits/build/`. Return to the project root after running:

```bash
cd ../..
```

### 4. Deploy Smart Contract

**Terminal 1**: Compile
```bash
npx hardhat compile
npx hardhat node
```

**Terminal 2**: Deploy to Sepolia Testnet Network
```bash
npx hardhat run scripts/deploy.js --network sepolia
```

### 5. Run the Application

```bash
npm start
# or 
node index.js
```

## 📖 Usage Guide

**Creating Agents**:
- Select "➕ Create New Agent"
- Choose from Hospital, Patient, or Insurer types.
- The agent gets a new Veramo DID, Ethereum wallet, and records itself on the blockchain.

**Healthcare Billing Workflow**:
1. **Policy Issuance**: Insurer issues an `InsurancePolicy` credential.
2. **Medical Bill**: Hospital issues a `MedicalBill` credential.
3. **Generate ZK Proof**: Patient generates a ZKP using both the medical bill and their policy, ensuring privacy.
4. **Verify ZK Proof**: The Insurer cryptographically verifies the proof against the active on-chain records, validating the predicates without compromising exact medical secrets.

**Blockchain Operations**:
- **Deploy Contract / Check Info**: Check agent's Ethereum address, ETH balance, and transaction history.
- **Revoke Credentials**: The issuer can revoke a credential directly on the blockchain, neutralizing the ZKP if the original bill is revoked.

## 🔐 Security Features

- **Cryptographic Security**: Ed25519 signatures, standard JWT formats, encrypted data-at-rest (`agent.db` and wallets).
- **Blockchain Security**: Immutable on-chain records guarantee decentralized trust. Revocations cannot be fully rolled back.
- **Zero-Knowledge Architecture**: The verifier (Insurer) evaluates claims (age rules, required diagnoses, coverage amounts) over a mathematically proven `snarkjs` zero-knowledge circuit, protecting unneeded fields.

## 📁 Project Structure

```text
ssi-blockchain-project/
├── contracts/
│   └── SSIRegistry.sol          # Smart contract for SSI operations
├── src/
│   ├── circuits/                # Circom circuits and trusted setup (setup.sh)
│   ├── agentManager-blockchain.js # Agent logic and blockchain integration
│   ├── zkpManager.js            # Zero-Knowledge Proof generation/verification
│   ├── zkpMenu.js               # CLI interactive UI components for ZKP logic
│   └── agentConfig-blockchain.js# Configs and Schemas
├── data/
│   └── wallets/                 # Local Agent wallets (ignored in git)
├── scripts/
│   └── deploy.js                # Contract deployment script
├── index.js                     # Main application (CLI)
├── hardhat.config.js            # Hardhat configuration
├── package.json                 # Dependencies
├── README.md                    # This document
└── README_ZKP.md                # In-depth architectural details around ZKPs
```

## 🔧 Smart Contract API

### SSIRegistry Contract Snippets
```solidity
// Register a new DID on-chain
function registerDID(string memory did) public returns (bool);

// Anchor a Verifiable Credential on-chain
function issueCredential(bytes32 credentialHash, string memory issuerDID, string memory subjectDID, string memory credentialType) public returns (bool);

// Check if a credential is valid
function verifyCredential(bytes32 credentialHash) public view returns (bool exists, uint256 issuedAt, string memory issuerDID, string memory subjectDID, string memory credentialType, bool revoked);

// Permanently revoke a credential
function revokeCredential(bytes32 credentialHash) public returns (bool);
```

## 🆘 Troubleshooting

- **ZKP Setup Fails `circom not found`**: Ensure `npm install` fully executed in the root directory. If `circom` still fails on MacOS or Windows, install Rust and strictly compile circom globally using Cargo (`cargo install circom`).
- **Insufficient funds for gas**: Ensure your active wallet has enough Sepolia ETH. Use the [Sepolia Faucet](https://sepoliafaucet.com/).
- **Contract not deployed**: Run `npx hardhat run scripts/deploy.js --network sepolia` and copy the resulting address. If using the automated setup script, verify your `.env` contains valid keys and URLs without a `0x` prefix for `PRIVATE_KEY`.

## 📜 License
MIT License - see LICENSE file for details.
