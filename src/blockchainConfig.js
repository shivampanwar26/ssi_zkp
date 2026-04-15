import 'dotenv/config';
import chalk from 'chalk';
import { ethers } from 'ethers';
import fs from 'fs/promises';
import path from 'path';

/**
 * Blockchain Configuration
 * Manages Ethereum connections and smart contract interactions
 * MATCHES DEPLOYED SSIRegistry.sol CONTRACT
 */

export class BlockchainManager {
  constructor(network = 'sepolia') {
    this.network = network;
    this.provider = null;
    this.contract = null;
    this.contractAddress = null;
    this.configPath = './data/blockchain-config.json';
  }

  /**
   * Initialize blockchain connection
   */
  async initialize() {
    const networks = {
      sepolia: {
        name: 'Sepolia Testnet',
        rpcUrl: process.env.SEPOLIA_RPC_URL || 'https://eth-sepolia.g.alchemy.com/v2/demo',
        chainId: 11155111,
        explorer: 'https://sepolia.etherscan.io'
      },
      localhost: {
        name: 'Local Hardhat',
        rpcUrl: 'http://127.0.0.1:8545',
        chainId: 31337,
        explorer: null
      }
    };

    const networkConfig = networks[this.network] || networks.sepolia;
    
    try {
      // Create provider - simpler approach without network detection override
      this.provider = new ethers.JsonRpcProvider(networkConfig.rpcUrl);
      
      // Quick connection test with longer timeout
      try {
        const blockNumber = await Promise.race([
          this.provider.getBlockNumber(),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 10000))
        ]);
        console.log(`✅ Connected to ${networkConfig.name} - Block: ${blockNumber}`);
      } catch (err) {
        console.log(`⚠️  Could not verify connection: ${err.message}`);
        // Continue anyway - provider might still work
      }
      
      // Load contract config
      const config = await this.loadConfig();
      if (config.contractAddress) {
        this.contractAddress = config.contractAddress;
        try {
          await this.connectToExistingContract(config.contractAddress);
          console.log(`📜 Using contract at: ${config.contractAddress}`);
          
          // Verify contract is accessible
          try {
            const count = await this.contract.getCredentialCount();
            console.log(`✅ Contract connected - ${count} credentials on chain\n`);
          } catch (err) {
            console.log(`⚠️  Contract read test failed: ${err.message}\n`);
            // Contract object exists but might have issues
          }
        } catch (err) {
          console.log(`⚠️  Contract connection failed: ${err.message}\n`);
          this.contract = null; // Clear invalid contract
        }
      } else {
        console.log(`⚠️  No contract address configured\n`);
      }
      
      return {
        network: networkConfig.name,
        chainId: networkConfig.chainId,
        explorer: networkConfig.explorer
      };
    } catch (error) {
      console.log(`⚠️  Blockchain init failed: ${error.message}\n`);
      return { network: networkConfig.name, offline: true };
    }
  }

  /**
   * Connect to deployed contract
   */
  async connectToExistingContract(address) {
    // ABI matching deployed SSIRegistry.sol exactly
    const abi = [
      // ── Events ──────────────────────────────────────────────────────────
      // FIX: parameter was 'owner' but contract uses 'registrant'
      "event DIDRegistered(string indexed did, address indexed registrant, uint256 timestamp)",
      // FIX: event was named CredentialIssued but contract emits CredentialStored
      "event CredentialStored(bytes32 indexed credentialHash, string issuerDID, string subjectDID, string credentialType, uint256 timestamp)",
      "event CredentialRevoked(bytes32 indexed credentialHash, uint256 timestamp)",
      // ── Write functions ──────────────────────────────────────────────────
      "function registerDID(string memory did) public returns (bool)",
      // FIX: function was named issueCredential but contract has storeCredential
      "function storeCredential(bytes32 credentialHash, string memory issuerDID, string memory subjectDID, string memory credentialType) public returns (bool)",
      "function revokeCredential(bytes32 credentialHash) public returns (bool)",
      // ── Read functions ───────────────────────────────────────────────────
      "function getDIDInfo(string memory did) public view returns (bool, address, uint256)",
      "function getDIDsByOwner(address owner) public view returns (string[] memory)",
      // FIX: verifyCredential does not exist in the contract; use getCredential.
      // FIX: return signature now has 7 values — bool exists is the FIRST return value.
      "function getCredential(bytes32 credentialHash) public view returns (bool, uint256, string memory, string memory, string memory, bool, uint256)",
      "function isRevoked(bytes32 credentialHash) public view returns (bool, uint256)",
      "function getCredentialCount() public view returns (uint256)"
    ];

    if (!this.provider) {
      throw new Error('Provider not initialized');
    }

    try {
      this.contractAddress = address;
      this.contract = new ethers.Contract(address, abi, this.provider);
      
      // Verify it's a valid contract by checking code at address
      const code = await this.provider.getCode(address);
      if (code === '0x') {
        throw new Error('No contract deployed at this address');
      }
    } catch (error) {
      console.log(`⚠️  Contract setup issue: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get or create wallet for an agent
   */
  async getOrCreateWallet(agentId, privateKey = null) {
    const walletPath = `./data/wallets/${agentId}/keys/ethereum-wallet.json`;
    
    try {
      const walletData = await fs.readFile(walletPath, 'utf-8');
      const parsed = JSON.parse(walletData);
      
      // Create wallet from stored private key
      let wallet = new ethers.Wallet(parsed.privateKey);
      
      if (this.provider) {
        wallet = wallet.connect(this.provider);
      }
      
      return wallet;
    } catch {
      // Create new wallet
      let wallet = privateKey ? new ethers.Wallet(privateKey) : ethers.Wallet.createRandom();
      
      if (this.provider) {
        wallet = wallet.connect(this.provider);
      }
      
      // Save wallet data (NOT encrypted for demo - encrypt in production!)
      await fs.mkdir(path.dirname(walletPath), { recursive: true });
      await fs.writeFile(walletPath, JSON.stringify({
        address: wallet.address,
        privateKey: wallet.privateKey,
        mnemonic: wallet.mnemonic?.phrase || null,
        createdAt: new Date().toISOString()
      }, null, 2), { mode: 0o600 });
      
      console.log(`  Created wallet: ${wallet.address}`);
      return wallet;
    }
  }

  // ======================================================
  // FUNDER WALLET - Pays gas for new agent DID registration
  // ======================================================
  //
  // Problem: New agents are created with 0 ETH wallets, so DID
  // registration on-chain fails. You'd have to manually fund each
  // wallet via a faucet before the agent is usable.
  //
  // Solution: A single "funder" wallet that:
  //   1. Is loaded from FUNDER_PRIVATE_KEY in .env (or auto-created)
  //   2. Pays gas to register DIDs on behalf of new agents
  //   3. Optionally sends a small amount of ETH to new agent wallets
  //      so they can do their own transactions later
  //
  // You fund ONE wallet once, and it handles all agent onboarding.
  // ======================================================

  /**
   * Initialize the funder wallet.
   * Loads from FUNDER_PRIVATE_KEY env var, or from saved config,
   * or creates a new one (which you then fund once via faucet).
   */
  async initializeFunder() {
    if (!this.provider) {
      return null;
    }

    const funderKeyPath = './data/.funder-wallet.json';

    try {
      // Priority 1: Environment variable
      if (process.env.FUNDER_PRIVATE_KEY) {
        this.funderWallet = new ethers.Wallet(process.env.FUNDER_PRIVATE_KEY, this.provider);
        console.log(chalk.gray(`  💳 Funder wallet (env): ${this.funderWallet.address}`));
      } else {
        // Priority 2: Saved funder wallet file
        try {
          const saved = await fs.readFile(funderKeyPath, 'utf-8');
          const parsed = JSON.parse(saved);
          this.funderWallet = new ethers.Wallet(parsed.privateKey, this.provider);
          console.log(chalk.gray(`  💳 Funder wallet (saved): ${this.funderWallet.address}`));
        } catch {
          // Priority 3: Create new funder wallet
          const newWallet = ethers.Wallet.createRandom();
          this.funderWallet = newWallet.connect(this.provider);
          
          await fs.mkdir(path.dirname(funderKeyPath), { recursive: true });
          await fs.writeFile(funderKeyPath, JSON.stringify({
            address: newWallet.address,
            privateKey: newWallet.privateKey,
            mnemonic: newWallet.mnemonic?.phrase || null,
            createdAt: new Date().toISOString(),
            note: 'Fund this wallet with Sepolia ETH. It pays gas for all agent DID registrations.'
          }, null, 2), { mode: 0o600 });

          console.log(chalk.yellow(`  💳 New funder wallet created: ${newWallet.address}`));
          console.log(chalk.yellow(`     Fund it at: https://sepoliafaucet.com/`));
        }
      }

      // Check funder balance
      const balance = await this.getBalance(this.funderWallet.address);
      const balFloat = parseFloat(balance.ether);
      
      if (balFloat === 0) {
        console.log(chalk.red(`  ⚠️  Funder wallet has 0 ETH!`));
        console.log(chalk.red(`     Fund ${this.funderWallet.address}`));
        console.log(chalk.red(`     at https://sepoliafaucet.com/`));
      } else if (balFloat < 0.01) {
        console.log(chalk.yellow(`  ⚠️  Funder balance low: ${balance.ether} ETH`));
      } else {
        console.log(chalk.green(`  ✅ Funder balance: ${balance.ether} ETH`));
      }

      return this.funderWallet;
    } catch (error) {
      console.log(chalk.yellow(`  ⚠️  Funder wallet init failed: ${error.message}`));
      this.funderWallet = null;
      return null;
    }
  }

  /**
   * Register a DID on-chain using the funder wallet (pays gas).
   * The DID belongs to the agent, but the funder wallet signs the tx.
   */
  async registerDIDWithFunder(did) {
    if (!this.funderWallet) {
      throw new Error('Funder wallet not initialized');
    }
    if (!this.contract) {
      throw new Error('Contract not initialized');
    }

    // Check if already registered
    const didInfo = await this.contract.getDIDInfo(did);
    if (didInfo[0]) {
      return { success: true, alreadyRegistered: true };
    }

    // Check funder balance
    const balance = await this.provider.getBalance(this.funderWallet.address);
    if (balance < ethers.parseEther('0.0005')) {
      throw new Error(
        `Funder wallet low on ETH (${ethers.formatEther(balance)} ETH). ` +
        `Fund ${this.funderWallet.address} at https://sepoliafaucet.com/`
      );
    }

    // Register using funder wallet
    console.log(chalk.gray(`  Method: SSIRegistry.registerDID(string)`));
    const contract = this.contract.connect(this.funderWallet);
    const tx = await contract.registerDID(did);
    const receipt = await tx.wait();

    return {
      success: true,
      transactionHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      fundedBy: this.funderWallet.address,
      alreadyRegistered: false
    };
  }

  /**
   * Send a small amount of ETH from funder to an agent wallet.
   * This lets the agent do its own transactions later (credential issuance, etc).
   * 
   * @param {string} toAddress - Agent's Ethereum address
   * @param {string} amountEther - Amount to send (default: '0.005' = enough for ~10 txs)
   */
  async fundAgentWallet(toAddress, amountEther = '0.005') {
    if (!this.funderWallet) {
      throw new Error('Funder wallet not initialized');
    }

    // Check funder balance
    const funderBalance = await this.provider.getBalance(this.funderWallet.address);
    const sendAmount = ethers.parseEther(amountEther);
    
    if (funderBalance < sendAmount + ethers.parseEther('0.001')) {
      throw new Error(
        `Funder has ${ethers.formatEther(funderBalance)} ETH, ` +
        `need ${amountEther} + gas. Fund ${this.funderWallet.address}`
      );
    }

    // Check if agent already has enough
    const agentBalance = await this.provider.getBalance(toAddress);
    if (agentBalance >= sendAmount) {
      return {
        success: true,
        skipped: true,
        reason: `Agent already has ${ethers.formatEther(agentBalance)} ETH`
      };
    }

    // Send ETH
    const tx = await this.funderWallet.sendTransaction({
      to: toAddress,
      value: sendAmount
    });
    const receipt = await tx.wait();

    return {
      success: true,
      skipped: false,
      transactionHash: receipt.hash,
      amount: amountEther,
      from: this.funderWallet.address,
      to: toAddress
    };
  }

  /**
   * Get funder wallet info.
   */
  async getFunderInfo() {
    if (!this.funderWallet) {
      return { initialized: false };
    }
    
    const balance = await this.getBalance(this.funderWallet.address);
    return {
      initialized: true,
      address: this.funderWallet.address,
      balance: balance.ether,
      network: this.network
    };
  }

  /**
   * Register DID on blockchain
   */
  async registerDID(did, wallet) {
    if (!this.contract) {
      throw new Error('Contract not initialized');
    }
    
    if (!wallet || !wallet.provider) {
      throw new Error('Wallet not connected to provider');
    }

    try {
      // Check if DID already registered
      const didInfo = await this.contract.getDIDInfo(did);
      if (didInfo[0]) {
        console.log(`  ℹ️  DID already registered: ${did.substring(0, 30)}...`);
        return {
          success: true,
          alreadyRegistered: true
        };
      }

      // Register the DID
      console.log(chalk.gray(`  Method: SSIRegistry.registerDID(string)`));
      const contract = this.contract.connect(wallet);
      const tx = await contract.registerDID(did);
      const receipt = await tx.wait();
      
      return {
        success: true,
        transactionHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        alreadyRegistered: false
      };
    } catch (error) {
      // More detailed error handling
      if (error.message.includes('insufficient funds')) {
        throw new Error(`Insufficient ETH in wallet ${wallet.address}. Fund it at https://sepoliafaucet.com/`);
      }
      throw new Error(`DID registration failed: ${error.message}`);
    }
  }

  /**
   * Issue credential on blockchain
   * CRITICAL FIX: Proper bytes32 generation
   */
  async issueCredentialOnChain(credential, issuerDID, subjectDID, issuerWallet) {
    if (!this.contract) {
      throw new Error('Contract not initialized');
    }
    
    if (!issuerWallet || !issuerWallet.provider) {
      throw new Error('Issuer wallet not connected to provider');
    }

    try {
      // Create a stable string representation of the credential
      // Important: Use deterministic serialization
      const credentialString = JSON.stringify(credential, Object.keys(credential).sort());
      
      // Generate proper bytes32 hash using keccak256
      // This will produce a 32-byte hash (64 hex characters + 0x prefix = 66 total)
      const credentialHashBytes = ethers.keccak256(ethers.toUtf8Bytes(credentialString));
      
      // CRITICAL: Verify it's proper bytes32 format
      if (!credentialHashBytes || credentialHashBytes.length !== 66) {
        throw new Error(`Invalid hash format: ${credentialHashBytes}`);
      }

      // Extract credential type
      let credentialType = 'VerifiableCredential';
      if (Array.isArray(credential.type)) {
        // Find the specific type (not the generic VerifiableCredential)
        credentialType = credential.type.find(t => t !== 'VerifiableCredential') || credential.type[0];
      } else if (typeof credential.type === 'string') {
        credentialType = credential.type;
      }

      // Check if credential already exists
      // FIX: verifyCredential does not exist — use getCredential. result[0] = bool exists.
      const existing = await this.contract.getCredential(credentialHashBytes);
      if (existing[0]) {
        console.log(`  ℹ️  Credential already on blockchain`);
        return {
          success: true,
          credentialHash: credentialHashBytes,
          alreadyExists: true
        };
      }

      // Connect wallet to contract
      const contractWithSigner = this.contract.connect(issuerWallet);
      
      // FIX: function is storeCredential in SSIRegistry.sol (not issueCredential)
      console.log(chalk.gray(`  Method: SSIRegistry.storeCredential(bytes32, string, string, string)`));
      const tx = await contractWithSigner.storeCredential(
        credentialHashBytes,  // bytes32 credentialHash
        issuerDID,            // string issuerDID
        subjectDID,           // string subjectDID
        credentialType        // string credentialType
      );
      
      const receipt = await tx.wait();
      
      return {
        success: true,
        credentialHash: credentialHashBytes,
        transactionHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        alreadyExists: false
      };
    } catch (error) {
      // Provide detailed error information
      const errorMessage = error.message || error.toString();
      
      // Check for common errors
      if (errorMessage.includes('insufficient funds')) {
        return {
          success: false,
          error: `Insufficient ETH in wallet ${issuerWallet.address}. Fund it at https://sepoliafaucet.com/`
        };
      }
      
      if (errorMessage.includes('Issuer DID not registered')) {
        return {
          success: false,
          error: 'Issuer DID not registered on blockchain. This should have been auto-registered.'
        };
      }
      
      if (errorMessage.includes('Subject DID not registered')) {
        return {
          success: false,
          error: 'Subject DID not registered on blockchain. This should have been auto-registered.'
        };
      }
      
      console.error(`  ⚠️  Blockchain storage failed: ${errorMessage}`);
      
      return {
        success: false,
        error: errorMessage
      };
    }
  }

  /**
   * Verify credential on blockchain
   */
  async verifyCredentialOnChain(credential) {
    if (!this.contract) {
      throw new Error('Contract not initialized');
    }

    try {
      // Create same hash as when storing
      const credentialString = JSON.stringify(credential, Object.keys(credential).sort());
      const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(credentialString));

      // FIX: verifyCredential does not exist in SSIRegistry.sol — use getCredential.
      // getCredential returns 7 values: (bool exists, uint256 storedAt, string issuerDID,
      //   string subjectDID, string credentialType, bool revoked, uint256 revokedAt)
      console.log(chalk.gray(`  Method: SSIRegistry.getCredential(bytes32) [view]`));
      const result = await this.contract.getCredential(credentialHash);
      
      return {
        exists: result[0],           // bool exists
        timestamp: Number(result[1]),// uint256 storedAt
        issuerDID: result[2],        // string issuerDID
        subjectDID: result[3],       // string subjectDID
        credentialType: result[4],   // string credentialType
        revoked: result[5],          // bool revoked
        revokedAt: Number(result[6]),// uint256 revokedAt
        credentialHash
      };
    } catch (error) {
      throw new Error(`Verification failed: ${error.message}`);
    }
  }

  /**
   * Revoke credential on blockchain
   */
  async revokeCredentialOnChain(credential, revokerWallet) {
    if (!this.contract || !revokerWallet) {
      throw new Error('Contract or wallet not initialized');
    }

    try {
      const credentialString = JSON.stringify(credential, Object.keys(credential).sort());
      const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(credentialString));

      const contract = this.contract.connect(revokerWallet);
      console.log(chalk.gray(`  Method: SSIRegistry.revokeCredential(bytes32)`));
      const tx = await contract.revokeCredential(credentialHash);
      const receipt = await tx.wait();
      
      return {
        success: true,
        transactionHash: receipt.hash,
        blockNumber: receipt.blockNumber
      };
    } catch (error) {
      throw new Error(`Revocation failed: ${error.message}`);
    }
  }

  /**
   * Get credential count
   */
  async getCredentialCount() {
    if (!this.contract) return 0;
    try {
      const count = await this.contract.getCredentialCount();
      return Number(count);
    } catch {
      return 0;
    }
  }

  /**
   * Get wallet balance
   */
  async getBalance(address) {
    if (!this.provider) {
      return { wei: '0', ether: '0.0' };
    }
    try {
      const balance = await this.provider.getBalance(address);
      return {
        wei: balance.toString(),
        ether: ethers.formatEther(balance)
      };
    } catch {
      return { wei: '0', ether: '0.0' };
    }
  }

  /**
   * Get blockchain explorer URL
   */
  getExplorerUrl(type, value) {
    const explorers = {
      sepolia: 'https://sepolia.etherscan.io',
      localhost: null
    };

    const baseUrl = explorers[this.network];
    if (!baseUrl) return null;

    switch (type) {
      case 'tx':
        return `${baseUrl}/tx/${value}`;
      case 'address':
        return `${baseUrl}/address/${value}`;
      case 'block':
        return `${baseUrl}/block/${value}`;
      default:
        return baseUrl;
    }
  }

  /**
   * Save configuration
   */
  async saveConfig(config) {
    try {
      const existingConfig = await this.loadConfig();
      const updatedConfig = { ...existingConfig, ...config };
      await fs.mkdir(path.dirname(this.configPath), { recursive: true });
      await fs.writeFile(this.configPath, JSON.stringify(updatedConfig, null, 2));
    } catch (error) {
      console.error('Config save failed:', error.message);
    }
  }

  /**
   * Load configuration
   */
  async loadConfig() {
    try {
      const content = await fs.readFile(this.configPath, 'utf-8');
      const config = JSON.parse(content);
      if (config.contractAddress) {
        this.contractAddress = config.contractAddress;
      }
      return config;
    } catch {
      return {};
    }
  }
}

export default BlockchainManager;