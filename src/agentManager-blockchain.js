import chalk from 'chalk';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import {
  AGENT_TYPES,
  canIssueCredential,
  canGenerateProof,
  canVerifyProof,
  canRequestProof,
  createAgentDatabase,
  createEthereumWallet,
  createVeramoAgent,
  CREDENTIAL_SCHEMAS
} from './agentConfig-blockchain.js';
import { BlockchainManager } from './blockchainConfig.js';
import { ZKPManager } from './zkpManager.js';
import {
  dashboardStats, agentTable, credentialTable,
  zkProofTable, verificationResult, txReceipt,
  blockchainStatusBar, infoBox, Table
} from '../tableUtils.js';

export class AgentManager {
  constructor(enableBlockchain = true, network = 'sepolia') {
    this.agents = new Map();
    this.walletsDir = './data/wallets';
    this.registryFile = './data/registry.json';
    this.enableBlockchain = enableBlockchain;
    this.network = network;
    this.blockchain = null;
    this.zkp = null;
  }

  // ======================================================
  // BLOCKCHAIN INITIALIZATION
  // ======================================================
  
  async initializeBlockchain() {
    if (!this.enableBlockchain) return;
    
    try {
      this.blockchain = new BlockchainManager(this.network);
      await this.blockchain.initialize();
      
      // Initialize funder wallet for agent onboarding
      await this.blockchain.initializeFunder();
      
      console.log(chalk.green(`✅ Blockchain initialized on ${this.network}\n`));
    } catch (error) {
      console.log(chalk.yellow(`⚠️  Blockchain unavailable: ${error.message}\n`));
      this.enableBlockchain = false;
    }

    // Initialize ZKP module
    try {
      this.zkp = new ZKPManager();
      await this.zkp.initialize();
    } catch (error) {
      console.log(chalk.yellow(`⚠️  ZKP module failed: ${error.message}\n`));
    }
  }

  // ======================================================
  // WALLET OPERATIONS
  // ======================================================
  
  async getWalletPath(agentId) {
    return path.join(this.walletsDir, agentId);
  }

  async saveToWallet(agentId, type, data, filename) {
    const walletPath = await this.getWalletPath(agentId);
    const filePath = path.join(walletPath, type, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
  }

  async loadFromWallet(agentId, type, filename) {
    try {
      const walletPath = await this.getWalletPath(agentId);
      const filePath = path.join(walletPath, type, filename);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  async listWalletItems(agentId, type) {
    try {
      const walletPath = await this.getWalletPath(agentId);
      const dirPath = path.join(walletPath, type);
      const files = await fs.readdir(dirPath);
      
      const items = [];
      for (const file of files) {
        if (file.endsWith('.json')) {
          const data = await this.loadFromWallet(agentId, type, file);
          if (data) items.push(data);
        }
      }
      return items;
    } catch {
      return [];
    }
  }

  // ======================================================
  // REGISTRY OPERATIONS
  // ======================================================
  
  async loadRegistry() {
    try {
      const content = await fs.readFile(this.registryFile, 'utf-8');
      return JSON.parse(content);
    } catch {
      return [];
    }
  }

  async saveRegistry(registry) {
    await fs.mkdir(path.dirname(this.registryFile), { recursive: true });
    await fs.writeFile(this.registryFile, JSON.stringify(registry, null, 2));
  }

  async updateAgentInRegistry(agentId, updates) {
    const registry = await this.loadRegistry();
    const index = registry.findIndex(a => a.id === agentId);
    
    if (index >= 0) {
      registry[index] = { ...registry[index], ...updates };
      await this.saveRegistry(registry);
    }
  }

  // ======================================================
  // LOAD EXISTING AGENTS
  // ======================================================
  
  async loadAgents() {
    try {
      const registry = await this.loadRegistry();

      for (const data of registry) {
        await this.loadAgent(
          data.id,
          data.name,
          data.type,
          data.did,
          data.metadata,
          data.blockchainAddress
        );
      }

      return this.agents.size;
    } catch (error) {
      console.error('Error loading agents:', error.message);
      return 0;
    }
  }

  async loadAgent(id, name, type, did, metadata = {}, blockchainAddress = null) {
    const db = await createAgentDatabase(id);
    const veramo = await createVeramoAgent(id, db);

    // Load or create Ethereum wallet
    let ethWallet = null;
    let address = blockchainAddress;
    
    if (this.enableBlockchain) {
      try {
        ethWallet = await createEthereumWallet(id);
        address = ethWallet.address;
        
        // Connect wallet to provider if blockchain is available
        if (this.blockchain?.provider) {
          ethWallet = ethWallet.connect(this.blockchain.provider);
        }

        // Check DID ownership on-chain: the DID should be owned by THIS agent's wallet.
        // If it was registered by the funder wallet in a previous version, warn the user.
        if (this.blockchain?.contract && did) {
          try {
            const didInfo = await this.blockchain.contract.getDIDInfo(did);
            if (didInfo[0]) { // DID exists on-chain
              const onChainOwner = didInfo[1].toLowerCase();
              const agentWallet = address.toLowerCase();
              
              if (onChainOwner !== agentWallet) {
                console.log(chalk.yellow(`  ⚠️  DID ownership mismatch for ${name}:`));
                console.log(chalk.yellow(`     On-chain owner: ${didInfo[1]}`));
                console.log(chalk.yellow(`     Agent wallet:   ${address}`));
                console.log(chalk.yellow(`     This agent cannot issue credentials on-chain.`));
                console.log(chalk.yellow(`     Fix: Delete this agent, recreate it, or redeploy the contract.`));
              }
            }
          } catch {
            // Non-critical — just a check
          }
        }
      } catch (error) {
        console.log(chalk.yellow(`⚠️  Could not load blockchain wallet for ${name}`));
      }
    }

    // Load connections from wallet
    const connections = await this.listWalletItems(id, 'connections');
    
    // Load credentials from wallet
    const credentials = await this.listWalletItems(id, 'credentials');

    const agent = {
      id,
      name,
      type,
      did,
      agent: veramo,
      ethWallet,
      blockchainAddress: address,
      connections,
      credentials,
      metadata: {
        ...metadata,
        lastAccessed: new Date().toISOString()
      }
    };

    this.agents.set(id, agent);
    return agent;
  }

  // ======================================================
  // CREATE NEW AGENT
  // ======================================================
  
  async createAgent(name, type, metadata = {}) {
    const id = this.generateAgentId(name);

    if (this.agents.has(id)) {
      throw new Error('Agent already exists');
    }

    const agentType = AGENT_TYPES[type];
    if (!agentType) {
      throw new Error(`Invalid agent type: ${type}`);
    }
    
    console.log(`\n${agentType.icon} Creating agent: ${name}...`);

    const db = await createAgentDatabase(id);
    const veramo = await createVeramoAgent(id, db);

    const identifier = await veramo.didManagerCreate({
      provider: 'did:key',
    });

    // Create Ethereum wallet for blockchain operations
    let ethWallet = null;
    let blockchainAddress = null;
    
    if (this.enableBlockchain) {
      try {
        ethWallet = await createEthereumWallet(id);
        blockchainAddress = ethWallet.address;
        console.log(chalk.gray(`  Blockchain wallet: ${blockchainAddress}`));
        
        // Connect wallet to provider
        if (this.blockchain?.provider) {
          ethWallet = ethWallet.connect(this.blockchain.provider);
        }
        
        // ── DID Registration Flow ──
        // IMPORTANT: The smart contract maps DID → msg.sender as owner.
        // When issuing credentials, the contract checks that the caller
        // is the DID owner. So the agent MUST register its own DID using
        // its OWN wallet — not the funder wallet.
        //
        // Flow:
        //   1. Funder sends ETH to agent wallet (so it can pay gas)
        //   2. Agent registers its own DID with its own wallet
        //   3. Contract records: DID owner = agent's wallet address
        //   4. Later, agent can call issueCredential() successfully
        //
        if (this.blockchain?.contract) {
          try {
            // Step 1: Fund the agent wallet using funder
            if (this.blockchain?.funderWallet) {
              try {
                console.log(chalk.gray('  Funding agent wallet from funder...'));
                const fundResult = await this.blockchain.fundAgentWallet(blockchainAddress);
                if (fundResult.success && !fundResult.skipped) {
                  console.log(chalk.green(`  ✅ Agent funded: ${fundResult.amount} ETH`));
                  console.log(chalk.gray(`     TX: ${fundResult.transactionHash.substring(0, 20)}...`));
                } else if (fundResult.skipped) {
                  console.log(chalk.gray(`  ℹ️  ${fundResult.reason}`));
                }
              } catch (fundError) {
                console.log(chalk.yellow(`  ⚠️  Funding skipped: ${fundError.message}`));
              }
            }

            // Step 2: Agent registers its own DID with its own wallet
            // Check if agent now has enough ETH (either from funder or pre-existing)
            const balance = await this.blockchain.getBalance(blockchainAddress);
            if (parseFloat(balance.ether) >= 0.0005) {
              console.log(chalk.gray('  Registering DID on blockchain (agent wallet)...'));
              const result = await this.blockchain.registerDID(identifier.did, ethWallet);
              
              if (result.success && !result.alreadyRegistered) {
                console.log(chalk.green(`  ✅ DID registered on-chain (tx: ${result.transactionHash.substring(0, 10)}...)`));
                console.log(chalk.gray(`     DID owner: ${blockchainAddress}`));
                metadata.didRegistrationTx = result.transactionHash;
                metadata.didRegisteredAt = new Date().toISOString();
                metadata.didOwnerWallet = blockchainAddress;
              } else if (result.alreadyRegistered) {
                console.log(chalk.gray('  ℹ️  DID already registered on-chain'));
              }
            } else {
              console.log(chalk.yellow(`  ⚠️  Agent has ${balance.ether} ETH — not enough for DID registration.`));
              if (!this.blockchain?.funderWallet) {
                console.log(chalk.yellow(`     Fund funder wallet or agent at https://sepoliafaucet.com/`));
                console.log(chalk.yellow(`     Agent address: ${blockchainAddress}`));
              }
            }
          } catch (error) {
            console.log(chalk.yellow(`  ⚠️  DID registration failed: ${error.message}`));
            // Continue — can register later
          }
        }
      } catch (error) {
        console.log(chalk.yellow(`  ⚠️  Blockchain wallet creation failed: ${error.message}`));
      }
    }

    const agent = {
      id,
      name,
      type,
      did: identifier.did,
      agent: veramo,
      ethWallet,
      blockchainAddress,
      connections: [],
      credentials: [],
      metadata: {
        ...metadata,
        createdAt: new Date().toISOString(),
        lastAccessed: new Date().toISOString(),
        agentType: agentType.label
      }
    };

    this.agents.set(id, agent);

    // Add to registry
    const registry = await this.loadRegistry();
    registry.push({
      id,
      name,
      type,
      did: identifier.did,
      blockchainAddress,
      metadata: agent.metadata
    });
    await this.saveRegistry(registry);

    console.log(`✅ Created: ${name}`);
    console.log(`DID: ${identifier.did}\n`);

    return agent;
  }

  // ======================================================
  // DELETE AGENT
  // ======================================================
  
  async deleteAgent(id) {
    const agent = this.agents.get(id);
    if (!agent) return;

    // Remove from other agents' connections
    for (const other of this.agents.values()) {
      const updated = other.connections.filter(c => c.agentId !== id);
      if (updated.length !== other.connections.length) {
        other.connections = updated;
        // Update connections in wallet
        for (const conn of other.connections) {
          await this.saveToWallet(other.id, 'connections', conn, `${conn.agentId}.json`);
        }
      }
    }

    // Remove from registry
    const registry = await this.loadRegistry();
    const filtered = registry.filter(a => a.id !== id);
    await this.saveRegistry(filtered);

    // Delete wallet directory
    try {
      const walletPath = await this.getWalletPath(id);
      await fs.rm(walletPath, { recursive: true, force: true });
    } catch (error) {
      console.error(`Could not delete wallet for ${id}`);
    }

    this.agents.delete(id);
  }

  // ======================================================
  // ISSUE CREDENTIAL
  // ======================================================
  
  async issueCredential(issuerId, subjectId, credentialData) {
    const issuer = this.getAgent(issuerId);
    const subject = this.getAgent(subjectId);

    if (!issuer || !subject) {
      throw new Error('Issuer or subject not found');
    }

    const credentialType = credentialData.type;
    
    // Validate permission using strict rules
    canIssueCredential(issuer.type, credentialType);

    // Validate schema
    const schema = CREDENTIAL_SCHEMAS[credentialType];
    if (!schema) {
      throw new Error(`Unknown credential type: ${credentialType}`);
    }

    // Validate required fields
    for (const field of schema.required) {
      if (!credentialData.claims[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    const issuerType = AGENT_TYPES[issuer.type];
    const subjectType = AGENT_TYPES[subject.type];
    
    console.log(`\n${issuerType.icon} ${chalk.cyan(issuer.name)} → ${subjectType.icon} ${chalk.green(subject.name)}`);
    console.log(chalk.yellow(`Issuing: ${credentialType}`));

    // Create the verifiable credential
    const credential = await issuer.agent.createVerifiableCredential({
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', credentialType],
        issuer: { id: issuer.did },
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: subject.did,
          ...credentialData.claims,
        },
      },
      proofFormat: 'jwt',
    });

    const credentialRecord = {
      id: crypto.randomBytes(32).toString('hex'),     
      issuer: issuer.name,
      issuerDid: issuer.did,
      type: credentialType,
      issuedAt: Date.now(),
      credential,
      status: 'active',
      blockchainTxHash: null
    };

    // Verify DIDs are registered before issuing credential
    // IMPORTANT: Each agent must register its own DID with its own wallet
    // so the contract maps DID ownership to that wallet address.
    if (this.enableBlockchain && this.blockchain?.contract) {
      try {
        // Check if issuer DID is registered
        const issuerInfo = await this.blockchain.contract.getDIDInfo(issuer.did);
        if (!issuerInfo[0]) {
          console.log(chalk.yellow('  ⚠️  Issuer DID not registered, registering now...'));
          
          // Ensure issuer wallet has ETH
          let issuerWalletForReg = issuer.ethWallet;
          if (!issuerWalletForReg || !issuerWalletForReg.provider) {
            issuerWalletForReg = await this.blockchain.getOrCreateWallet(issuer.id);
          }
          
          // Fund issuer if needed
          if (this.blockchain.funderWallet) {
            try {
              await this.blockchain.fundAgentWallet(issuer.blockchainAddress);
            } catch { /* non-critical */ }
          }
          
          const result = await this.blockchain.registerDID(issuer.did, issuerWalletForReg);
          if (result.success) {
            console.log(chalk.green(`  ✅ Issuer DID registered (tx: ${result.transactionHash?.substring(0, 10)}...)`));
          }
        }

        // Check if subject DID is registered
        const subjectInfo = await this.blockchain.contract.getDIDInfo(subject.did);
        if (!subjectInfo[0]) {
          console.log(chalk.yellow('  ⚠️  Subject DID not registered, registering now...'));
          
          let subjectWallet = subject.ethWallet;
          if (!subjectWallet || !subjectWallet.provider) {
            subjectWallet = await this.blockchain.getOrCreateWallet(subject.id);
          }
          
          // Fund subject if needed
          if (this.blockchain.funderWallet) {
            try {
              await this.blockchain.fundAgentWallet(subject.blockchainAddress);
            } catch { /* non-critical */ }
          }
          
          const result = await this.blockchain.registerDID(subject.did, subjectWallet);
          if (result.success) {
            console.log(chalk.green(`  ✅ Subject DID registered (tx: ${result.transactionHash?.substring(0, 10)}...)`));
          }
        }
      } catch (error) {
        console.log(chalk.yellow(`  ⚠️  DID registration check failed: ${error.message}`));
      }
    }

    // Store on blockchain if enabled
    if (this.enableBlockchain && this.blockchain?.contract) {
      try {
        console.log(chalk.gray('  Storing credential on blockchain...'));
        console.log(chalk.gray(`  Method: SSIRegistry.storeCredential(bytes32, string, string, string)`));
        
        // Ensure issuer wallet is connected
        let issuerWallet = issuer.ethWallet;
        if (!issuerWallet || !issuerWallet.provider) {
          issuerWallet = await this.blockchain.getOrCreateWallet(issuerId);
        }
        
        // Use the proper blockchain method from blockchainConfig.js
        const result = await this.blockchain.issueCredentialOnChain(
          credential,
          issuer.did,
          subject.did,
          issuerWallet
        );
        
        if (result.success) {
          credentialRecord.blockchainTxHash = result.transactionHash;
          credentialRecord.blockchainHash = result.credentialHash;
          credentialRecord.blockNumber = result.blockNumber;
          console.log(chalk.green(`  ✅ Blockchain TX: ${result.transactionHash.substring(0, 20)}...`));
          console.log(chalk.gray(`     Block: ${result.blockNumber} | Gas: ${result.gasUsed || 'N/A'}`));
          console.log(chalk.gray(`     Credential Hash: ${result.credentialHash.substring(0, 24)}...`));
          console.log(chalk.gray(`     Issuer DID: ${issuer.did.substring(0, 36)}...`));
          console.log(chalk.gray(`     Subject DID: ${subject.did.substring(0, 36)}...`));
          
          // Add explorer link
          const explorerUrl = this.blockchain.getExplorerUrl('tx', result.transactionHash);
          if (explorerUrl) {
            console.log(chalk.gray(`     View: ${explorerUrl}`));
          }
        } else {
          console.log(chalk.yellow(`  ⚠️  Blockchain storage failed: ${result.error}`));
        }
      } catch (error) {
        console.log(chalk.yellow(`  ⚠️  Blockchain storage error: ${error.message}`));
      }
    }

    subject.credentials.push(credentialRecord);

    // Save credential to subject's (holder's) wallet
    await this.saveToWallet(
      subject.id,
      'credentials',
      credentialRecord,
      `${credentialRecord.id}.json`
    );

    // Also save a copy to the issuer's wallet so the insurer can look up
    // policies they issued (needed by loadPolicyFromInsurerWallet).
    try {
      await this.saveToWallet(
        issuerId,
        'credentials',
        { ...credentialRecord, isIssuerCopy: true, subjectDid: subject.did },
        `issued_${credentialRecord.id}.json`
      );
    } catch {
      // Non-critical — insurer wallet may not have a credentials dir yet
    }

    console.log(chalk.green('✅ Issued and saved to wallet\n'));

    return credential;
  }

  // ======================================================
  // VERIFY CREDENTIAL
  // ======================================================
  
  async verifyCredential(verifierId, credential) {
    const verifier = this.getAgent(verifierId);

    if (!verifier) {
      throw new Error('Verifier not found');
    }

    const verifierType = AGENT_TYPES[verifier.type];
    console.log(`\n${verifierType.icon} ${chalk.cyan(verifier.name)} verifying...`);

    try {
      // Verify with Veramo
      const result = await verifier.agent.verifyCredential({
        credential,
      });

      if (!result.verified) {
        console.log(chalk.red('❌ CRYPTOGRAPHIC VERIFICATION FAILED\n'));
        return false;
      }
      
      console.log(chalk.green('  ✅ Cryptographic signature valid'));

      // 🔧 FIX #2: Verify on blockchain using correct hash method
      if (this.enableBlockchain && this.blockchain?.contract) {
        try {
          const blockchainResult = await this.blockchain.verifyCredentialOnChain(credential);
          
          if (!blockchainResult.exists) {
            console.log(chalk.red('❌ CREDENTIAL NOT FOUND ON BLOCKCHAIN\n'));
            return false;
          }

          if (blockchainResult.revoked) {
            console.log(chalk.red('❌ CREDENTIAL REVOKED ON BLOCKCHAIN\n'));
            console.log(chalk.gray(`   Revoked at: ${new Date(blockchainResult.timestamp * 1000).toLocaleString()}`));
            return false;
          }

          console.log(chalk.green('  ✅ Blockchain verified'));
          console.log(chalk.gray(`     Issued: ${new Date(blockchainResult.timestamp * 1000).toLocaleString()}`));
          console.log(chalk.gray(`     Type: ${blockchainResult.credentialType}`));
          console.log(chalk.gray(`     Hash: ${blockchainResult.credentialHash.substring(0, 20)}...`));
        } catch (error) {
          console.log(chalk.yellow(`  ⚠️  Blockchain verification unavailable: ${error.message}`));
        }
      }

      console.log(chalk.green('✅ VERIFIED\n'));
      return true;
    } catch (e) {
      console.log(chalk.red('❌ ERROR:', e.message));
      return false;
    }
  }

  // ======================================================
  // REVOKE CREDENTIAL
  // ======================================================
  
  async revokeCredential(issuerId, credential) {
    const issuer = this.getAgent(issuerId);
    
    if (!issuer) {
      throw new Error('Issuer not found');
    }

    console.log(chalk.yellow(`\n🚫 ${issuer.name} revoking credential...`));

    // Revoke on blockchain if enabled
    if (this.enableBlockchain && this.blockchain?.contract) {
      try {
        // Ensure wallet is connected
        let issuerWallet = issuer.ethWallet;
        if (!issuerWallet || !issuerWallet.provider) {
          issuerWallet = await this.blockchain.getOrCreateWallet(issuerId);
        }
        
        const result = await this.blockchain.revokeCredentialOnChain(credential, issuerWallet);
        
        if (result.success) {
          console.log(chalk.green('✅ Revoked on blockchain'));
          console.log(chalk.gray(`   TX: ${result.transactionHash.substring(0, 20)}...`));
          return true;
        }
      } catch (error) {
        console.log(chalk.red(`❌ Blockchain revocation failed: ${error.message}\n`));
        return false;
      }
    }

    console.log(chalk.yellow('⚠️  Blockchain not available for revocation\n'));
    return false;
  }

  // ======================================================
  // BLOCKCHAIN OPERATIONS
  // ======================================================
  


  async getBlockchainBalance(agentId) {
    const agent = this.getAgent(agentId);
    if (!agent || !agent.ethWallet) {
      throw new Error('Agent wallet not found');
    }

    return await this.blockchain.getBalance(agent.blockchainAddress);
  }

  // ======================================================
  // ZKP: PROOF REQUESTS (Insurer -> Patient)
  // ======================================================

  async _getProofRequestDir(agentId, direction = 'incoming') {
    const walletPath = await this.getWalletPath(agentId);
    return path.join(walletPath, 'proof-requests', direction);
  }

  async _saveProofRequest(agentId, direction, requestRecord) {
    const dir = await this._getProofRequestDir(agentId, direction);
    await fs.mkdir(dir, { recursive: true });
    const filePath = path.join(dir, `${requestRecord.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(requestRecord, null, 2));
  }

  async _loadProofRequest(agentId, requestId, direction = 'incoming') {
    try {
      const dir = await this._getProofRequestDir(agentId, direction);
      const content = await fs.readFile(path.join(dir, `${requestId}.json`), 'utf-8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  async listProofRequests(agentId, direction = 'incoming') {
    try {
      const dir = await this._getProofRequestDir(agentId, direction);
      const files = await fs.readdir(dir);
      const requests = [];

      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        const content = await fs.readFile(path.join(dir, file), 'utf-8');
        requests.push(JSON.parse(content));
      }

      return requests.sort(
        (a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime()
      );
    } catch {
      return [];
    }
  }

  async requestZKProof(requesterId, holderId, proofType, requestOptions = {}) {
    const requester = this.getAgent(requesterId);
    const holder = this.getAgent(holderId);

    if (!requester || !holder) {
      throw new Error('Requester or holder agent not found');
    }

    canRequestProof(requester.type, proofType);
    const schema = CREDENTIAL_SCHEMAS[proofType];
    if (!schema) {
      throw new Error(`Unknown proof type: ${proofType}`);
    }
    const requestedFields = Array.isArray(requestOptions.requestedFields) && requestOptions.requestedFields.length > 0
      ? [...new Set(requestOptions.requestedFields)]
      : [...new Set(schema.suggestedDisclosure || [])];

    const requestRecord = {
      id: crypto.randomBytes(16).toString('hex'),
      proofType,
      status: 'pending',
      requesterId,
      requesterName: requester.name,
      requesterDid: requester.did,
      holderId,
      holderName: holder.name,
      holderDid: holder.did,
      requestedFields,
      proofSchema: {
        appliesToCredential: schema.appliesToCredential,
        proofType: schema.proofType || 'statement',
        field: schema.field || null,
        suggestedDisclosure: schema.suggestedDisclosure || [],
        typicallyHidden: schema.typicallyHidden || [],
        description: schema.description || '',
      },
      note: requestOptions.note || null,
      createdAt: new Date().toISOString(),
      fulfilledAt: null,
      fulfilledByProofId: null,
    };

    await this._saveProofRequest(holderId, 'incoming', requestRecord);
    await this._saveProofRequest(requesterId, 'outgoing', requestRecord);

    console.log(chalk.cyan(`\n📝 Proof requested: ${proofType}`));
    console.log(chalk.gray(`   Requester: ${requester.name} -> Holder: ${holder.name}`));
    console.log(chalk.gray(`   Applies to credential: ${schema.appliesToCredential}`));
    if (requestedFields.length > 0) {
      console.log(chalk.gray(`   Requested fields: ${requestedFields.join(', ')}`));
    }
    console.log(chalk.green('✅ Proof request recorded in both wallets\n'));

    return requestRecord;
  }

  // ======================================================
  // ZKP: GENERATE PROOF (Patient generates locally)
  // ======================================================
  
  /**
   * Patient generates a ZK proof from a credential in their wallet.
   * Matches sequence diagram: Step 6 - "computes and creates ZK proof locally"
   * 
   * @param {string} proverId        - Patient agent ID
   * @param {string} credentialId    - ID of the credential in patient's wallet
   * @param {string[]} disclosedFields - Fields the patient CHOOSES to reveal
   * @param {string|null} proofRequestId - Optional linked proof request
   * @param {string|null} policyCredentialId - ID of the insurer-issued policy VC in patient's wallet
   * @returns {Object} zkProof
   */
  async generateZKProof(proverId, credentialId, disclosedFields, proofRequestId = null, policyCredentialId = null) {
    if (!this.zkp) {
      throw new Error('ZKP module not initialized');
    }

    const prover = this.getAgent(proverId);
    if (!prover) {
      throw new Error('Prover agent not found');
    }
    canGenerateProof(prover.type);

    // Find the credential in the prover's wallet
    const credRecord = prover.credentials.find(c => c.id === credentialId);
    if (!credRecord) {
      throw new Error('Credential not found in wallet');
    }

    let proofRequest = null;
    if (proofRequestId) {
      proofRequest = await this._loadProofRequest(proverId, proofRequestId, 'incoming');
      if (!proofRequest) {
        throw new Error(`Proof request not found: ${proofRequestId}`);
      }
      if (proofRequest.status !== 'pending') {
        throw new Error(`Proof request is already ${proofRequest.status}`);
      }
      if (proofRequest.holderId !== proverId) {
        throw new Error('This proof request is not assigned to the selected prover');
      }

      const expectedCredentialType = proofRequest.proofSchema?.appliesToCredential;
      if (expectedCredentialType && expectedCredentialType !== credRecord.type) {
        throw new Error(
          `Requested proof requires ${expectedCredentialType} credential, but selected credential is ${credRecord.type}`
        );
      }

      const claimFields = Object.keys(credRecord.credential?.credentialSubject || {});
      const requestedFields = (proofRequest.requestedFields || []).filter(field => claimFields.includes(field));
      const missingRequested = requestedFields.filter(field => !disclosedFields.includes(field));
      if (missingRequested.length > 0) {
        throw new Error(
          `Selected fields must include requested fields: ${missingRequested.join(', ')}`
        );
      }
    }

    // ── Look up the insurer-issued policy credential (required for MedicalBill proofs) ──
    let policyCredential = null;
    let policyRecord     = null;

    if (policyCredentialId) {
      // Explicitly selected policy credential
      policyRecord = prover.credentials.find(c => c.id === policyCredentialId);
      if (!policyRecord) {
        throw new Error('Policy credential not found in wallet');
      }
      policyCredential = policyRecord.credential;
    } else if (credRecord.type === 'MedicalBill') {
      // Auto-select: pick the first InsurancePolicy credential in the wallet
      policyRecord = prover.credentials.find(c => c.type === 'InsurancePolicy');
      if (policyRecord) {
        policyCredential = policyRecord.credential;
        console.log(chalk.gray(`   Auto-selected policy VC: ${policyRecord.issuer}`));
      }
    }
    // For non-MedicalBill credentials, policyCredential stays null (not required).

    const proverType = AGENT_TYPES[prover.type];
    console.log(`\n${proverType.icon} ${chalk.green(prover.name)} generating ZK proof...`);
    console.log(chalk.gray(`   Credential: ${credRecord.type} (from ${credRecord.issuer})`));

    // Generate the proof — pass policy credential and record for multi-VC circuit
    const zkProof = await this.zkp.generateProof(
      credRecord.credential,
      credRecord,
      disclosedFields,
      prover,
      policyCredential,
      policyRecord
    );

    if (proofRequest) {
      zkProof.requestReference = {
        requestId: proofRequest.id,
        proofType: proofRequest.proofType,
        requestedByAgentId: proofRequest.requesterId,
        requestedByDid: proofRequest.requesterDid,
        requestedAt: proofRequest.createdAt,
      };

      proofRequest.status = 'fulfilled';
      proofRequest.fulfilledAt = new Date().toISOString();
      proofRequest.fulfilledByProofId = zkProof.id;

      await this._saveProofRequest(proverId, 'incoming', proofRequest);
      await this._saveProofRequest(proofRequest.requesterId, 'outgoing', proofRequest);
    }

    // Save proof to prover's wallet
    await this.zkp.saveProof(proverId, zkProof);

    // Log proof audit trail locally (not on-chain anchoring)
    // NOTE: We do NOT call issueCredential on-chain here because the smart
    // contract requires the issuer's wallet to sign — a patient cannot issue
    // for a hospital's DID. The original credential is already on-chain;
    // the verifier checks that during proof verification (step 8-9).
    await this.zkp.recordProofAuditTrail(zkProof);

    // Display the proof
    this.zkp.displayProof(zkProof);

    return zkProof;
  }

  // ======================================================
  // ZKP: SUBMIT PROOF (Patient → Insurer)
  // ======================================================

  /**
   * Patient submits a ZK proof to a verifier (insurer).
   * Matches sequence diagram: Step 7 - "sends generated ZK proof"
   */
  async submitZKProof(proverId, verifierId, proofId) {
    if (!this.zkp) {
      throw new Error('ZKP module not initialized');
    }

    const prover = this.getAgent(proverId);
    const verifier = this.getAgent(verifierId);
    
    if (!prover || !verifier) {
      throw new Error('Prover or verifier agent not found');
    }

    canGenerateProof(prover.type);
    canVerifyProof(verifier.type);

    // Load proof from prover's wallet
    const zkProof = await this.zkp.loadProof(proverId, proofId);
    if (!zkProof) {
      throw new Error('Proof not found in wallet');
    }

    if (zkProof.generatedBy && zkProof.generatedBy !== prover.did) {
      throw new Error('Proof ownership mismatch: selected prover did not generate this proof');
    }

    if (zkProof.requestReference?.proofType) {
      canRequestProof(verifier.type, zkProof.requestReference.proofType);
      if (
        zkProof.requestReference.requestedByAgentId &&
        zkProof.requestReference.requestedByAgentId !== verifierId
      ) {
        throw new Error('This proof was requested by a different verifier');
      }

      const proofCredentialType = zkProof.publicInputs?.credentialType;
      if (
        proofCredentialType
        && zkProof.requestReference.proofSchema && zkProof.requestReference.proofSchema.appliesToCredential        && proofCredentialType !== zkProof.requestReference.proofSchema.appliesToCredential
      ) {
        throw new Error(
          `Proof type ${zkProof.requestReference.proofType} requires ${requestSchema.appliesToCredential}, got ${proofCredentialType}`
        );
      }
    }

    const proverType = AGENT_TYPES[prover.type];
    const verifierType = AGENT_TYPES[verifier.type];
    
    console.log(`\n${proverType.icon} ${chalk.green(prover.name)} → ${verifierType.icon} ${chalk.blue(verifier.name)}`);
    console.log(chalk.yellow('Submitting ZK Proof...'));

    // Save proof to verifier's wallet (received proofs directory)
    const receivedDir = `./data/wallets/${verifierId}/received-proofs`;
    await fs.mkdir(receivedDir, { recursive: true });
    
    const submission = {
      ...zkProof,
      submittedBy: proverId,
      submittedByDid: prover.did,
      submittedAt: new Date().toISOString(),
      proofRequest: zkProof.requestReference || null,
    };
    
    await fs.writeFile(
      path.join(receivedDir, `${zkProof.id}.json`),
      JSON.stringify(submission, null, 2)
    );

    console.log(chalk.green('✅ Proof submitted successfully\n'));
    return submission;
  }

  // ======================================================
  // ZKP: VERIFY PROOF (Insurer verifies)
  // ======================================================

  /**
   * Verifier (insurer) verifies a received ZK proof.
   * Matches sequence diagram: Steps 8-9
   *   Step 8: "Verify Hospital ID" on blockchain
   *   Step 9: "verifies mathematical proof locally"
   */
  async verifyZKProof(verifierId, proofId) {
    if (!this.zkp) {
      throw new Error('ZKP module not initialized');
    }

    const verifier = this.getAgent(verifierId);
    if (!verifier) {
      throw new Error('Verifier agent not found');
    }
    canVerifyProof(verifier.type);

    // Load proof from verifier's received-proofs directory
    const receivedDir = `./data/wallets/${verifierId}/received-proofs`;
    let zkProof;
    
    try {
      const content = await fs.readFile(path.join(receivedDir, `${proofId}.json`), 'utf-8');
      zkProof = JSON.parse(content);
    } catch {
      // Also check prover's wallet (for direct verification flow)
      zkProof = await this.zkp.loadProof(verifierId, proofId);
    }

    if (!zkProof) {
      throw new Error('Proof not found');
    }

    if (zkProof.requestReference?.proofType) {
      canRequestProof(verifier.type, zkProof.requestReference.proofType);
      if (
        zkProof.requestReference.requestedByAgentId &&
        zkProof.requestReference.requestedByAgentId !== verifierId
      ) {
        throw new Error('This proof was requested by a different verifier');
      }
    }

    const verifierType = AGENT_TYPES[verifier.type];
    console.log(`\n${verifierType.icon} ${chalk.blue(verifier.name)} verifying ZK proof...`);

    // Run full verification (includes blockchain DID check)
    const result = await this.zkp.verifyProof(
      zkProof,
      verifier,
      this.enableBlockchain ? this.blockchain : null
    );

    // Update the proof with verification result
    zkProof.verified = result.valid;
    zkProof.verifiedBy = verifier.did;
    zkProof.verifiedByName = verifier.name;
    zkProof.verifiedAt = result.verifiedAt;

    // Save updated proof to verifier's received-proofs
    try {
      await fs.writeFile(
        path.join(receivedDir, `${proofId}.json`),
        JSON.stringify(zkProof, null, 2)
      );
    } catch {
      // Not critical
    }

    // Also update the proof in the PATIENT's wallet so their status refreshes
    if (zkProof.submittedBy) {
      try {
        const proverProofPath = `./data/wallets/${zkProof.submittedBy}/proofs/${proofId}.json`;
        const proverContent = await fs.readFile(proverProofPath, 'utf-8');
        const proverProof = JSON.parse(proverContent);
        
        proverProof.verified = result.valid;
        proverProof.verifiedBy = verifier.did;
        proverProof.verifiedByName = verifier.name;
        proverProof.verifiedAt = result.verifiedAt;
        
        await fs.writeFile(proverProofPath, JSON.stringify(proverProof, null, 2));
        console.log(chalk.gray(`   📋 Patient proof status updated`));
      } catch {
        // Patient proof file might not exist at that path — not critical
      }
    } else {
      // Fallback: try to find the prover by scanning the proof's generatedBy DID
      try {
        const agents = this.listAgents();
        const prover = agents.find(a => a.did === zkProof.generatedBy);
        if (prover) {
          const proverProofPath = `./data/wallets/${prover.id}/proofs/${proofId}.json`;
          const proverContent = await fs.readFile(proverProofPath, 'utf-8');
          const proverProof = JSON.parse(proverContent);
          
          proverProof.verified = result.valid;
          proverProof.verifiedBy = verifier.did;
          proverProof.verifiedByName = verifier.name;
          proverProof.verifiedAt = result.verifiedAt;
          
          await fs.writeFile(proverProofPath, JSON.stringify(proverProof, null, 2));
          console.log(chalk.gray(`   📋 Patient proof status updated`));
        }
      } catch {
        // Not critical
      }
    }

    // Display result
    this.zkp.displayVerificationResult(result);

    return result;
  }

  // ======================================================
  // ZKP: LIST PROOFS FOR AGENT
  // ======================================================

  async listZKProofs(agentId) {
    if (!this.zkp) return [];
    return await this.zkp.listProofs(agentId);
  }

  // ======================================================
  // ZKP: LIST RECEIVED PROOFS (for verifier)
  // ======================================================

  async listReceivedProofs(agentId) {
    const receivedDir = `./data/wallets/${agentId}/received-proofs`;
    try {
      const files = await fs.readdir(receivedDir);
      const proofs = [];
      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(receivedDir, file), 'utf-8');
          proofs.push(JSON.parse(content));
        }
      }
      return proofs;
    } catch {
      return [];
    }
  }

  // ======================================================
  // HELPER METHODS
  // ======================================================
  
  generateAgentId(name) {
    return name.toLowerCase().replace(/[^a-z0-9]/g, '-');
  }

  getAgent(id) {
    return this.agents.get(id);
  }

  listAgents() {
    return Array.from(this.agents.values()).map(agent => ({
      id: agent.id,
      name: agent.name,
      type: agent.type,
      did: agent.did,
      blockchainAddress: agent.blockchainAddress,
      connections: agent.connections,
      credentials: agent.credentials,
      metadata: agent.metadata
    }));
  }

  // ======================================================
  // EXPORT AGENT DATA
  // ======================================================
  
  async exportAgentWallet(agentId) {
    const agent = this.getAgent(agentId);
    if (!agent) throw new Error('Agent not found');

    const exportData = {
      agent: {
        id: agent.id,
        name: agent.name,
        type: agent.type,
        did: agent.did,
        blockchainAddress: agent.blockchainAddress,
        metadata: agent.metadata
      },
      connections: await this.listWalletItems(agentId, 'connections'),
      credentials: await this.listWalletItems(agentId, 'credentials'),
      exportedAt: new Date().toISOString()
    };

    return exportData;
  }

  // ======================================================
  // GET STATISTICS
  // ======================================================
  
  getStatistics() {
    const agents = this.listAgents();
    const totalConnections = agents.reduce((sum, a) => sum + a.connections.length, 0);
    const totalCredentials = agents.reduce((sum, a) => sum + a.credentials.length, 0);

    const typeCount = {};
    agents.forEach(a => {
      typeCount[a.type] = (typeCount[a.type] || 0) + 1;
    });

    return {
      totalAgents: agents.length,
      totalConnections: totalConnections / 2,
      totalCredentials,
      agentsByType: typeCount,
      blockchainNetwork: this.network
    };
  }

  // ======================================================
  // CLEAN ALL DATA
  // ======================================================
  
  async cleanAll() {
    const agents = this.listAgents();
    for (const agent of agents) {
      await this.deleteAgent(agent.id);
    }
    this.agents.clear();
  }
}
