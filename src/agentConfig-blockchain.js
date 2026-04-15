import { createAgent } from '@veramo/core';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { DataStore, DataStoreORM, DIDStore, Entities, KeyStore, PrivateKeyStore } from '@veramo/data-store';
import { DIDManager } from '@veramo/did-manager';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyManager } from '@veramo/key-manager';
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local';
import crypto from 'crypto';
import { Resolver } from 'did-resolver';
import { ethers } from 'ethers';
import { getResolver as ethrDidResolver } from 'ethr-did-resolver';
import fs from 'fs/promises';
import { getResolver as keyDidResolver } from 'key-did-resolver';
import path from 'path';
import { DataSource } from 'typeorm';
import { getResolver as webDidResolver } from 'web-did-resolver';

// Generate or load master encryption key
async function getMasterKey() {
  const keyPath = './data/.master.key';
  
  try {
    const key = await fs.readFile(keyPath, 'utf-8');
    return key.trim();
  } catch {
    // Generate new master key
    const newKey = crypto.randomBytes(32).toString('hex');
    await fs.mkdir('./data', { recursive: true });
    await fs.writeFile(keyPath, newKey, { mode: 0o600 });
    return newKey;
  }
}

// Create wallet directory structure
async function ensureWalletStructure(agentId) {
  const walletPath = `./data/wallets/${agentId}`;
  await fs.mkdir(`${walletPath}/credentials`, { recursive: true });
  await fs.mkdir(`${walletPath}/connections`, { recursive: true });
  await fs.mkdir(`${walletPath}/keys`, { recursive: true });
  return walletPath;
}

// Create Ethereum wallet for blockchain operations
export async function createEthereumWallet(agentId) {
  const walletPath = `./data/wallets/${agentId}/keys`;
  const walletFile = path.join(walletPath, 'ethereum-wallet.json');
  
  try {
    // Try to load existing wallet
    const walletData = await fs.readFile(walletFile, 'utf-8');
    const parsed = JSON.parse(walletData);
    return new ethers.Wallet(parsed.privateKey);
  } catch {
    // Create new wallet
    const wallet = ethers.Wallet.createRandom();
    await fs.mkdir(walletPath, { recursive: true });
    await fs.writeFile(walletFile, JSON.stringify({
      address: wallet.address,
      privateKey: wallet.privateKey,
      mnemonic: wallet.mnemonic?.phrase || null,
      createdAt: new Date().toISOString()
    }, null, 2), { mode: 0o600 });
    
    return wallet;
  }
}

// Create database connection for an agent
export async function createAgentDatabase(agentId) {
  const walletPath = await ensureWalletStructure(agentId);
  
  const dbConnection = new DataSource({
    type: 'sqlite',
    database: `${walletPath}/agent.db`,
    synchronize: true,
    logging: false,
    entities: Entities,
  });

  await dbConnection.initialize();
  return dbConnection;
}

// Create a Veramo agent with enhanced security
export async function createVeramoAgent(agentId, dbConnection) {
  const masterKey = await getMasterKey();
  
  const agent = createAgent({
    plugins: [
      new KeyManager({
        store: new KeyStore(dbConnection),
        kms: {
          local: new KeyManagementSystem(
            new PrivateKeyStore(dbConnection, new SecretBox(masterKey))
          ),
        },
      }),
      new DIDManager({
        store: new DIDStore(dbConnection),
        defaultProvider: 'did:key',
        providers: {
          'did:key': new KeyDIDProvider({
            defaultKms: 'local',
          }),
        },
      }),
      new DIDResolverPlugin({
        resolver: new Resolver({
          ...keyDidResolver(),
          ...ethrDidResolver({ infuraProjectId: 'mock' }),
          ...webDidResolver(),
        }),
      }),
      new CredentialPlugin(),
      new DataStore(dbConnection),
      new DataStoreORM(dbConnection),
    ],
  });

  return agent;
}

// ======================================================
// CREDENTIAL SCHEMA DEFINITIONS
// ======================================================

export const CREDENTIAL_SCHEMAS = {

  // ── MEDICAL BILL (only hospitals can issue) ────────────────────────────────
  MedicalBill: {
    type: 'MedicalBill',
    issuerRestriction: ['hospital'],
    required: ['billNumber', 'patientName', 'diagnosis', 'treatment', 'amount', 'date'],
    properties: {
      billNumber:  { type: 'string',   description: 'Unique bill identifier' },
      patientName: { type: 'string',   description: 'Patient full name' },
      age:         { type: 'integer',  description: 'Patient age at time of service' },
      diagnosis:   { type: 'string',   description: 'Medical diagnosis' },
      treatment:   { type: 'string',   description: 'Treatment provided' },
      amount:      { type: 'string',   description: 'Total bill amount (e.g. "$2500.00")' },
      // 'date' is the canonical service date field the schema requires.
      // index.js also sends 'serviceDate' (same value) for ZKP predicate naming.
      date:        { type: 'string',   format: 'date',      description: 'Date of service (YYYY-MM-DD)' },
      serviceDate: { type: 'string',   format: 'date',      description: 'Date of service (alias for ZKP use)' },
      issuedDate:  { type: 'string',   format: 'date-time', description: 'Bill issue timestamp' },
    },
  },

  // ── INSURANCE POLICY (only insurers can issue) ─────────────────────────────
  InsurancePolicy: {
    type: 'InsurancePolicy',
    issuerRestriction: ['insurer'],
    required: ['policyNumber', 'policyHolder', 'planName', 'coverageAmount', 'coveragePercent', 'validUntil'],
    properties: {
      policyNumber:     { type: 'string', description: 'Unique policy identifier' },
      policyHolder:     { type: 'string', description: 'Name of the insured person' },
      planName:         { type: 'string', description: 'Insurance plan name' },
      coverageAmount:   { type: 'string', description: 'Maximum coverage amount (e.g. "$50000.00")' },
      coveragePercent:  { type: 'string', description: 'Coverage percentage (e.g. "80%")' },
      coveredDiagnoses: { type: 'string', description: 'Comma-separated covered conditions, or "ALL"' },
      deductible:       { type: 'string', description: 'Annual deductible (e.g. "$500.00")' },
      validUntil:       { type: 'string', format: 'date', description: 'Policy expiry date (YYYY-MM-DD)' },
      status:           { type: 'string', description: 'Policy status (e.g. "Active")' },
      issuedDate:       { type: 'string', format: 'date-time', description: 'Policy issue timestamp' },
    },
  },

  // ── INSURANCE PAYMENT RECORD (only insurers can issue) ────────────────────
  InsurancePayment: {
    type: 'InsurancePayment',
    issuerRestriction: ['insurer'],
    required: ['claimNumber', 'originalBillNumber', 'approvedAmount', 'coverage', 'patientName', 'paymentDate', 'status'],
    properties: {
      claimNumber:        { type: 'string', description: 'Insurance claim number' },
      originalBillNumber: { type: 'string', description: 'Reference to original bill' },
      approvedAmount:     { type: 'string', description: 'Approved payment amount' },
      coverage:           { type: 'string', description: 'Coverage percentage applied' },
      patientName:        { type: 'string', description: 'Patient name' },
      paymentDate:        { type: 'string', format: 'date-time', description: 'Payment date' },
      status:             { type: 'string', description: 'Payment status (Approved / Denied / Pending)' },
    },
  },
};

// ======================================================
// AGENT TYPE CONFIGURATIONS
// ======================================================

export const AGENT_TYPES = {
  hospital: {
    label: 'Hospital',
    color: 'cyan',
    icon: '🏥',
    canIssue: ['MedicalBill'],
    canGenerateProofs: false,
    canVerifyProofs:   false,
    description: 'Healthcare provider — issues medical bills',
  },

  patient: {
    label: 'Patient',
    color: 'green',
    icon: '👤',
    canIssue: [],               // patients cannot issue credentials
    canGenerateProofs: true,    // patients generate ZK proofs from their credentials
    canVerifyProofs:   false,
    description: 'Individual receiving healthcare — holds credentials, generates ZK proofs',
  },

  insurer: {
    label: 'Insurance Company',
    color: 'blue',
    icon: '🏢',
    canIssue: ['InsurancePolicy', 'InsurancePayment'],
    canGenerateProofs: false,
    canVerifyProofs:   true,    // insurers verify ZK proofs
    canRequestProofs:  true,    // insurers can request proofs from patients
    description: 'Insurance provider — issues policies, verifies ZK proofs, approves reimbursements',
  },
};

// ======================================================
// PERMISSION HELPERS
// ======================================================

/**
 * Check whether an agent type is allowed to issue a credential type.
 * Throws a descriptive error if not permitted.
 */
export function canIssueCredential(agentType, credentialType) {
  const schema = CREDENTIAL_SCHEMAS[credentialType];

  if (!schema) {
    throw new Error(`Unknown credential type: ${credentialType}`);
  }

  if (!schema.issuerRestriction) {
    return true; // No restriction defined — allow
  }

  if (!schema.issuerRestriction.includes(agentType)) {
    const allowed = schema.issuerRestriction
      .map(t => AGENT_TYPES[t]?.label || t)
      .join(', ');
    throw new Error(
      `❌ PERMISSION DENIED: Only ${allowed} can issue ${credentialType} credentials. ` +
      `${AGENT_TYPES[agentType]?.label || agentType} cannot issue this type.`
    );
  }

  return true;
}

/**
 * Check whether an agent type can generate ZK proofs.
 * @param {string} agentType      - e.g. 'patient', 'hospital', 'insurer'
 * @param {string} [credentialType] - Optional credential type to validate exists
 */
export function canGenerateProof(agentType, credentialType) {
  const config = AGENT_TYPES[agentType];
  if (!config) throw new Error(`Unknown agent type: ${agentType}`);

  if (!config.canGenerateProofs) {
    throw new Error(
      `❌ PERMISSION DENIED: ${config.label} cannot generate ZK proofs. ` +
      `Only Patients can generate proofs from their credentials.`
    );
  }

  if (credentialType && !CREDENTIAL_SCHEMAS[credentialType]) {
    throw new Error(`Unknown credential type: ${credentialType}`);
  }

  return true;
}

/**
 * Check whether an agent type can verify ZK proofs.
 * @param {string} agentType    - e.g. 'patient', 'hospital', 'insurer'
 * @param {string} [proofType]  - Optional proof type to validate exists
 */
export function canVerifyProof(agentType, proofType) {
  const config = AGENT_TYPES[agentType];
  if (!config) throw new Error(`Unknown agent type: ${agentType}`);

  if (!config.canVerifyProofs) {
    throw new Error(
      `❌ PERMISSION DENIED: ${config.label} cannot verify ZK proofs. ` +
      `Only Insurance Companies can verify proofs.`
    );
  }

  if (proofType && !CREDENTIAL_SCHEMAS[proofType]) {
    throw new Error(`Unknown proof type: ${proofType}`);
  }

  return true;
}

/**
 * Check whether an agent type can request ZK proofs.
 * @param {string} agentType    - e.g. 'patient', 'hospital', 'insurer'
 * @param {string} [proofType]  - Optional proof type to validate exists in schemas
 */
export function canRequestProof(agentType, proofType) {
  const config = AGENT_TYPES[agentType];
  if (!config) throw new Error(`Unknown agent type: ${agentType}`);

  if (!config.canRequestProofs) {
    throw new Error(
      `❌ PERMISSION DENIED: ${config.label} cannot request ZK proofs. ` +
      `Only Insurance Companies can request proofs.`
    );
  }

  if (proofType && !CREDENTIAL_SCHEMAS[proofType]) {
    throw new Error(`Unknown proof type: ${proofType}`);
  }

  return true;
}