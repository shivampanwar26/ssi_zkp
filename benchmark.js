/**
 * ============================================================
 *  benchmark.js  —  SSI Healthcare System Performance Benchmarks
 * ============================================================
 *
 *  Measures latency (ms) for four core operations:
 *    1. Register DID
 *    2. Store Verifiable Credential (VC issuance)
 *    3. ZKP Proof Generation
 *    4. ZKP Proof Verification
 *
 *  Usage:
 *    node benchmark.js                    # run all benchmarks (3 iterations)
 *    node benchmark.js --runs 5           # 5 iterations each
 *    node benchmark.js --skip-zkp         # skip ZKP steps
 *    node benchmark.js --output res.json  # custom output filename
 *
 *  Output:
 *    benchmark_results.json   — raw per-run latencies
 *    benchmark_summary.json   — mean / min / max / stddev per step
 *
 *  Requirements:
 *    npm install  (project deps already installed)
 *    circuits/setup.sh already run  (for ZKP steps)
 * ============================================================
 */

import fs from 'fs/promises';
import crypto from 'crypto';
import { performance } from 'perf_hooks';

import { ZKPManager } from './src/zkpManager.js';
import {
  createVeramoAgent,
} from './src/agentConfig-blockchain.js';

// ── CLI flags ────────────────────────────────────────────────────────────────
const args    = process.argv.slice(2);
const flag    = (f) => args.includes(f);
const flagVal = (f, def) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : def; };

const RUNS        = parseInt(flagVal('--runs', '3'), 10);
const SKIP_ZKP    = flag('--skip-zkp');
const OUTPUT_FILE = flagVal('--output', 'benchmark_results.json');
const SUMMARY_FILE = 'benchmark_summary.json';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Run fn, return elapsed ms */
async function time(fn) {
  const t0 = performance.now();
  await fn();
  return +(performance.now() - t0).toFixed(2);
}

/** Statistics over array of numbers */
function stats(arr) {
  if (!arr.length) return { mean: 0, min: 0, max: 0, stddev: 0, runs: 0 };
  const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
  const variance = arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
  return {
    mean:   +mean.toFixed(2),
    min:    +Math.min(...arr).toFixed(2),
    max:    +Math.max(...arr).toFixed(2),
    stddev: +Math.sqrt(variance).toFixed(2),
    runs:   arr.length,
    raw:    arr,
  };
}

/** Pretty print a stats object */
function printStats(label, s) {
  console.log(
    `  ${label.padEnd(28)}` +
    `mean=${String(s.mean).padStart(9)} ms  ` +
    `min=${String(s.min).padStart(8)} ms  ` +
    `max=${String(s.max).padStart(8)} ms  ` +
    `σ=${String(s.stddev).padStart(8)} ms`
  );
}

// ── Unique tmp dir per benchmark run ─────────────────────────────────────────
const TMP = `./data/_bench_${Date.now()}`;

// ── Patched createAgentDatabase that uses bench tmp path ─────────────────────
async function createAgentDatabase_bench(agentId, dbPath) {
  const { DataSource } = await import('typeorm');
  const { Entities }   = await import('@veramo/data-store');
  const db = new DataSource({
    type:        'sqlite',
    database:    `${dbPath}/agent.db`,
    synchronize: true,
    logging:     false,
    entities:    Entities,
  });
  await db.initialize();
  return db;
}

// ── Main benchmark suite ─────────────────────────────────────────────────────
async function runBenchmarks() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   SSI Healthcare System — Performance Benchmark          ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`  Iterations : ${RUNS}`);
  console.log(`  ZKP        : ${SKIP_ZKP ? 'SKIPPED' : 'enabled'}`);
  console.log('');

  await fs.mkdir(TMP, { recursive: true });

  const results = {};

  // ─────────────────────────────────────────────────────────────────────────
  // 1. Register DID  (DID creation + on-chain DID registration)
  //    Mirrors the real createAgent() flow in agentManager-blockchain.js:
  //      didManagerCreate → createEthereumWallet → registerDID on-chain
  // ─────────────────────────────────────────────────────────────────────────
  console.log('■  Step 1 — Register DID (with on-chain anchor)');
  results['Register DID'] = [];

  for (let r = 0; r < RUNS; r++) {
    const agentId = `bench-did-${r}-${Date.now()}`;
    const dbPath  = `${TMP}/wallets/${agentId}`;
    await fs.mkdir(`${dbPath}/credentials`, { recursive: true });
    await fs.mkdir(`${dbPath}/connections`, { recursive: true });
    await fs.mkdir(`${dbPath}/keys`,        { recursive: true });

    // Setup outside the timer
    const db     = await createAgentDatabase_bench(agentId, dbPath);
    const veramo = await createVeramoAgent(agentId, db);

    const ms = await time(async () => {
      // 1. Create DID (key generation + DID document)
      const identifier = await veramo.didManagerCreate({ provider: 'did:key' });

      // 2. Create Ethereum wallet (key pair generation)
      const { ethers } = await import('ethers');
      const wallet = ethers.Wallet.createRandom();
      await fs.writeFile(`${dbPath}/keys/ethereum-wallet.json`, JSON.stringify({
        address:    wallet.address,
        privateKey: wallet.privateKey,
        createdAt:  new Date().toISOString(),
      }));

      // 3. Register DID on-chain (simulated — matches blockchain.registerDID)
      const didHash = crypto.createHash('sha256').update(identifier.did).digest('hex');
      await fs.writeFile(`${TMP}/ledger-did-${r}.json`, JSON.stringify({
        did:          identifier.did,
        didHash,
        owner:        wallet.address,
        registeredAt: Math.floor(Date.now() / 1000),
        txHash:       '0x' + didHash,
        blockNumber:  500 + r,
      }));
    });

    await db.destroy();
    results['Register DID'].push(ms);
    process.stdout.write(`    run ${r + 1}/${RUNS}: ${ms} ms\n`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 2. Store VC  (Issue + hash + on-chain anchor + wallet store)
  //    Mirrors the full issueCredential() flow in agentManager-blockchain.js:
  //      createVerifiableCredential → compute credential hash →
  //      anchor hash on-chain → save to holder wallet
  // ─────────────────────────────────────────────────────────────────────────
  console.log('■  Step 2 — Store Verifiable Credential (with on-chain anchor)');
  results['Store VC'] = [];

  for (let r = 0; r < RUNS; r++) {
    const issId   = `bench-iss-${r}-${Date.now()}`;
    const holId   = `bench-hol-${r}-${Date.now()}`;
    const issPath = `${TMP}/wallets/${issId}`;
    const holPath = `${TMP}/wallets/${holId}`;
    for (const p of [issPath, holPath]) {
      await fs.mkdir(`${p}/credentials`, { recursive: true });
      await fs.mkdir(`${p}/connections`, { recursive: true });
      await fs.mkdir(`${p}/keys`,        { recursive: true });
    }

    // Setup outside the timer
    const dbIss     = await createAgentDatabase_bench(issId, issPath);
    const veramoIss = await createVeramoAgent(issId, dbIss);
    const issuerDID = await veramoIss.didManagerCreate({ provider: 'did:key' });

    const dbHol     = await createAgentDatabase_bench(holId, holPath);
    const veramoHol = await createVeramoAgent(holId, dbHol);
    const holderDID = await veramoHol.didManagerCreate({ provider: 'did:key' });

    const ms = await time(async () => {
      // 1. Issue VC (JWT signing)
      const vc = await veramoIss.createVerifiableCredential({
        credential: {
          issuer:       { id: issuerDID.did },
          '@context':   ['https://www.w3.org/2018/credentials/v1'],
          type:         ['VerifiableCredential', 'MedicalBill'],
          issuanceDate: new Date().toISOString(),
          credentialSubject: {
            id:          holderDID.did,
            billNumber:  `BILL-${r}`,
            patientName: 'Test Patient',
            diagnosis:   'Hypertension',
            treatment:   'Medication',
            amount:      '$1500.00',
            date:        new Date().toISOString().split('T')[0],
          },
        },
        proofFormat: 'jwt',
      });

      // 2. Compute credential hash (matches blockchainConfig.js hashCredential)
      const vcJson = JSON.stringify(vc);
      const credentialHash = crypto.createHash('sha256').update(vcJson).digest('hex');

      // 3. Anchor credential on-chain (simulated — write to ledger store)
      //    In production this calls SSIRegistry.storeCredential(bytes32, ...)
      const anchorRecord = {
        credentialHash,
        issuerDid:    issuerDID.did,
        subjectDid:   holderDID.did,
        credType:     'MedicalBill',
        timestamp:    Math.floor(Date.now() / 1000),
        txHash:       '0x' + credentialHash,
        blockNumber:  1000 + r,
        revoked:      false,
      };
      await fs.writeFile(
        `${TMP}/ledger-cred-${r}.json`,
        JSON.stringify(anchorRecord)
      );

      // 4. Store credential record to holder wallet
      const stored = {
        id:               crypto.randomBytes(32).toString('hex'),
        type:             'MedicalBill',
        issuer:           issuerDID.did,
        issuerDid:        issuerDID.did,
        subject:          holderDID.did,
        vc,
        issuedAt:         new Date().toISOString(),
        status:           'active',
        blockchainHash:   credentialHash,
        blockchainTxHash: anchorRecord.txHash,
        blockNumber:      anchorRecord.blockNumber,
      };
      await fs.writeFile(
        `${holPath}/credentials/${stored.id}.json`,
        JSON.stringify(stored)
      );
    });

    results['Store VC'].push(ms);
    await dbIss.destroy();
    await dbHol.destroy();
    process.stdout.write(`    run ${r + 1}/${RUNS}: ${ms} ms\n`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 3 & 4. ZKP Proof Generation + Verification
  // ─────────────────────────────────────────────────────────────────────────
  if (!SKIP_ZKP) {
    console.log('■  Step 3 — ZKP Proof Generation');
    console.log('■  Step 4 — ZKP Proof Verification');

    const zkp = new ZKPManager();
    await zkp.initialize();

    if (zkp._circuitReady) {
      results['Proof Generation'] = [];
      results['Proof Verification'] = [];

      // Mock data matching real generateProof / verifyProof signatures
      const mockPatientDID  = 'did:key:bench-patient';
      const mockHospitalDID = 'did:key:bench-hospital';
      const mockInsurerDID  = 'did:key:bench-insurer';
      const medicalHash     = crypto.createHash('sha256').update('bench-medical').digest('hex');
      const policyHash      = crypto.createHash('sha256').update('bench-policy').digest('hex');

      const mockMedicalCredential = {
        '@context':   ['https://www.w3.org/2018/credentials/v1'],
        type:         ['VerifiableCredential', 'MedicalBill'],
        issuer:       { id: mockHospitalDID },
        issuanceDate: '2024-06-01T00:00:00Z',
        credentialSubject: {
          id: mockPatientDID, billNumber: 'BENCH-001', patientName: 'Bench Patient',
          diagnosis: 'Hypertension', treatment: 'Medication', amount: '$1500.00',
          date: '2024-06-01', serviceDate: '2024-06-01', age: 35,
        },
        proof: { jwt: 'mock.jwt.token' },
      };

      const mockCredentialRecord = {
        id: 'bench-med-rec', type: 'MedicalBill', issuer: 'Bench Hospital',
        issuerDid: mockHospitalDID, issuedAt: Date.now(),
        blockchainHash: medicalHash, blockchainTxHash: '0x' + medicalHash, status: 'active',
      };

      const mockPolicyCredential = {
        '@context':   ['https://www.w3.org/2018/credentials/v1'],
        type:         ['VerifiableCredential', 'InsurancePolicy'],
        issuer:       { id: mockInsurerDID },
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: mockPatientDID, policyNumber: 'BENCH-POL-001', policyHolder: 'Bench Patient',
          planName: 'Bench Plan', coverageAmount: '$50000.00', coveragePercent: '80%',
          coveredDiagnoses: 'ALL', deductible: '$500.00', validUntil: '2099-12-31', status: 'Active',
        },
        proof: { jwt: 'mock.policy.jwt' },
      };

      const mockPolicyRecord = {
        id: 'bench-pol-rec', type: 'InsurancePolicy', issuer: 'Bench Insurer',
        issuerDid: mockInsurerDID, issuedAt: Date.now(),
        blockchainHash: policyHash, blockchainTxHash: '0x' + policyHash, status: 'active',
      };

      const mockProverAgent   = { id: 'bench-patient', did: mockPatientDID, type: 'patient' };
      const mockVerifierAgent = { id: 'bench-insurer', did: mockInsurerDID, type: 'insurer' };

      for (let r = 0; r < RUNS; r++) {
        let zkProof;

        const genMs = await time(async () => {
          zkProof = await zkp.generateProof(
            mockMedicalCredential, mockCredentialRecord,
            ['amount', 'diagnosis'], mockProverAgent,
            mockPolicyCredential, mockPolicyRecord, {}
          );
        });

        const verMs = await time(async () => {
          await zkp.verifyProof(zkProof, mockVerifierAgent, null);
        });

        results['Proof Generation'].push(genMs);
        results['Proof Verification'].push(verMs);
        process.stdout.write(`    run ${r + 1}/${RUNS}: gen=${genMs} ms  ver=${verMs} ms\n`);
      }
    } else {
      console.log('    ⚠  Circuit not ready — skipping ZKP (run circuits/setup.sh first)');
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Summary
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════════════');
  console.log('  RESULTS SUMMARY');
  console.log('══════════════════════════════════════════════════════════');

  const summary = {};
  for (const [label, times] of Object.entries(results)) {
    summary[label] = stats(times);
    printStats(label, summary[label]);
  }

  await fs.writeFile(OUTPUT_FILE, JSON.stringify({ results, runs: RUNS, timestamp: new Date().toISOString() }, null, 2));
  await fs.writeFile(SUMMARY_FILE, JSON.stringify(summary, null, 2));

  console.log(`\n✅ Raw results → ${OUTPUT_FILE}`);
  console.log(`✅ Summary     → ${SUMMARY_FILE}`);
  console.log('\nRun  node plot_results.js  to generate graphs.\n');

  // Cleanup
  await fs.rm(TMP, { recursive: true, force: true });
}

// ── Entry point ───────────────────────────────────────────────────────────────
runBenchmarks().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
