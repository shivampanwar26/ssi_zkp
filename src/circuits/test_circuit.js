/**
 * test_circuit.js — Smoke test for the MedicalCredential circuit
 *
 * Usage (called automatically by setup.sh):
 *   node test_circuit.js <wasm> <zkey> <vk.json>
 *
 * Tests the 8 public outputs:
 *   [0] credentialHash     — non-zero Poseidon hash
 *   [1] issuerDIDHash      — non-zero Poseidon hash
 *   [2] subjectDIDHash     — non-zero Poseidon hash
 *   [3] amountInRange      — boolean (0 or 1)
 *   [4] diagnosisHash      — non-zero Poseidon hash
 *   [5] policyValid        — boolean (0 or 1)
 *   [6] coverageSufficient — boolean (0 or 1)
 *   [7] ageEligible        — boolean (0 or 1)
 */

import { existsSync, readFileSync } from 'fs';
import { fileURLToPath }            from 'url';
import path                         from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ── Locate snarkjs in node_modules up to 4 levels up ─────────────────────────
const nmCandidates = [
  path.join(__dirname, 'node_modules'),
  path.join(__dirname, '..', 'node_modules'),
  path.join(__dirname, '..', '..', 'node_modules'),
  path.join(__dirname, '..', '..', '..', 'node_modules'),
];

let snarkjsPath;
for (const nm of nmCandidates) {
  const p = path.join(nm, 'snarkjs', 'main.js');
  if (existsSync(p)) { snarkjsPath = p; break; }
}

if (!snarkjsPath) {
  console.error('❌ Cannot find snarkjs. Run setup.sh first, or: npm install snarkjs');
  process.exit(1);
}

const snarkjs = await import(snarkjsPath);

// ── CLI args ──────────────────────────────────────────────────────────────────
const wasmFile = process.argv[2] || path.join(__dirname, 'build', 'medical_credential_js', 'medical_credential.wasm');
const zkeyFile = process.argv[3] || path.join(__dirname, 'build', 'proving.zkey');
const vkFile   = process.argv[4] || path.join(__dirname, 'build', 'vk.json');

const vk = JSON.parse(readFileSync(vkFile, 'utf8'));

// ── Public signal indices ─────────────────────────────────────────────────────
// In circom 2, outputs are listed first (in declaration order),
// then public inputs (none here — all inputs are private).
const SIG = {
  credentialHash:    0,
  issuerDIDHash:     1,
  subjectDIDHash:    2,
  amountInRange:     3,
  diagnosisHash:     4,
  policyValid:       5,
  coverageSufficient:6,
  ageEligible:       7,
};

// ── Base valid input ──────────────────────────────────────────────────────────
const NOW    = Math.floor(Date.now() / 1000);
const EXPIRY = NOW + 86400;  // 1 day from now

// All field values must fit within BN128 scalar field (~254 bits).
// Credential fields are 240-bit integers; amounts/timestamps are small ints.
const SALT = '98765432109876543210';

const base = {
  billAmount:          '250000',          // $2,500.00 in cents
  coverageAmount:      '5000000',         // $50,000.00 in cents
  policyExpiry:        String(EXPIRY),
  currentTimestamp:    String(NOW),
  patientAge:          '35',
  ageMin:              '0',
  ageMax:              '59',
  diagnosisPreimage:   '12345678901234567890',
  salt:                SALT,
  credentialFields:    ['1','2','3','4','5','6','7','8','9','10'],
  issuerDIDPreimage:   '11111111111111111111',
  subjectDIDPreimage:  '22222222222222222222',
  billAmountMin:       '0',
  billAmountMax:       '10000000',        // $100,000.00 in cents
  proofNonce:          SALT,              // MUST equal salt
};

// ── Test runner ───────────────────────────────────────────────────────────────
let passed = 0, failed = 0;

async function test(label, input, expected) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmFile, zkeyFile);
    const proofOk = await snarkjs.groth16.verify(vk, publicSignals, proof);

    if (!proofOk) {
      console.log(`  ❌ ${label} — Groth16 verification FAILED`);
      failed++;
      return;
    }

    // Check each expected signal
    let allOk = true;
    for (const [name, expectedVal] of Object.entries(expected)) {
      const idx    = SIG[name];
      const actual = publicSignals[idx];
      if (expectedVal !== null && actual !== String(expectedVal)) {
        console.log(`  ❌ ${label}`);
        console.log(`     signal ${name}[${idx}]: expected ${expectedVal}, got ${actual}`);
        allOk = false;
      }
    }

    // Check that hash outputs are non-zero
    for (const hashName of ['credentialHash','issuerDIDHash','subjectDIDHash','diagnosisHash']) {
      if (publicSignals[SIG[hashName]] === '0') {
        console.log(`  ❌ ${label} — ${hashName} is zero (shouldn't happen)`);
        allOk = false;
      }
    }

    if (allOk) {
      console.log(`  ✅ ${label}`);
      passed++;
    } else {
      failed++;
    }
  } catch (err) {
    console.log(`  ❌ ${label} — circuit rejected: ${err.message.split('\n')[0]}`);
    failed++;
  }
}

// ── Test cases ────────────────────────────────────────────────────────────────
console.log('\n🧪 MedicalCredential circuit — smoke tests\n');
console.log(`   WASM : ${wasmFile}`);
console.log(`   zkey : ${zkeyFile}`);
console.log(`   vk   : ${vkFile}\n`);

// 1. Valid base case — everything passes
await test(
  'valid inputs → all signals true',
  { ...base },
  { amountInRange: 1, policyValid: 1, coverageSufficient: 1, ageEligible: 1 }
);

// 2. Amount above max → amountInRange = 0
await test(
  'billAmount > billAmountMax → amountInRange=0',
  { ...base, billAmount: '20000000' },        // $200k > $100k max
  { amountInRange: 0, policyValid: 1, coverageSufficient: 0, ageEligible: 1 }
);

// 3. Amount below min → amountInRange = 0
await test(
  'billAmount < billAmountMin → amountInRange=0',
  { ...base, billAmountMin: '500000', billAmount: '100' },
  { amountInRange: 0 }
);

// 4. Policy expired → policyValid = 0
await test(
  'policyExpiry < currentTimestamp → policyValid=0',
  { ...base, policyExpiry: String(NOW - 3600) },  // expired 1h ago
  { amountInRange: 1, policyValid: 0, coverageSufficient: 1, ageEligible: 1 }
);

// 5. Coverage too low → coverageSufficient = 0
await test(
  'coverageAmount < billAmount → coverageSufficient=0',
  { ...base, coverageAmount: '100000', billAmount: '500000' },  // $1k < $5k
  { amountInRange: 1, policyValid: 1, coverageSufficient: 0, ageEligible: 1 }
);

// 6. All limits hit simultaneously
await test(
  'expired policy + over coverage + out of range + over-age → all false',
  {
    ...base,
    billAmount:       '20000000',           // over range max
    coverageAmount:   '1',                  // way below bill
    policyExpiry:     String(NOW - 1),      // just expired
    patientAge:       '75',                 // over age max
  },
  { amountInRange: 0, policyValid: 0, coverageSufficient: 0, ageEligible: 0 }
);

// 7. Boundary: billAmount === billAmountMax → amountInRange = 1
await test(
  'billAmount === billAmountMax (boundary) → amountInRange=1',
  { ...base, billAmount: base.billAmountMax },
  { amountInRange: 1, ageEligible: 1 }
);

// 8. Age above max → ageEligible = 0
await test(
  'patientAge > ageMax → ageEligible=0',
  { ...base, patientAge: '60' },
  { ageEligible: 0, amountInRange: 1, policyValid: 1, coverageSufficient: 1 }
);

// 9. proofNonce must equal salt — circuit constraint
//    (different nonce → constraint fails → witness generation throws)
let nonceTestPassed = false;
try {
  await snarkjs.groth16.fullProve(
    { ...base, proofNonce: '99999999' },
    wasmFile, zkeyFile
  );
  console.log('  ❌ proofNonce ≠ salt — should have been rejected but wasn\'t');
  failed++;
} catch {
  console.log('  ✅ proofNonce ≠ salt → circuit correctly rejected');
  passed++;
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n   Results: ${passed} passed, ${failed} failed\n`);
if (failed > 0) { console.error('❌ Some tests failed'); process.exit(1); }
console.log('✅ All circuit tests passed — real Groth16 proofs working\n');
