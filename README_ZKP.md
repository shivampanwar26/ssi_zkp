# ZKP Process README

This document explains how the current Zero-Knowledge Proof (ZKP) flow works in this project, including:

- End-to-end runtime flow
- Circuit variables and their meaning
- JavaScript-side variables and metadata
- Verification checks
- Reimbursement variables and formulas

It reflects the current code in:

- `src/zkpManager.js`
- `src/zkpMenu.js`
- `src/agentManager-blockchain.js`
- `src/circuits/medical_credential.circom`

## 1) High-Level Architecture

The project uses **Groth16 proofs via `snarkjs`** over the BN128 curve.

Core idea:

- Patient has a credential (Medical Bill or Insurance Policy).
- Patient generates a ZK proof locally.
- Proof is submitted to insurer.
- Insurer verifies proof mathematically and with integrity/blockchain checks.
- If valid, insurer computes reimbursement.

Important current behavior:

- `amount` is intentionally disclosed as an exact value in `disclosedClaims.amount` for reimbursement.
- Sensitive values (for example diagnosis text, hashes, non-disclosed fields) remain private or abstracted.
- Proofs are **not anchored on-chain**; proof audit hashes are stored locally, while original credential hashes are verified on-chain.

## 2) End-to-End Runtime Flow

### Step A: Generate proof (Patient)

Entry points:

- `src/zkpMenu.js` -> `handleGenerateProof(...)`
- `src/agentManager-blockchain.js` -> `generateZKProof(...)`
- `src/zkpManager.js` -> `generateProof(...)`

What happens:

1. Patient selects a credential and which fields to disclose/prove.
2. `generateProof()` builds circuit input (`circuitInput`).
3. `snarkjs.groth16.fullProve(...)` creates:
   - `proof` (pi_a, pi_b, pi_c)
   - `publicSignals` (array of circuit outputs)
4. JS builds `publicInputs`, `predicates`, and `disclosedClaims`.
5. Proof object is saved to wallet:
   - `./data/wallets/<patientId>/proofs/<proofId>.json`

### Step B: Submit proof (Patient -> Insurer)

Entry points:

- `src/zkpMenu.js` -> `handleSubmitProof(...)`
- `src/agentManager-blockchain.js` -> `submitZKProof(...)`

What happens:

1. Loads proof from patient wallet.
2. Copies proof JSON to insurer received folder with submission metadata:
   - `submittedBy`
   - `submittedByDid`
   - `submittedAt`
3. Saved in:
   - `./data/wallets/<insurerId>/received-proofs/<proofId>.json`

### Step C: Verify proof (Insurer)

Entry points:

- `src/zkpMenu.js` -> `handleVerifyProof(...)`
- `src/agentManager-blockchain.js` -> `verifyZKProof(...)`
- `src/zkpManager.js` -> `verifyProof(...)`

What happens:

1. Insurer selects bill proof (and optional policy proof).
2. `verifyProof()` executes validation checks (explained later).
3. Proof verification result is written back into:
   - Insurer received proof file
   - Patient proof file (status sync)

### Step D: Reimbursement calculation and record

Entry points:

- `src/zkpMenu.js` -> compliance checks + confirmation
- `src/zkpManager.js` -> `calculateReimbursement(...)`
- `src/zkpManager.js` -> `saveReimbursement(...)`

What happens:

1. Uses verified bill proof claims and insurer policy.
2. Computes reimbursement breakdown.
3. On approval, saves reimbursement JSON:
   - `./data/wallets/<insurerId>/reimbursements/<recordId>.json`

## 3) Circuit Variables (medical_credential.circom)

Defined in `src/circuits/medical_credential.circom`.

### 3.1 Circuit inputs (`signal input`)

- `billAmount`
  - Bill value in integer cents.
  - Example: `250000` means `$2500.00`.
- `coverageAmount`
  - Policy coverage limit in cents.
- `policyExpiry`
  - Policy expiry Unix timestamp.
- `currentTimestamp`
  - Current time at proof generation (Unix timestamp).
- `patientAge`
  - Patient age in years (private witness input).
- `ageMin`
  - Minimum eligible age (inclusive).
- `ageMax`
  - Maximum eligible age (inclusive).
- `diagnosisPreimage`
  - Field-encoded diagnosis string.
- `salt`
  - Random blinding nonce.
- `credentialFields[10]`
  - Ten encoded credential fields used to bind credential content.
- `issuerDIDPreimage`
  - Field-encoded issuer DID string.
- `subjectDIDPreimage`
  - Field-encoded patient DID string.
- `billAmountMin`
  - Lower bound for amount range check.
- `billAmountMax`
  - Upper bound for amount range check.
- `proofNonce`
  - Must equal `salt` (anti-replay binding constraint).

### 3.2 Circuit outputs (`signal output`)

- `credentialHash`
  - Poseidon hash over `credentialFields + salt`.
  - Binds proof to a specific credential content.
- `issuerDIDHash`
  - Poseidon hash of issuer DID preimage + salt.
- `subjectDIDHash`
  - Poseidon hash of subject DID preimage + salt.
- `amountInRange`
  - `1` if `billAmountMin <= billAmount <= billAmountMax`, else `0`.
- `diagnosisHash`
  - Poseidon hash of diagnosis preimage + salt.
- `policyValid`
  - `1` if `policyExpiry > currentTimestamp`, else `0`.
- `coverageSufficient`
  - `1` if `coverageAmount >= billAmount`, else `0`.
- `ageEligible`
  - `1` if `ageMin <= patientAge <= ageMax`, else `0`.

## 4) Variables Built in `generateProof()`

Main variables in `src/zkpManager.js`:

- `timestamp`
  - JS timestamp used for proof freshness checks (`proofTimestamp`).
- `allClaims`
  - `credential.credentialSubject` values.
- `saltBig`, `saltStr`
  - Random blinding value used in circuit input.
- `now`
  - Current Unix timestamp.
- `billAmountCents`
  - Parsed bill amount in cents from credential.
- `coverageAmountCents`
  - Parsed coverage amount in cents from hints/credential.
- `policyExpiry`
  - Derived Unix timestamp from policy date.
- `diagnosisPreimage`
  - Encoded diagnosis value.
- `issuerDIDPreimage`, `subjectDIDPreimage`
  - Encoded DID values.
- `FIELD_KEYS`
  - Fixed list of 10 claim field keys for `credentialFields`.
- `credentialFields`
  - 10 encoded field elements bound into `credentialHash`.
- `billAmountMin`, `billAmountMax`
  - Range bounds used by circuit for `amountInRange`.
- `ageYears`, `ageMin`, `ageMax`
  - Age witness/range used by circuit for `ageEligible`.
- `circuitInput`
  - Full witness input object passed to `fullProve`.
- `snarkProof`, `publicSignals`
  - Result from `snarkjs.groth16.fullProve`.

## 5) Proof JSON Structure and Significance

Saved proof object includes:

- `id`
  - Unique proof identifier.
- `proofHash`
  - SHA-256 over proof/signals for audit reference.
- `protocol`, `curve`, `circuitId`, `engine`
  - Cryptographic context.
- `proof`
  - Groth16 proof points (`pi_a`, `pi_b`, `pi_c`).
- `publicInputs`
  - App-level metadata plus parsed signal booleans/tokens.
- `integrityDigest`, `masterCommitment`
  - HMAC-based tamper detection binding.
- `credentialReference`
  - Issuer/type/hash references to original credential.
- `generatedAt`, `generatedBy`
  - Provenance.
- `verified`, `verifiedBy`, `verifiedAt`
  - Verification status fields.

## 6) `publicInputs` and `disclosedClaims`

Important fields inside `publicInputs`:

- Identity/context:
  - `credentialType`, `issuerDID`, `subjectDID`, `issuanceTimestamp`, `proofTimestamp`, `circuitId`
- Circuit-derived values:
  - `credentialHash`, `issuerDIDHash`, `subjectDIDHash`, `diagnosisHash`
  - `amountInRange`, `policyValid`, `coverageSufficient`, `ageEligible`
  - `snarkPublicSignals` (raw array for verifier)
- UI/policy metadata:
  - `predicates`
  - `hiddenFieldCount`
  - `disclosedClaims`

`disclosedClaims` significance:

- This is what downstream reimbursement logic reads.
- Current behavior:
  - `disclosedClaims.amount` is exact (for reimbursement math).
  - Other fields are generally predicate labels/tokens.

## 7) Verification Checks in `verifyProof()`

`checks` object fields:

- `structureValid`
  - Proof has required structure and core fields.
- `freshnessValid`
  - Proof age <= 24 hours.
- `integrityValid`
  - Recomputed HMAC equals stored `integrityDigest`.
  - Protects against edited JSON after proof generation.
- `proofMathValid`
  - Cryptographic pairing check (`snarkjs.groth16.verify`).
- `commitmentsValid`
  - For real snarkjs proofs, treated as valid if math check passed.
- `issuerDIDOnChain`
  - Issuer DID exists on blockchain (if blockchain available).
- `credentialOnChain`
  - Referenced credential hash exists, not revoked, issuer DID matches.

`result.valid` is overall pass/fail after all critical checks.

## 8) Reimbursement Variables and Formula

Function:

- `calculateReimbursement(policyDisclosed, billDisclosed, insurerPolicy)`

Input significance:

- `insurerPolicy`
  - Most trusted source (insurer wallet credential values).
- `policyDisclosed`
  - Fallback/cross-check policy claims from proof.
- `billDisclosed`
  - Bill-side disclosed claims from proof.

Key variables:

- `policySource`
  - `insurerPolicy || policyDisclosed || {}`
- `billAmount`
  - Parsed from `billDisclosed.amount`.
- `amountIsHidden`
  - Legacy compatibility branch for old range-tokenized proofs.
- `diagnosisCovered`
  - Derived from diagnosis predicate token or legacy raw value.
- `ageEligible`
  - Derived from age predicate token/value.
- `maxCoverage`, `coveragePct`, `deductible`
  - Parsed policy financial terms.
- `effectiveBillAmount`
  - Uses bill amount normally.
  - Uses cap fallback only for legacy hidden-amount proofs.

Formula:

1. `afterDeductible = max(0, effectiveBillAmount - deductible)`
2. `coverageApplied = afterDeductible * (coveragePct / 100)`
3. `reimbursable = min(coverageApplied, maxCoverage)` if cap exists, else `coverageApplied`
4. `finalReimbursement = reimbursable` only if `diagnosisCovered && ageEligible`, else `0`
5. `patientOwes = effectiveBillAmount - finalReimbursement`

Output breakdown fields:

- `billAmount`
- `billAmountIsHidden`
- `deductible`
- `afterDeductible`
- `coveragePercent`
- `coverageApplied`
- `maxCoverage`
- `maxCoverageSource`
- `diagnosisCovered`
- `ageEligible`
- `reimbursementAmount`
- `patientOwes`
- `calculatedAt`

## 9) Storage Paths

- Patient generated proofs:
  - `./data/wallets/<agentId>/proofs/*.json`
- Insurer received proofs:
  - `./data/wallets/<agentId>/received-proofs/*.json`
- Insurer reimbursements:
  - `./data/wallets/<agentId>/reimbursements/*.json`
- Proof audit records:
  - `./data/proofs/audit/*-audit.json`

## 10) Current Notes on Range Proof Functionality

- The **CLI menu entry for range proof generation was removed** from the active `index.js` + `zkpMenu.js` flow.
- Range-proof helper methods still exist in backend code for compatibility/testing:
  - `generateRangeProof(...)`
  - `verifyRangeProof(...)`
- Verification now uses a **fail-closed** policy for Groth16 math checks:
  - proofs missing valid `snarkPublicSignals` are rejected
  - legacy structural-format fallback verification is removed

## 11) Quick Debug Checklist

If proof generation fails:

1. Ensure circuit artifacts exist under `src/circuits/build`.
2. Run setup script:
   - `cd src/circuits && ./setup.sh`
3. Check `wasm`, `zkey`, and `vk.json` paths.

If verification fails:

1. Check `integrityDigest` mismatch (proof JSON may have been edited).
2. Check proof freshness (older than 24h fails).
3. Check blockchain connectivity for DID/credential checks.
4. Check if credential hash is revoked or issuer DID mismatched on-chain.
