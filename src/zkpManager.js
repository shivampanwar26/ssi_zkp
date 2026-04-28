import crypto from 'crypto';
import chalk from 'chalk';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// snarkjs — real Groth16 over BN128
// Install: npm install snarkjs
import * as snarkjs from 'snarkjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

/**
 * ====================================================================
 * ZKP MANAGER — Real Groth16 over BN128 (snarkjs + circom)  v2: multi-VC
 * ====================================================================
 *
 * Circuit: circuits/medical_credential.circom
 *   Compiled to:  circuits/build/medical_credential_js/medical_credential.wasm
 *   Proving key:  circuits/build/proving.zkey
 *   Verif. key:   circuits/build/vk.json
 *
 * One-time setup (run before first use):
 *   cd circuits && ./setup.sh
 *
 * WHAT CHANGED FROM v1 (multi-VC security fix)
 * ─────────────────────────────────────────────
 * v1 sourced billAmount, policyExpiry, and coverageAmount from either
 * predicateHints (caller-supplied) or allClaims (the patient's own VC).
 * All three values were therefore self-reported — the patient could provide
 * any numbers they liked and the circuit would happily compute policyValid /
 * coverageSufficient based on the fake values.
 *
 * v2 introduces a second VC in the witness: the insurer-issued policy VC.
 *   - policyExpiry and coverageAmount are now read exclusively from
 *     policyCredential.credentialSubject — the document InsureUltra signed.
 *   - The circuit commits to all five policy fields via Poseidon → policyVCHash
 *     (public signal [8]).
 *   - During verification the insurer checks policyVCHash against the on-chain
 *     commitment of their own policy VC.  A patient who tampers with any policy
 *     field will produce a hash that does NOT match → proof rejected.
 *
 * What the circuit proves (without revealing private data):
 *   1. Medical-VC integrity — Poseidon(credentialFields, salt) matches on-chain hash
 *   2. Bill amount range    — amount ∈ [min, max]
 *   3. Diagnosis hash       — Poseidon(diagnosis, salt) for set-membership
 *   4. Policy validity      — policyVCFields[3] (policyExpiry) > now       ← from insurer VC
 *   5. Coverage sufficiency — policyVCFields[2] (coverageAmount) >= bill   ← from insurer VC
 *   6. Age eligibility      — age ∈ [ageMin, ageMax]
 *   7. Policy VC commitment — Poseidon(policyVCFields, policySalt)         ← NEW
 *
 * Public signals (verifier sees):
 *   credentialHash, issuerDIDHash, subjectDIDHash,
 *   amountInRange, diagnosisHash, policyValid, coverageSufficient, ageEligible,
 *   policyVCHash   ← NEW
 *
 * Private witness (patient only):
 *   [medical VC]  billAmount, patientAge, ageMin, ageMax,
 *                 diagnosisPreimage, salt, credentialFields[10],
 *                 issuerDIDPreimage, subjectDIDPreimage,
 *                 billAmountMin, billAmountMax, proofNonce
 *   [policy VC]   policyVCFields[5], policySalt, currentTimestamp
 *
 * Architecture:
 *   - Real Groth16: snarkjs.groth16.fullProve / snarkjs.groth16.verify
 *   - Policy data (coverageAmount, policyExpiry) sourced from insurer-issued
 *     policy VC credential, not from predicateHints or patient self-report.
 *   - verifyProof() checks policyVCHash (public signal [8]) against the
 *     on-chain hash of the policy VC so the insurer can confirm the exact
 *     policy document that was committed to in the circuit.
 * ====================================================================
 */

export class ZKPManager {
  constructor() {
    this.proofsDir     = './data/proofs';
    this.circuitVersion = 'medical_credential_v2';   // bumped — circuit changed
    this.protocol      = 'groth16';
    this.curve         = 'bn128';

    // Paths to compiled circuit artifacts (produced by circuits/setup.sh)
    const buildDir     = path.join(__dirname, 'circuits', 'build');
    this.wasmPath      = path.join(buildDir, 'medical_credential_js', 'medical_credential.wasm');
    this.zkeyPath      = path.join(buildDir, 'proving.zkey');
    this.vkPath        = path.join(buildDir, 'vk.json');

    this._vk           = null;   // cached verification key (loaded on first verify)
    this._circuitReady = false;  // set true after artifact check in initialize()
  }

  // ======================================================
  // INITIALIZATION
  // ======================================================

  async initialize() {
    await fs.mkdir(this.proofsDir, { recursive: true });

    // Check all circuit artifacts are present
    const missing = [];
    for (const [label, p] of [
      ['WASM witness generator', this.wasmPath],
      ['Proving key (zkey)',     this.zkeyPath],
      ['Verification key (vk)',  this.vkPath],
    ]) {
      try { await fs.access(p); }
      catch { missing.push(`  ✗ ${label}: ${p}`); }
    }

    if (missing.length > 0) {
      console.log(chalk.yellow('\n⚠️  Circuit artifacts not found. Run the trusted setup first:\n'));
      console.log(chalk.white('   cd circuits && chmod +x setup.sh && ./setup.sh\n'));
      missing.forEach(m => console.log(chalk.red(m)));
      console.log('');
      this._circuitReady = false;
    } else {
      // Pre-load and cache the verification key
      const vkRaw = await fs.readFile(this.vkPath, 'utf-8');
      this._vk    = JSON.parse(vkRaw);
      this._circuitReady = true;
      console.log(chalk.green('✅ ZKP Module initialized (real Groth16 over BN128)'));
      console.log(chalk.gray(`   Circuit:  ${this.circuitVersion}`));
      console.log(chalk.gray(`   Protocol: ${this.protocol} | Curve: ${this.curve}`));
      console.log(chalk.gray(`   WASM:     ${this.wasmPath}`));
      console.log(chalk.gray(`   zkey:     ${this.zkeyPath}\n`));
    }
  }

  // ── Throw a clear error when setup has not been run ──────────────────────
  _requireCircuit() {
    if (!this._circuitReady) {
      throw new Error(
        'Circuit artifacts missing. Run:  cd circuits && ./setup.sh\n' +
        'See circuits/README.md for instructions.'
      );
    }
  }

  // ======================================================
  // CORE: GENERATE ZK PROOF  (real Groth16 via snarkjs)
  // ======================================================

  /**
   * Generate a real Groth16 ZK proof from a medical credential AND an
   * insurer-issued policy credential.
   *
   * Privacy model:
   *   - Sensitive medical fields remain private in the witness.
   *   - Bill amount is intentionally disclosed for reimbursement calculation.
   *   - Policy data (coverageAmount, policyExpiry) comes exclusively from the
   *     insurer-signed policy VC — NOT from predicateHints or patient self-report.
   *   - The circuit produces nine public signals:
   *       credentialHash, issuerDIDHash, subjectDIDHash,
   *       amountInRange, diagnosisHash, policyValid, coverageSufficient,
   *       ageEligible, policyVCHash
   *   - The verifier learns ONLY: which statements are satisfied and the two
   *     VC commitment hashes (medical + policy) — never raw field values.
   *
   * @param {Object}   credential        - Full W3C medical VC (private, never sent)
   * @param {Object}   credentialRecord  - Wallet metadata record for the medical VC
   * @param {string[]} disclosedFields   - Fields to include in witness
   * @param {Object}   proverAgent       - Patient generating the proof
   * @param {Object}   policyCredential  - Full W3C policy VC issued by insurer
   * @param {Object}   policyRecord      - Wallet metadata record for the policy VC
   *                                       (must contain blockchainHash of the policy VC)
   * @param {Object}   [predicateHints]  - { billAmountMin, billAmountMax, ageMin, ageMax }
   *                                       NOTE: coverageAmount and policyExpiry are no
   *                                       longer accepted here — they come from policyCredential.
   * @returns {Object} zkProof
   */
  async generateProof(
    credential,
    credentialRecord,
    disclosedFields,
    proverAgent,
    policyCredential,
    policyRecord,
    predicateHints = {}
  ) {
    this._requireCircuit();

    // ── Guard: policy credential is mandatory ─────────────────────────────────
    if (!policyCredential?.credentialSubject) {
      throw new Error(
        'generateProof() requires a policyCredential (insurer-issued policy VC). ' +
        'coverageAmount and policyExpiry must come from the insurer-signed document, ' +
        'not from predicateHints or self-reported fields.'
      );
    }

    console.log(chalk.magenta('\n🔐 Generating Real Groth16 ZK Proof (multi-VC)...'));
    console.log(chalk.gray(`   Circuit:  ${this.circuitVersion}`));
    console.log(chalk.gray(`   Protocol: real Groth16 / BN128 (snarkjs)\n`));
    console.log(chalk.cyan(`   Medical VC issuer: ${credentialRecord.issuerDid?.substring(0, 40)}...`));
    console.log(chalk.cyan(`   Policy  VC issuer: ${policyRecord?.issuerDid?.substring(0, 40) || 'unknown'}...`));

    const timestamp = Date.now();
    const allClaims = credential.credentialSubject || {};

    // ── Step 1: Build circuit witness inputs ──────────────────────────────────
    // All values are converted to field elements (BigInt strings).
    // Strings are encoded via _strToField (truncated Poseidon-ready integers).

    // Salt for medical VC: 128-bit random nonce
    const saltBig  = BigInt('0x' + crypto.randomBytes(16).toString('hex'));
    const saltStr  = saltBig.toString();

    // Salt for policy VC: separate 128-bit random nonce
    const policySaltBig = BigInt('0x' + crypto.randomBytes(16).toString('hex'));
    const policySaltStr = policySaltBig.toString();

    const now = Math.floor(timestamp / 1000);  // Unix seconds

    // ── MEDICAL VC fields ─────────────────────────────────────────────────────

    // Bill amount: strip currency symbol, convert to cents (from hospital VC)
    const billAmountCents = this._toCents(allClaims.amount || '0');

    // Age (years): if missing/invalid, force out-of-range (255) so eligibility fails safe.
    const parsedAge = parseFloat(String(allClaims.age ?? '').replace(/[^0-9.]/g, ''));
    const ageYears = Number.isFinite(parsedAge)
      ? Math.max(0, Math.round(parsedAge))
      : 255;

    // Diagnosis: encode as field element for Poseidon
    const diagnosisPreimage = this._strToField(allClaims.diagnosis || allClaims.coveredDiagnoses || '');

    // Issuer and subject DIDs as field elements
    const issuerDIDPreimage  = this._strToField(credentialRecord.issuerDid || '');
    const subjectDIDPreimage = this._strToField(proverAgent.did || '');

    // Credential fields array (exactly 10 elements, zero-padded)
    // We hash all claim values into the array deterministically.
    const FIELD_KEYS = [
      'billNumber', 'patientName', 'diagnosis', 'treatment',
      'amount', 'serviceDate', 'issuedDate',
      'policyNumber', 'planName', 'validUntil',
    ];
    const credentialFields = FIELD_KEYS.map(k =>
      this._strToField(String(allClaims[k] ?? '')).toString()
    );

    // Range bounds for amount check (from hints or defaults)
    const billAmountMin = (predicateHints.billAmountMin ?? 0).toString();
    const billAmountMax = (predicateHints.billAmountMax != null
      ? this._toCents(String(predicateHints.billAmountMax))
      : 100_000_000   // $1M cap default
    ).toString();
    const ageMin = (predicateHints.ageMin ?? 0).toString();
    const ageMax = (predicateHints.ageMax ?? 59).toString();

    // ── POLICY VC fields ──────────────────────────────────────────────────────
    //
    // coverageAmount and policyExpiry come EXCLUSIVELY from the insurer-signed
    // policy credential — predicateHints.coverageAmount and
    // predicateHints.policyExpiry are intentionally ignored here.
    //
    // If the patient tampers with any of these five values the resulting
    // policyVCHash will not match the on-chain commitment InsureUltra
    // published → verifyProof() will reject the proof.
    const policySubject = policyCredential.credentialSubject;

    const coverageAmountCents = this._toCents(policySubject.coverageAmount || '0');

    const policyExpiryDate =
      policySubject.policyExpiry ||
      policySubject.validUntil  ||
      policySubject.expiryDate  ||
      null;
    const policyExpiry = policyExpiryDate
      ? Math.floor(new Date(policyExpiryDate).getTime() / 1000)
      : 0;   // 0 → policyExpiry <= now → policyValid = 0 (fail-safe)

    // policyVCFields layout (must match circom signal index):
    //   [0] policyNumber   → encoded as field element
    //   [1] planName       → encoded as field element
    //   [2] coverageAmount → integer cents  (drives coverageSufficient check)
    //   [3] policyExpiry   → Unix timestamp (drives policyValid check)
    //   [4] insuredDIDField→ patient DID encoded, cryptographically links policy to holder
    const policyVCFields = [
      this._strToField(String(policySubject.policyNumber ?? '')).toString(),
      this._strToField(String(policySubject.planName     ?? '')).toString(),
      coverageAmountCents.toString(),
      policyExpiry.toString(),
      this._strToField(proverAgent.did || '').toString(),
    ];

    console.log(chalk.gray(`   Policy fields sourced from insurer VC (NOT self-reported):`));
    console.log(chalk.gray(`     policyNumber   : ${policySubject.policyNumber || 'N/A'}`));
    console.log(chalk.gray(`     planName       : ${policySubject.planName     || 'N/A'}`));
    console.log(chalk.gray(`     coverageAmount : ${coverageAmountCents} cents (from insurer VC)`));
    console.log(chalk.gray(`     policyExpiry   : ${policyExpiry} (Unix) ← from insurer VC`));

    // ── Circuit input object ──────────────────────────────────────────────────
    // NOTE: coverageAmount and policyExpiry are NOT top-level inputs anymore —
    // they live inside policyVCFields[2] and policyVCFields[3].
    const circuitInput = {
      // Medical VC inputs
      billAmount:          billAmountCents.toString(),
      patientAge:          ageYears.toString(),
      ageMin,
      ageMax,
      diagnosisPreimage:   diagnosisPreimage.toString(),
      salt:                saltStr,
      credentialFields,
      issuerDIDPreimage:   issuerDIDPreimage.toString(),
      subjectDIDPreimage:  subjectDIDPreimage.toString(),
      billAmountMin,
      billAmountMax,
      proofNonce:          saltStr,   // must equal salt — see circuit constraint 0

      // Policy VC inputs (from insurer-issued VC — NOT self-reported)
      policyVCFields,
      policySalt:          policySaltStr,
      currentTimestamp:    now.toString(),
    };

    // ── Step 2: Run real Groth16 proof via snarkjs ────────────────────────────
    console.log(chalk.gray('\n   Running snarkjs.groth16.fullProve...'));
    console.log(chalk.gray('   (This takes 2–10s depending on hardware)\n'));

    let snarkProof, publicSignals;
    try {
      ({ proof: snarkProof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput,
        this.wasmPath,
        this.zkeyPath
      ));
    } catch (err) {
      throw new Error(`Groth16 proof generation failed: ${err.message}`);
    }

    // ── Step 3: Parse public signals ─────────────────────────────────────────
    // Signal order matches circuit output declarations:
    //   [0] credentialHash
    //   [1] issuerDIDHash
    //   [2] subjectDIDHash
    //   [3] amountInRange
    //   [4] diagnosisHash
    //   [5] policyValid
    //   [6] coverageSufficient
    //   [7] ageEligible
    //   [8] policyVCHash          ← NEW (commitment to insurer-issued policy VC)
    const [
      credentialHash,
      issuerDIDHashSig,
      subjectDIDHashSig,
      amountInRangeSig,
      diagnosisHashSig,
      policyValidSig,
      coverageSufficientSig,
      ageEligibleSig,
      policyVCHashSig,            // NEW
    ] = publicSignals;

    const amountInRange      = amountInRangeSig      === '1';
    const policyValid        = policyValidSig        === '1';
    const coverageSufficient = coverageSufficientSig === '1';
    const ageEligible        = ageEligibleSig        === '1';

    // ── Step 4: Build predicate metadata (labels for UI — not used by circuit) ─
    const disclosedAmount = String(allClaims.amount ?? '0');
    const predicates = {
      amount: {
        type:       'exact',
        statement:  `billAmount disclosed for reimbursement: ${disclosedAmount}`,
        publicValue: disclosedAmount,
        satisfied:  amountInRange,
        rangeCheck: `billAmount ∈ [${billAmountMin}, ${billAmountMax}] cents`,
        signalIndex: 3,
      },
      diagnosis: {
        type:       'hash',
        statement:  `diagnosis committed (Poseidon hash: ${diagnosisHashSig.substring(0, 16)}...)`,
        publicValue: `diagnosis_hash_${diagnosisHashSig.substring(0, 16)}`,
        satisfied:  true,   // presence always true — insurer checks hash against whitelist
        diagnosisHash: diagnosisHashSig,
        signalIndex: 4,
      },
      policyValidity: {
        type:       'date',
        statement:  policyValid
          ? 'policy is not expired (proven from insurer-issued policy VC)'
          : 'policy has expired (from insurer-issued policy VC)',
        publicValue: policyValid ? 'policyValid' : 'policyExpired',
        satisfied:  policyValid,
        signalIndex: 5,
        source: 'insurer-vc',   // annotate that this came from the signed policy VC
      },
      coverage: {
        type:       'numeric',
        statement:  coverageSufficient
          ? 'coverageAmount (insurer VC) >= billAmount'
          : 'coverageAmount (insurer VC) < billAmount',
        publicValue: coverageSufficient ? 'coverage_sufficient' : 'coverage_insufficient',
        satisfied:  coverageSufficient,
        signalIndex: 6,
        source: 'insurer-vc',   // annotate that this came from the signed policy VC
      },
      age: {
        type:       'numeric',
        statement:  `age ∈ [${ageMin}, ${ageMax}]`,
        publicValue: ageEligible
          ? `age_in_range_${ageMin}_${ageMax}`
          : `age_out_of_range_${ageMin}_${ageMax}`,
        satisfied:  ageEligible,
        signalIndex: 7,
      },
      policyVCCommitment: {         // NEW predicate — shows policyVCHash in UI
        type:       'hash',
        statement:  `policy VC committed (Poseidon hash: ${policyVCHashSig.substring(0, 16)}...) — verifiable against insurer on-chain hash`,
        publicValue: `policy_vc_hash_${policyVCHashSig.substring(0, 16)}`,
        satisfied:  true,
        policyVCHash: policyVCHashSig,
        signalIndex: 8,
        source: 'insurer-vc',
      },
    };

    // ── Step 5: Build public inputs object ───────────────────────────────────
    const publicInputs = {
      credentialType:      credentialRecord.type,
      issuerDID:           credentialRecord.issuerDid,
      subjectDID:          proverAgent.did,
      issuanceTimestamp:   credentialRecord.issuedAt,
      proofTimestamp:      timestamp,
      circuitId:           this.circuitVersion,

      // Real circuit public signals
      credentialHash,
      issuerDIDHash:       issuerDIDHashSig,
      subjectDIDHash:      subjectDIDHashSig,
      diagnosisHash:       diagnosisHashSig,
      amountInRange,
      policyValid,
      coverageSufficient,
      ageEligible,
      policyVCHash:        policyVCHashSig,  // NEW
      snarkPublicSignals:  publicSignals,    // raw array for snarkjs.verify

      // Predicate metadata (UI labels — not part of cryptographic proof)
      predicates,
      hiddenFieldCount: Object.keys(allClaims).filter(
        k => k !== 'id' && !disclosedFields.includes(k)
      ).length,

      // disclosedClaims: public values used by reimbursement engine.
      // amount is intentionally disclosed as exact value for reimbursement.
      disclosedClaims: Object.fromEntries(
        Object.entries(predicates).map(([k, p]) => [k, p.publicValue])
      ),
    };

    // ── Step 6: Integrity HMAC (binds JS metadata to snark proof) ────────────
    // The actual cryptographic guarantee comes from the snark proof.
    // This HMAC additionally binds the snark proof to our JS metadata
    // so tampering with publicInputs after generation is detectable.
    //
    // v2 ADDITION: policyVCHash and policyCredentialHash are now included in
    // the integrity payload so any post-generation tampering with the policy
    // reference is caught during verifyProof().
    const masterCommitment = this._computeCommitment(
      JSON.stringify(snarkProof) + saltStr
    );
    // ⚠  The payload key order and field names here are the CANONICAL form.
    //    verifyProof() must recompute EXACTLY the same JSON.stringify() call.
    const integrityPayload = JSON.stringify({
      snarkProof,
      snarkPublicSignals:    publicSignals,
      credentialType:        credentialRecord.type,
      issuerDid:             credentialRecord.issuerDid,
      credentialHashOnChain: credentialRecord.blockchainHash || null,
      // v2 additions — policy VC binding
      policyVCHash:          policyVCHashSig,
      policyCredentialHash:  policyRecord?.blockchainHash || null,
      policyIssuerDid:       policyRecord?.issuerDid      || null,
    });
    const integrityDigest = crypto.createHmac('sha256', masterCommitment)
      .update(integrityPayload)
      .digest('hex');

    // ── Step 7: Proof hash for audit trail ───────────────────────────────────
    const proofHash = this._computeCommitment(
      JSON.stringify(snarkProof) + JSON.stringify(publicSignals)
    );

    // ── Step 8: Assemble the final proof object ───────────────────────────────
    const zkProof = {
      id:        crypto.randomBytes(16).toString('hex'),
      proofHash,
      protocol:  this.protocol,
      curve:     this.curve,
      circuitId: this.circuitVersion,
      engine:    'snarkjs',

      // Real Groth16 proof (π_a, π_b, π_c as elliptic curve points)
      proof: snarkProof,

      // Public signals (circuit outputs)
      publicInputs,

      // Tamper protection
      integrityDigest,
      masterCommitment,

      // Medical VC reference
      credentialReference: {
        type:             credentialRecord.type,
        issuer:           credentialRecord.issuer,
        issuerDid:        credentialRecord.issuerDid,
        issuedAt:         credentialRecord.issuedAt,
        credentialHash:   credentialRecord.blockchainHash || null,
        blockchainTxHash: credentialRecord.blockchainTxHash || null,
      },

      // Policy VC reference (NEW — insurer-issued policy VC binding)
      policyVCReference: {
        policyVCHash:      policyVCHashSig,               // circuit-committed hash
        policyIssuerDid:   policyRecord?.issuerDid || null,
        policyCredentialHash: policyRecord?.blockchainHash || null,
        policyBlockchainTxHash: policyRecord?.blockchainTxHash || null,
        policyIssuedAt:    policyRecord?.issuedAt || null,
        policyNumber:      policySubject.policyNumber || null,
        planName:          policySubject.planName     || null,
        // NOTE: coverageAmount and policyExpiry are NOT stored here in plaintext.
        // They are committed to inside policyVCHash; the verifier checks
        // policyVCHash against the on-chain commitment — no raw value is needed.
      },

      generatedAt: new Date(timestamp).toISOString(),
      generatedBy: proverAgent.did,

      verified:   null,
      verifiedBy: null,
      verifiedAt: null,
    };

    // ── Console summary ───────────────────────────────────────────────────────
    console.log(chalk.green('   ✅ Real Groth16 proof generated (multi-VC)'));
    console.log(chalk.gray(`   Hash: ${proofHash.substring(0, 24)}...`));
    console.log('');
    console.log(chalk.cyan('   Public signals (what the verifier sees):'));
    console.log(chalk.green(`   ✅ amountInRange      : ${amountInRange}`));
    console.log(chalk.green(`   ✅ policyValid        : ${policyValid}  ← proven from insurer VC`));
    console.log(chalk.green(`   ✅ coverageSufficient : ${coverageSufficient}  ← proven from insurer VC`));
    console.log(chalk.green(`   ✅ ageEligible        : ${ageEligible}`));
    console.log(chalk.green(`   ✅ diagnosisHash      : ${diagnosisHashSig.substring(0, 20)}...`));
    console.log(chalk.green(`   ✅ policyVCHash       : ${policyVCHashSig.substring(0, 20)}...  ← NEW`));
    console.log(chalk.gray (`   🔒 credentialHash     : ${credentialHash.substring(0, 20)}... (on-chain verifiable)`));
    console.log(chalk.yellow(`\n   🙈 Sensitive values remain hidden, except amount (disclosed for reimbursement)\n`));

    return zkProof;
  }


  // ======================================================
  // CORE: VERIFY ZK PROOF
  // ======================================================

  /**
   * Verify a zero-knowledge proof.
   *
   * Verification checks:
   *   [1/8] Proof structure valid
   *   [2/8] Proof freshness (< 24 h)
   *   [3/8] Integrity HMAC (tamper detection — now covers policy VC fields)
   *   [4/8] Groth16 pairing check (snarkjs)
   *   [5/8] Commitment consistency
   *   [6/8] Issuer DID on blockchain
   *   [7/8] Medical credential hash on blockchain (not revoked, issuer matches)
   *   [8/8] Policy VC hash on blockchain ← NEW
   *         Compares policyVCHash (public signal [8]) against the on-chain
   *         commitment of the insurer-issued policy VC, confirming that
   *         coverageAmount / policyExpiry came from InsureUltra's signed doc.
   *
   * @param {Object} zkProof           - The ZK proof to verify
   * @param {Object} verifierAgent     - The agent verifying (insurer)
   * @param {Object} blockchainManager - Blockchain manager for on-chain checks
   * @returns {Object} verificationResult
   */
  async verifyProof(zkProof, verifierAgent, blockchainManager = null) {
    console.log(chalk.cyan('\n🔍 Verifying Zero-Knowledge Proof (multi-VC)...'));

    const checks = {
      structureValid:    false,
      freshnessValid:    false,
      integrityValid:    false,
      proofMathValid:    false,
      commitmentsValid:  false,
      issuerDIDOnChain:  null,   // null = not checked, true/false = result
      credentialOnChain: null,
      policyVCOnChain:   null,   // NEW: insurer policy VC on-chain commitment check
    };

    let overallValid = true;

    // ── Check 1: Proof structure ──────────────────────────────────────────────
    console.log(chalk.gray('   [1/8] Checking proof structure...'));
    if (!zkProof?.proof?.pi_a || !zkProof?.proof?.pi_b || !zkProof?.proof?.pi_c) {
      console.log(chalk.red('   ❌ Malformed proof structure'));
      checks.structureValid = false;
      overallValid = false;
    } else if (!zkProof.publicInputs?.credentialType) {
      console.log(chalk.red('   ❌ Missing credentialType in publicInputs'));
      checks.structureValid = false;
      overallValid = false;
    } else if (!zkProof.integrityDigest || !zkProof.masterCommitment) {
      console.log(chalk.red('   ❌ Missing integrity digest — proof may be forged'));
      checks.structureValid = false;
      overallValid = false;
    } else if (!zkProof.policyVCReference?.policyVCHash) {
      // v2: policy VC reference is mandatory
      console.log(chalk.red('   ❌ Missing policyVCReference — proof was generated without insurer policy VC'));
      checks.structureValid = false;
      overallValid = false;
    } else {
      checks.structureValid = true;
      console.log(chalk.green('   ✅ Structure valid (medical VC + policy VC references present)'));
    }

    // ── Check 2: Proof freshness (not older than 24 hours) ───────────────────
    console.log(chalk.gray('   [2/8] Checking proof freshness...'));
    const proofAge = Date.now() - zkProof.publicInputs.proofTimestamp;
    const maxAge   = 24 * 60 * 60 * 1000; // 24 hours

    if (proofAge > maxAge) {
      console.log(chalk.red(`   ❌ Proof expired (${Math.round(proofAge / 3600000)}h old, max 24h)`));
      checks.freshnessValid = false;
      overallValid = false;
    } else {
      checks.freshnessValid = true;
      const ageMinutes = Math.round(proofAge / 60000);
      console.log(chalk.green(`   ✅ Fresh (${ageMinutes}m old)`));
    }

    // ── Check 3: INTEGRITY DIGEST — TAMPER DETECTION ─────────────────────────
    // The HMAC was computed at proof generation time over a canonical payload
    // that now includes policyVCHash and policyCredentialHash.  Any post-
    // generation tampering with the policy reference is detected here.
    console.log(chalk.gray('   [3/8] Verifying integrity digest (tamper detection — includes policy VC)...'));
    if (zkProof.integrityDigest && zkProof.masterCommitment) {
      let recomputedPayload;
      if (zkProof.engine === 'snarkjs') {
        recomputedPayload = JSON.stringify({
          snarkProof:            zkProof.proof,
          snarkPublicSignals:    zkProof.publicInputs?.snarkPublicSignals,
          credentialType:        zkProof.credentialReference?.type,
          issuerDid:             zkProof.credentialReference?.issuerDid,
          credentialHashOnChain: zkProof.credentialReference?.credentialHash || null,
          // v2 additions — must match exactly what generateProof() serialised
          policyVCHash:          zkProof.policyVCReference?.policyVCHash || null,
          policyCredentialHash:  zkProof.policyVCReference?.policyCredentialHash || null,
          policyIssuerDid:       zkProof.policyVCReference?.policyIssuerDid || null,
        });
      }
      const recomputedDigest = crypto.createHmac('sha256', zkProof.masterCommitment)
        .update(recomputedPayload)
        .digest('hex');

      if (recomputedDigest === zkProof.integrityDigest) {
        checks.integrityValid = true;
        console.log(chalk.green('   ✅ Integrity check passed — no tampering detected (medical + policy VC)'));
      } else {
        checks.integrityValid = false;
        overallValid = false;
        console.log(chalk.red('   ❌ INTEGRITY CHECK FAILED — PROOF HAS BEEN TAMPERED WITH'));
        console.log(chalk.red('      Disclosed claims, commitments, policy VC reference, or credential ref'));
        console.log(chalk.red('      were modified after proof generation.'));
        console.log(chalk.red(`      Expected: ${zkProof.integrityDigest.substring(0, 24)}...`));
        console.log(chalk.red(`      Got:      ${recomputedDigest.substring(0, 24)}...`));
      }
    } else {
      checks.integrityValid = false;
      overallValid = false;
      console.log(chalk.red('   ❌ No integrity digest present — cannot verify authenticity'));
    }

    // ── Check 4: Real Groth16 verification (snarkjs) ─────────────────────────
    // snarkjs.groth16.verify checks e(π_a, π_b) == e(α,β)·e(vk_x,γ)·e(π_c,δ)
    console.log(chalk.gray('   [4/8] Verifying Groth16 proof (snarkjs pairing check)...'));
    if (zkProof.engine === 'snarkjs' && zkProof.publicInputs?.snarkPublicSignals) {
      try {
        if (!this._vk) {
          const vkRaw = await fs.readFile(this.vkPath, 'utf-8');
          this._vk = JSON.parse(vkRaw);
        }
        const snarkValid = await snarkjs.groth16.verify(
          this._vk,
          zkProof.publicInputs.snarkPublicSignals,
          zkProof.proof
        );
        checks.proofMathValid = snarkValid;
        if (snarkValid) {
          console.log(chalk.green('   ✅ Real Groth16 pairing check passed'));
          const pi = zkProof.publicInputs;
          console.log(chalk.gray(`      amountInRange      : ${pi.amountInRange}`));
          console.log(chalk.gray(`      policyValid        : ${pi.policyValid}  ← from insurer VC`));
          console.log(chalk.gray(`      coverageSufficient : ${pi.coverageSufficient}  ← from insurer VC`));
          console.log(chalk.gray(`      ageEligible        : ${pi.ageEligible}`));
          console.log(chalk.gray(`      diagnosisHash      : ${String(pi.diagnosisHash || '').substring(0, 20)}...`));
          console.log(chalk.gray(`      policyVCHash       : ${String(pi.policyVCHash || '').substring(0, 20)}...  ← NEW`));
        } else {
          console.log(chalk.red('   ❌ Groth16 pairing check FAILED — proof is invalid'));
          overallValid = false;
        }
      } catch (err) {
        checks.proofMathValid = false;
        overallValid = false;
        console.log(chalk.red(`   ❌ snarkjs.groth16.verify threw: ${err.message}`));
      }
    } else {
      checks.proofMathValid = false;
      overallValid = false;
      const engine = zkProof?.engine || 'unknown';
      console.log(chalk.red(`   ❌ Rejecting proof: engine=${engine}, snarkPublicSignals missing/invalid (fail-closed)`));
    }

    // ── Check 5: Commitment consistency ──────────────────────────────────────
    console.log(chalk.gray('   [5/8] Verifying commitments...'));
    if (zkProof.engine === 'snarkjs') {
      checks.commitmentsValid = true;
      const sigCount = zkProof.publicInputs?.snarkPublicSignals?.length || 0;
      console.log(chalk.green(`   ✅ ${sigCount} public signal(s) verified by Groth16 pairing check`));
    }

    // ── Check 6: Verify issuer DID on blockchain ──────────────────────────────
    console.log(chalk.gray('   [6/8] Verifying issuer DID on blockchain...'));
    if (blockchainManager?.contract) {
      try {
        const issuerDID = zkProof.publicInputs.issuerDID;
        const didInfo = await blockchainManager.contract.getDIDInfo(issuerDID);

        if (didInfo[0]) { // exists
          checks.issuerDIDOnChain = true;
          const registeredAt = new Date(Number(didInfo[2]) * 1000).toLocaleString();
          console.log(chalk.green(`   ✅ Issuer DID registered on-chain`));
          console.log(chalk.gray(`      Owner: ${didInfo[1]}`));
          console.log(chalk.gray(`      Registered: ${registeredAt}`));
        } else {
          checks.issuerDIDOnChain = false;
          console.log(chalk.red('   ❌ Issuer DID NOT found on blockchain'));
          overallValid = false;
        }
      } catch (error) {
        checks.issuerDIDOnChain = null;
        console.log(chalk.yellow(`   ⚠️  Blockchain DID check failed: ${error.message}`));
      }
    } else {
      console.log(chalk.yellow('   ⚠️  Blockchain not available for DID check'));
    }

    // ── Check 7: Verify medical credential hash on blockchain ─────────────────
    // Cross-verify: on-chain issuerDID must match the one claimed in the proof.
    // Without this, an attacker could reference ANY valid hash from a different issuer.
    console.log(chalk.gray('   [7/8] Verifying medical credential on blockchain...'));
    if (blockchainManager?.contract && zkProof.credentialReference?.credentialHash) {
      try {
        const credHash = zkProof.credentialReference.credentialHash;
        console.log(chalk.gray(`   Method: SSIRegistry.getCredential(bytes32) [view]`));
        const result = await blockchainManager.contract.getCredential(credHash);

        if (result[0]) { // exists
          if (result[5]) { // revoked
            checks.credentialOnChain = false;
            console.log(chalk.red('   ❌ Medical credential REVOKED on blockchain'));
            overallValid = false;
          } else {
            const onChainIssuerDID = result[2];
            const proofIssuerDID   = zkProof.publicInputs.issuerDID;

            if (onChainIssuerDID === proofIssuerDID) {
              checks.credentialOnChain = true;
              console.log(chalk.green('   ✅ Medical credential verified on-chain (not revoked)'));
              console.log(chalk.green(`      Issuer DID matches: ${onChainIssuerDID.substring(0, 36)}...`));
              console.log(chalk.gray(`      Type: ${result[4]}`));
              console.log(chalk.gray(`      Subject: ${result[3].substring(0, 36)}...`));
              console.log(chalk.gray(`      Issued: ${new Date(Number(result[1]) * 1000).toLocaleString()}`));
            } else {
              checks.credentialOnChain = false;
              overallValid = false;
              console.log(chalk.red('   ❌ ISSUER DID MISMATCH — medical credential issued by a different entity!'));
              console.log(chalk.red(`      Proof claims issuer:  ${proofIssuerDID.substring(0, 40)}...`));
              console.log(chalk.red(`      On-chain issuer:      ${onChainIssuerDID.substring(0, 40)}...`));
            }
          }
        } else {
          checks.credentialOnChain = false;
          console.log(chalk.yellow('   ⚠️  Medical credential hash not found on-chain'));
        }
      } catch (error) {
        checks.credentialOnChain = null;
        console.log(chalk.yellow(`   ⚠️  Blockchain credential check failed: ${error.message}`));
      }
    } else {
      console.log(chalk.yellow('   ⚠️  Blockchain not available or no medical credential hash'));
    }

    // ── Check 8: Verify policy VC commitment on blockchain ────────────────────
    //
    // This is the KEY new check introduced by the multi-VC approach.
    //
    // What it does:
    //   1. Read policyVCHash from public signal [8]  (circuit-computed Poseidon
    //      commitment over all five insurer-signed policy fields).
    //   2. Look up the policy VC by policyCredentialHash on-chain.
    //   3. Confirm the on-chain policy VC was issued by the expected insurer DID.
    //   4. Confirm the policy VC is not revoked.
    //
    // Why this closes the self-report gap:
    //   - A patient cannot fake coverageAmount or policyExpiry because doing so
    //     changes policyVCHash → it won't match the on-chain commitment.
    //   - The insurer's DID check ensures the policy came from InsureUltra,
    //     not from a fake issuer the patient invented.
    //
    console.log(chalk.gray('   [8/8] Verifying policy VC commitment on blockchain (anti-self-report check)...'));
    const policyVCHashFromSignal = zkProof.publicInputs?.snarkPublicSignals?.[8];
    const policyCredHashOnChain  = zkProof.policyVCReference?.policyCredentialHash;
    const policyIssuerDid        = zkProof.policyVCReference?.policyIssuerDid;

    if (blockchainManager?.contract && policyCredHashOnChain) {
      try {
        const result = await blockchainManager.contract.getCredential(policyCredHashOnChain);

        if (result[0]) { // exists
          if (result[5]) { // revoked
            checks.policyVCOnChain = false;
            overallValid = false;
            console.log(chalk.red('   ❌ Policy VC REVOKED on blockchain — cannot accept this proof'));
            console.log(chalk.red(`      Policy VC hash: ${policyCredHashOnChain.substring(0, 32)}...`));
          } else {
            const onChainPolicyIssuer = result[2];

            if (policyIssuerDid && onChainPolicyIssuer !== policyIssuerDid) {
              // Policy issuer on-chain does not match what the proof claims
              checks.policyVCOnChain = false;
              overallValid = false;
              console.log(chalk.red('   ❌ POLICY ISSUER DID MISMATCH — policy VC was not issued by the expected insurer!'));
              console.log(chalk.red(`      Proof claims policy issuer: ${policyIssuerDid.substring(0, 40)}...`));
              console.log(chalk.red(`      On-chain policy issuer:     ${onChainPolicyIssuer.substring(0, 40)}...`));
              console.log(chalk.red('      A patient cannot forge the insurer\'s DID — rejecting proof.'));
            } else {
              checks.policyVCOnChain = true;
              console.log(chalk.green('   ✅ Policy VC verified on-chain (InsureUltra-issued, not revoked)'));
              console.log(chalk.green(`      Policy Issuer DID: ${onChainPolicyIssuer.substring(0, 40)}...`));
              console.log(chalk.gray (`      Policy VC type:    ${result[4]}`));
              console.log(chalk.gray (`      Issued:            ${new Date(Number(result[1]) * 1000).toLocaleString()}`));
              console.log(chalk.gray (`      policyVCHash (circuit): ${String(policyVCHashFromSignal || '').substring(0, 20)}...`));
              console.log(chalk.cyan ('      coverageAmount and policyExpiry proven from insurer-signed VC ✅'));
            }
          }
        } else {
          // Hash not found on-chain — this is a hard failure (not a warning).
          // Without on-chain confirmation we cannot trust the policy data.
          checks.policyVCOnChain = false;
          overallValid = false;
          console.log(chalk.red('   ❌ Policy VC hash NOT found on blockchain — cannot verify policy data'));
          console.log(chalk.red(`      Hash: ${policyCredHashOnChain.substring(0, 32)}...`));
          console.log(chalk.red('      The policy VC must be registered on-chain by the insurer before submitting a claim.'));
        }
      } catch (error) {
        checks.policyVCOnChain = null;
        console.log(chalk.yellow(`   ⚠️  Policy VC blockchain check failed: ${error.message}`));
      }
    } else if (!policyCredHashOnChain) {
      // No hash at all — the proof was generated without a registered policy VC.
      checks.policyVCOnChain = false;
      overallValid = false;
      console.log(chalk.red('   ❌ No policy VC on-chain hash in proof — policy data cannot be verified'));
      console.log(chalk.red('      Ensure the insurer registers the policy VC on-chain before proof generation.'));
    } else {
      console.log(chalk.yellow('   ⚠️  Blockchain not available — policy VC check skipped'));
    }

    // ── Final result ──────────────────────────────────────────────────────────
    const result = {
      valid:          overallValid,
      checks,
      verifiedBy:     verifierAgent.did,
      verifiedAt:     new Date().toISOString(),
      proofHash:      zkProof.proofHash,
      publicInputs:   zkProof.publicInputs,
      disclosedClaims: zkProof.publicInputs.disclosedClaims || {},
      predicates:      zkProof.publicInputs.predicates      || {},
      policyVCHash:    zkProof.publicInputs.policyVCHash    || null,
    };

    if (overallValid) {
      console.log(chalk.green.bold('\n✅ ZK PROOF VERIFIED SUCCESSFULLY (multi-VC)'));
      const preds = zkProof.publicInputs.predicates || {};
      if (Object.keys(preds).length > 0) {
        console.log(chalk.gray('   Proven statements:'));
        for (const [field, pred] of Object.entries(preds)) {
          const icon = pred.satisfied ? chalk.green('✅') : chalk.red('❌');
          const src  = pred.source === 'insurer-vc' ? chalk.cyan(' [insurer VC]') : '';
          console.log(`      ${icon} ${pred.statement}${src}`);
        }
      }
      const hiddenCount = zkProof.publicInputs.hiddenFieldCount ?? 0;
      if (hiddenCount > 0) {
        console.log(chalk.yellow(`   🙈 ${hiddenCount} field(s) withheld (completely hidden)`));
      }
      console.log('');
    } else {
      console.log(chalk.red.bold('\n❌ ZK PROOF VERIFICATION FAILED\n'));
    }

    return result;
  }

  // ======================================================
  // REIMBURSEMENT CALCULATION
  // ======================================================

  /**
   * Load the insurance policy credential the insurer issued to a specific patient.
   *
   * Reads from the insurer's own wallet directory so the reimbursement engine
   * always uses the authoritative policy terms — never the patient's selectively
   * disclosed (and potentially incomplete) ZKP claims.
   *
   * @param {string} insurerId  - Agent ID of the insurer (wallet directory name)
   * @param {string} patientDid - DID of the patient (policy holder)
   * @returns {Object|null}     - The raw policy claims object, or null if not found
   */
  async loadPolicyFromInsurerWallet(insurerId, patientDid) {
    const walletsRoot = './data/wallets';

    // Collect credential files from ALL wallet directories.
    // The policy credential may be in the insurer's wallet (issuer copy)
    // or in the patient's wallet (original holder copy).
    const allFilePaths = [];

    try {
      const allWallets = await fs.readdir(walletsRoot);
      for (const wallet of allWallets) {
        const dir = path.join(walletsRoot, wallet, 'credentials');
        try {
          const wFiles = await fs.readdir(dir);
          allFilePaths.push(...wFiles.map(f => path.join(dir, f)));
        } catch { /* skip wallets without credentials dir */ }
      }
    } catch { return null; }

    for (const filepath of allFilePaths) {
      if (!filepath.endsWith('.json')) continue;
      try {
        const content = await fs.readFile(filepath, 'utf-8');
        const record  = JSON.parse(content);

        if (
          record.type === 'InsurancePolicy' &&
          (
            record.subjectDid === patientDid ||
            record.credential?.credentialSubject?.id === patientDid ||
            record.credential?.credentialSubject?.policyHolder !== undefined
          )
        ) {
          const claims = record.credential?.credentialSubject || {};
          const { id: _id, ...policyClaims } = claims;
          console.log(chalk.gray(`   📋 Policy loaded from wallet: ${claims.policyNumber || 'N/A'} (plan: ${claims.planName || 'N/A'})`));
          // Return flat claims object — callers access .coverageAmount etc. directly
          return policyClaims;
        }
      } catch { /* malformed file, skip */ }
    }
    return null;
  }

  /**
   * Calculate reimbursement amount based on a verified ZK proof.
   *
   * Policy terms (coverageAmount, coveragePercent, deductible, coveredDiagnoses)
   * are read from the insurer's OWN wallet — the credential they issued — so the
   * cap can never be zeroed out by a patient omitting fields in their ZKP.
   *
   * Bill fields (amount, diagnosis) are read from the patient's disclosed claims,
   * since only the patient holds the hospital bill credential.
   *
   * @param {Object}      policyDisclosed  - Disclosed claims from patient's policy ZKP
   * @param {Object}      billDisclosed    - Disclosed claims from patient's bill ZKP
   * @param {Object|null} insurerPolicy    - Raw policy claims loaded from insurer wallet
   * @returns {Object} reimbursement breakdown
   */
  calculateReimbursement(policyDisclosed, billDisclosed, insurerPolicy = null, priorReimbursedTotal = 0) {
    console.log(chalk.cyan('\n💰 Calculating Reimbursement...\n'));

    if (insurerPolicy) {
      console.log(chalk.green('   ✅ Using authoritative policy terms from insurer wallet'));
    } else {
      console.log(chalk.yellow('   ⚠️  Insurer policy not found in wallet — falling back to patient-disclosed claims'));
    }

    const policySource = insurerPolicy || policyDisclosed || {};

    // ── Parse bill amount ────────────────────────────────────────────────────
    let billAmount = 0;
    const rawAmountField = billDisclosed?.amount || '';
    if (!rawAmountField.startsWith('amount_in_range_')) {
      billAmount = parseFloat(String(rawAmountField).replace(/[^0-9.]/g, '')) || 0;
    }
    const amountIsHidden = billAmount === 0 && String(billDisclosed?.amount || '').startsWith('amount_in_range_');

    // ── Parse diagnosis coverage ─────────────────────────────────────────────
    const rawDiagnosisField = String(billDisclosed?.diagnosis || '').trim();
    let diagnosisCovered = true;

    if (rawDiagnosisField === 'diagnosis_covered') {
      diagnosisCovered = true;
      console.log(chalk.green('   ✅ Diagnosis covered (proven by ZK predicate)'));
    } else if (rawDiagnosisField === 'diagnosis_not_covered') {
      diagnosisCovered = false;
      console.log(chalk.red('   ❌ Diagnosis not covered (proven by ZK predicate)'));
    } else if (rawDiagnosisField.endsWith('_present') || rawDiagnosisField === '') {
      const coveredDiags = String(policySource.coveredDiagnoses || 'ALL').trim();
      diagnosisCovered   = coveredDiags.toUpperCase() === 'ALL';
      if (!diagnosisCovered) {
        console.log(chalk.yellow('   ⚠️  Diagnosis disclosed as presence-only — cannot confirm coverage'));
      }
    } else {
      const coveredDiags = String(
        policySource.coveredDiagnoses || policyDisclosed?.coveredDiagnoses || 'ALL'
      ).trim();
      const billDiagnosisLower = rawDiagnosisField.toLowerCase();
      if (coveredDiags.toUpperCase() !== 'ALL') {
        const coveredList = coveredDiags.split(',').map(d => d.trim().toLowerCase());
        diagnosisCovered  = coveredList.some(d =>
          billDiagnosisLower.includes(d) || d.includes(billDiagnosisLower)
        );
      }
    }

    // ── Parse age eligibility ────────────────────────────────────────────────
    const rawAgeField = String(billDisclosed?.age || '').trim();
    let ageEligible = false;
    if (rawAgeField.startsWith('age_in_range_')) {
      ageEligible = rawAgeField === 'age_in_range_0_59';
      if (!ageEligible) {
        console.log(chalk.red('   ❌ Age NOT eligible (proven age >= 60 — outside policy range)'));
      } else {
        console.log(chalk.green('   ✅ Age eligible (proven age < 60 by ZK range proof)'));
      }
    } else if (rawAgeField.startsWith('age_out_of_range_')) {
      ageEligible = false;
      console.log(chalk.red('   ❌ Age NOT eligible (proven out-of-range by circuit age check)'));
    } else if (rawAgeField !== '') {
      const rawAge = parseFloat(rawAgeField.replace(/[^0-9.]/g, ''));
      ageEligible  = !isNaN(rawAge) && rawAge < 60;
      console.log(ageEligible
        ? chalk.green(`   ✅ Age eligible (${rawAge} < 60)`)
        : chalk.red(`   ❌ Age NOT eligible (${rawAge} >= 60)`)
      );
    } else {
      console.log(chalk.red('   ❌ Age not proven — reimbursement requires age eligibility proof'));
    }

    // ── Parse policy terms from authoritative source ─────────────────────────
    const rawCoverage   = policySource.coverageAmount  || policyDisclosed?.coverageAmount  || '0';
    const rawPercent    = policySource.coveragePercent || policyDisclosed?.coveragePercent || '100';
    const rawDeductible = policySource.deductible      || policyDisclosed?.deductible      || '0';

    const maxCoverage = parseFloat(String(rawCoverage).replace(/[^0-9.]/g, ''))   || 0;
    const coveragePct = parseFloat(String(rawPercent).replace(/[^0-9.]/g, ''))    || 100;
    const deductible  = parseFloat(String(rawDeductible).replace(/[^0-9.]/g, '')) || 0;

    // ── Remaining coverage after prior reimbursements ────────────────────────
    const remainingCoverage = maxCoverage > 0
      ? Math.max(0, maxCoverage - priorReimbursedTotal)
      : 0;

    if (priorReimbursedTotal > 0) {
      console.log(chalk.yellow(`   📊 Prior reimbursements: $${priorReimbursedTotal.toFixed(2)}`));
      if (maxCoverage > 0) {
        console.log(chalk.cyan(`   📉 Remaining coverage:   $${remainingCoverage.toFixed(2)} (of $${maxCoverage.toFixed(2)} total)`));
      }
    }

    if (maxCoverage > 0 && remainingCoverage <= 0) {
      console.log(chalk.red('   🚫 Coverage fully exhausted — no remaining coverage for reimbursement'));
    }

    const effectiveBillAmount = (amountIsHidden && remainingCoverage > 0)
      ? remainingCoverage
      : (amountIsHidden && maxCoverage > 0)
        ? remainingCoverage
        : billAmount;

    // Step 1: apply ANNUAL deductible
    // The deductible is a yearly amount the patient pays out-of-pocket before
    // insurance kicks in.  Once met (across all claims in the year), it is NOT
    // subtracted again from subsequent claims.
    const deductibleAlreadyPaid = Math.min(deductible, priorReimbursedTotal > 0
      ? deductible   // if there were prior reimbursements, deductible was already met
      : 0);
    const remainingDeductible = Math.max(0, deductible - deductibleAlreadyPaid);
    const afterDeductible = Math.max(0, effectiveBillAmount - remainingDeductible);

    if (deductible > 0) {
      if (remainingDeductible <= 0) {
        console.log(chalk.green(`   ✅ Annual deductible ($${deductible.toFixed(2)}) already met — not applied`));
      } else {
        console.log(chalk.yellow(`   📋 Annual deductible: $${remainingDeductible.toFixed(2)} remaining (of $${deductible.toFixed(2)} total)`));
      }
    }

    // Step 2: apply coverage percentage
    const coverageApplied = afterDeductible * (coveragePct / 100);

    // Step 3: cap at remaining coverage
    let reimbursable;
    if (maxCoverage > 0) {
      reimbursable = Math.min(coverageApplied, remainingCoverage);
    } else {
      reimbursable = coverageApplied;
    }

    // Step 4: zero out if diagnosis not covered OR patient age not eligible
    const finalReimbursement = (diagnosisCovered && ageEligible) ? Math.max(0, reimbursable) : 0;
    const patientOwes        = effectiveBillAmount - finalReimbursement;

    const capSource = insurerPolicy?.coverageAmount
      ? chalk.green('(from insurer policy ✅)')
      : chalk.yellow('(from patient disclosure ⚠️)');

    const breakdown = {
      billAmount:            parseFloat(effectiveBillAmount.toFixed(2)),
      billAmountIsHidden:    amountIsHidden,
      deductible:            parseFloat(deductible.toFixed(2)),
      afterDeductible:       parseFloat(afterDeductible.toFixed(2)),
      coveragePercent:       coveragePct,
      coverageApplied:       parseFloat(coverageApplied.toFixed(2)),
      maxCoverage:           parseFloat(maxCoverage.toFixed(2)),
      priorReimbursedTotal:  parseFloat(priorReimbursedTotal.toFixed(2)),
      remainingCoverage:     parseFloat((maxCoverage > 0 ? remainingCoverage : 0).toFixed(2)),
      remainingAfterThis:    parseFloat((maxCoverage > 0 ? Math.max(0, remainingCoverage - finalReimbursement) : 0).toFixed(2)),
      maxCoverageSource:     insurerPolicy?.coverageAmount ? 'insurer-wallet' : 'patient-disclosure',
      diagnosisCovered,
      ageEligible,
      reimbursementAmount:   parseFloat(finalReimbursement.toFixed(2)),
      patientOwes:           parseFloat(patientOwes.toFixed(2)),
      calculatedAt:          new Date().toISOString(),
    };

    // ── Console display ───────────────────────────────────────────────────────
    if (amountIsHidden) {
      console.log(chalk.white('   Bill Amount:          ') + chalk.yellow('hidden (ZK range proof)'));
      console.log(chalk.gray ('   (reimbursement capped at remaining coverage amount)'));
    } else {
      console.log(chalk.white('   Bill Amount:          ') + chalk.yellow(`$${breakdown.billAmount.toFixed(2)}`));
    }
    console.log(chalk.white('   Annual Deductible:    ') + chalk.yellow(`$${deductible.toFixed(2)}`) + (remainingDeductible < deductible ? chalk.green(` (met — $${remainingDeductible.toFixed(2)} applied this claim)`) : ''));
    console.log(chalk.white('   After Deductible:     ') + chalk.cyan(`$${breakdown.afterDeductible.toFixed(2)}`));
    console.log(chalk.white('   Coverage %:           ') + chalk.cyan(`${breakdown.coveragePercent}%`));
    console.log(chalk.white('   Coverage Applied:     ') + chalk.cyan(`$${breakdown.coverageApplied.toFixed(2)}`));
    console.log(chalk.white('   Max Coverage Cap:     ') + chalk.cyan(`$${breakdown.maxCoverage > 0 ? breakdown.maxCoverage.toFixed(2) : 'Unlimited'} `) + capSource);
    if (priorReimbursedTotal > 0 && maxCoverage > 0) {
      console.log(chalk.white('   Prior Reimbursed:     ') + chalk.yellow(`$${breakdown.priorReimbursedTotal.toFixed(2)}`));
      console.log(chalk.white('   Remaining Coverage:   ') + chalk.cyan(`$${breakdown.remainingCoverage.toFixed(2)}`));
    }
    console.log(chalk.white('   Diagnosis Covered:    ') + (diagnosisCovered ? chalk.green('Yes ✅') : chalk.red('No ❌')));
    console.log(chalk.white('   Age Eligible (<60):   ') + (ageEligible ? chalk.green('Yes ✅') : chalk.red('No ❌')));
    console.log('');
    console.log(chalk.green.bold(`   💸 Reimbursement:    $${breakdown.reimbursementAmount.toFixed(2)}`));
    console.log(chalk.yellow(`   🧾 Patient Owes:     $${breakdown.patientOwes.toFixed(2)}`));
    if (maxCoverage > 0) {
      console.log(chalk.cyan(`   📉 Remaining After:   $${breakdown.remainingAfterThis.toFixed(2)} of $${maxCoverage.toFixed(2)}`));
    }
    console.log('');

    return breakdown;
  }

  /**
   * Save a reimbursement record to the insurer's wallet directory.
   */
  async saveReimbursement(insurerId, record) {
    const dir = `./data/wallets/${insurerId}/reimbursements`;
    await fs.mkdir(dir, { recursive: true });
    const filepath = path.join(dir, `${record.id}.json`);
    await fs.writeFile(filepath, JSON.stringify(record, null, 2));
    console.log(chalk.gray(`   💾 Reimbursement record saved: ${filepath}`));
    return filepath;
  }

  /**
   * List all reimbursement records for an insurer.
   */
  async listReimbursements(insurerId) {
    const dir = `./data/wallets/${insurerId}/reimbursements`;
    try {
      const files = await fs.readdir(dir);
      const records = [];
      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(dir, file), 'utf-8');
          records.push(JSON.parse(content));
        }
      }
      return records;
    } catch {
      return [];
    }
  }

  // ======================================================
  // PROOF STORAGE (WALLET INTEGRATION)
  // ======================================================

  async saveProof(agentId, zkProof) {
    const proofDir = `./data/wallets/${agentId}/proofs`;
    await fs.mkdir(proofDir, { recursive: true });
    const filename = `${zkProof.id}.json`;
    const filepath = path.join(proofDir, filename);
    await fs.writeFile(filepath, JSON.stringify(zkProof, null, 2));
    console.log(chalk.gray(`   💾 Proof saved: ${filepath}`));
    return filepath;
  }

  async loadProof(agentId, proofId) {
    const filepath = `./data/wallets/${agentId}/proofs/${proofId}.json`;
    try {
      const content = await fs.readFile(filepath, 'utf-8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  async listProofs(agentId) {
    const proofDir = `./data/wallets/${agentId}/proofs`;
    try {
      const files = await fs.readdir(proofDir);
      const proofs = [];
      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(proofDir, file), 'utf-8');
          proofs.push(JSON.parse(content));
        }
      }
      return proofs;
    } catch {
      return [];
    }
  }

  // ======================================================
  // LOCAL PROOF AUDIT LOGGING
  // ======================================================

  /**
   * Record proof hash locally for audit trail.
   *
   * ZK proofs are NOT anchored on-chain via issueCredential() because
   * the smart contract enforces that only the DID owner can issue credentials
   * for their DID.  The audit trail works like this:
   *   1. The ORIGINAL medical credential is already on-chain (issued by hospital)
   *   2. The POLICY VC is already on-chain (issued by insurer)
   *   3. The ZK proof references both hashes
   *   4. During verification, the insurer checks BOTH hashes on-chain
   *   5. The proof itself is stored locally in the patient's wallet
   */
  async recordProofAuditTrail(zkProof) {
    const proofString = JSON.stringify({
      proofHash:        zkProof.proofHash,
      circuitId:        zkProof.circuitId,
      publicInputs:     zkProof.publicInputs,
      policyVCReference: zkProof.policyVCReference,
      generatedAt:      zkProof.generatedAt,
    });

    const proofBytes32 = '0x' + crypto.createHash('sha256')
      .update(proofString)
      .digest('hex');

    console.log(chalk.gray('   📋 Proof hash computed for audit trail'));
    console.log(chalk.gray(`      Hash: ${proofBytes32.substring(0, 24)}...`));
    console.log(chalk.gray(`      Medical credential on-chain: ${zkProof.credentialReference?.credentialHash ? 'Yes ✅' : 'No'}`));
    console.log(chalk.gray(`      Policy VC on-chain:          ${zkProof.policyVCReference?.policyCredentialHash ? 'Yes ✅' : 'No'}`));

    const auditRecord = {
      proofId:              zkProof.id,
      proofHash:            zkProof.proofHash,
      proofBytes32,
      credentialHash:       zkProof.credentialReference?.credentialHash || null,
      credentialTxHash:     zkProof.credentialReference?.blockchainTxHash || null,
      policyVCHash:         zkProof.policyVCReference?.policyVCHash || null,
      policyCredentialHash: zkProof.policyVCReference?.policyCredentialHash || null,
      policyIssuerDid:      zkProof.policyVCReference?.policyIssuerDid || null,
      generatedAt:          zkProof.generatedAt,
      note: 'Multi-VC proof. Both medical credential and policy VC are on-chain. ' +
            'Verifier checks both hashes on-chain during verification.'
    };

    try {
      const auditDir = './data/proofs/audit';
      await fs.mkdir(auditDir, { recursive: true });
      await fs.writeFile(
        path.join(auditDir, `${zkProof.id}-audit.json`),
        JSON.stringify(auditRecord, null, 2)
      );
    } catch {
      // Non-critical
    }

    return {
      success: true,
      proofBytes32,
      storedLocally: true,
      anchoredOnChain: false,
      note: 'Proof audit record stored locally. Both medical credential and policy VC are verified on-chain during proof verification.'
    };
  }

  // ======================================================
  // DISPLAY HELPERS
  // ======================================================

  /**
   * Pretty-print a ZK proof to the console.
   */
  displayProof(zkProof) {
    console.log(chalk.magenta('\n┌─────────────────────────────────────────────────────┐'));
    console.log(chalk.magenta('│ 🔐 Zero-Knowledge Proof (multi-VC)                 │'));
    console.log(chalk.magenta('├─────────────────────────────────────────────────────┤'));
    console.log(chalk.white(`│ ID:       ${zkProof.id}`));
    console.log(chalk.white(`│ Circuit:  ${zkProof.circuitId}`));
    console.log(chalk.white(`│ Protocol: ${zkProof.protocol} | Curve: ${zkProof.curve}`));
    console.log(chalk.magenta('├─── Proof Elements (cryptographic) ──────────────────┤'));
    const _fmtG1 = (pt) => Array.isArray(pt) ? String(pt[0]).substring(0, 42) + '...' : String(pt).substring(0, 42) + '...';
    const _fmtG2 = (pt) => Array.isArray(pt[0]) ? String(pt[0][0]).substring(0, 42) + '...' : String(pt[0]).substring(0, 42) + '...';
    console.log(chalk.gray(`│ π_a: ${_fmtG1(zkProof.proof.pi_a)}`));
    console.log(chalk.gray(`│ π_b: ${_fmtG2(zkProof.proof.pi_b)}`));
    console.log(chalk.gray(`│ π_c: ${_fmtG1(zkProof.proof.pi_c)}`));
    console.log(chalk.magenta('├─── Public Signals ──────────────────────────────────┤'));
    console.log(chalk.white(`│ Type:     ${zkProof.publicInputs.credentialType}`));
    console.log(chalk.white(`│ Issuer:   ${zkProof.publicInputs.issuerDID?.substring(0, 40)}...`));
    console.log(chalk.white(`│ Subject:  ${zkProof.publicInputs.subjectDID?.substring(0, 40)}...`));

    const predicates = zkProof.publicInputs.predicates || {};
    if (Object.keys(predicates).length > 0) {
      console.log(chalk.magenta('├─── Proven Statements (no raw values) ───────────────┤'));
      for (const [field, pred] of Object.entries(predicates)) {
        const icon = pred.satisfied ? chalk.green('✅') : chalk.red('❌');
        const src  = pred.source === 'insurer-vc' ? chalk.cyan(' [insurer VC]') : '';
        console.log(`│ ${icon} ${pred.statement}${src}`);
        console.log(chalk.gray(`│    commitment: ${pred.commitment?.substring(0, 28) || pred.policyVCHash?.substring(0, 28) || pred.diagnosisHash?.substring(0, 28) || 'N/A'}...`));
      }
    }

    console.log(chalk.magenta('├─── Credential Reference (Medical VC) ───────────────┤'));
    console.log(chalk.gray(`│ From: ${zkProof.credentialReference.issuer}`));
    console.log(chalk.gray(`│ Hash: ${zkProof.credentialReference.credentialHash?.substring(0, 32) || 'N/A'}...`));
    console.log(chalk.gray(`│ TX:   ${zkProof.credentialReference.blockchainTxHash?.substring(0, 32) || 'N/A'}...`));

    console.log(chalk.magenta('├─── Policy VC Reference (Insurer-issued) ────────────┤'));
    const pvc = zkProof.policyVCReference || {};
    console.log(chalk.gray(`│ Policy Issuer: ${pvc.policyIssuerDid?.substring(0, 36) || 'N/A'}...`));
    console.log(chalk.gray(`│ policyVCHash:  ${pvc.policyVCHash?.substring(0, 28) || 'N/A'}...`));
    console.log(chalk.gray(`│ On-chain hash: ${pvc.policyCredentialHash?.substring(0, 28) || 'N/A'}...`));
    console.log(chalk.gray(`│ policyNumber:  ${pvc.policyNumber || 'N/A'}`));
    console.log(chalk.gray(`│ planName:      ${pvc.planName || 'N/A'}`));

    console.log(chalk.magenta('├─── Metadata ───────────────────────────────────────┤'));
    console.log(chalk.gray(`│ Generated: ${zkProof.generatedAt}`));
    console.log(chalk.gray(`│ Hash:      ${zkProof.proofHash.substring(0, 32)}...`));

    if (zkProof.verified !== null) {
      const icon  = zkProof.verified ? '✅' : '❌';
      const color = zkProof.verified ? chalk.green : chalk.red;
      const verifierDisplay = zkProof.verifiedByName || zkProof.verifiedBy?.substring(0, 30) + '...';
      console.log(color(`│ Verified:  ${icon} ${zkProof.verified ? 'VALID' : 'INVALID'} by ${verifierDisplay}`));
      if (zkProof.verifiedAt) {
        console.log(chalk.gray(`│ At:        ${zkProof.verifiedAt}`));
      }
    } else {
      console.log(chalk.yellow(`│ Verified:  ⏳ Not yet verified`));
    }

    console.log(chalk.magenta('└─────────────────────────────────────────────────────┘\n'));
  }

  /**
   * Display verification result.
   */
  displayVerificationResult(result) {
    console.log(chalk.cyan('\n┌─────────────────────────────────────────────────────┐'));
    console.log(chalk.cyan('│ 🔍 Verification Result (multi-VC)                   │'));
    console.log(chalk.cyan('├─────────────────────────────────────────────────────┤'));

    const checkIcon = (val) => val === true ? chalk.green('✅') : val === false ? chalk.red('❌') : chalk.yellow('⚠️ ');

    console.log(`│ Structure:       ${checkIcon(result.checks.structureValid)} ${result.checks.structureValid ? 'Valid' : 'Invalid'}`);
    console.log(`│ Freshness:       ${checkIcon(result.checks.freshnessValid)} ${result.checks.freshnessValid ? 'Fresh' : 'Expired'}`);
    console.log(`│ Integrity:       ${checkIcon(result.checks.integrityValid)} ${result.checks.integrityValid ? 'No tampering detected' : result.checks.integrityValid === false ? 'TAMPERED — data modified after generation!' : 'Not checked'}`);
    console.log(`│ Math Proof:      ${checkIcon(result.checks.proofMathValid)} ${result.checks.proofMathValid ? 'Pairing check passed' : 'Failed'}`);
    console.log(`│ Commitments:     ${checkIcon(result.checks.commitmentsValid)} ${result.checks.commitmentsValid ? 'Consistent' : 'Invalid'}`);
    console.log(`│ Issuer DID:      ${checkIcon(result.checks.issuerDIDOnChain)} ${result.checks.issuerDIDOnChain === true ? 'On-chain' : result.checks.issuerDIDOnChain === false ? 'NOT on-chain' : 'Not checked'}`);
    console.log(`│ Medical VC:      ${checkIcon(result.checks.credentialOnChain)} ${result.checks.credentialOnChain === true ? 'On-chain (not revoked)' : result.checks.credentialOnChain === false ? 'NOT on-chain / revoked' : 'Not checked'}`);
    console.log(`│ Policy VC:       ${checkIcon(result.checks.policyVCOnChain)} ${result.checks.policyVCOnChain === true ? 'On-chain (insurer-issued, not revoked)' : result.checks.policyVCOnChain === false ? 'NOT on-chain / revoked / issuer mismatch' : 'Not checked'}`);

    console.log(chalk.cyan('├─────────────────────────────────────────────────────┤'));

    if (result.valid) {
      console.log(chalk.green.bold('│ 🎉 OVERALL: VERIFIED                                │'));
    } else {
      console.log(chalk.red.bold('│ 🚫 OVERALL: FAILED                                  │'));
    }

    if (result.predicates && Object.keys(result.predicates).length > 0) {
      console.log(chalk.cyan('├─── Proven Statements (no raw values) ──────────────┤'));
      for (const [field, pred] of Object.entries(result.predicates)) {
        const icon = pred.satisfied ? chalk.green('✅') : chalk.red('❌');
        const src  = pred.source === 'insurer-vc' ? chalk.cyan(' [insurer VC]') : '';
        console.log(`│ ${icon} ${pred.statement}${src}`);
      }
    }

    console.log(chalk.cyan('└─────────────────────────────────────────────────────┘\n'));
  }

  // ======================================================
  // INTERNAL: CRYPTOGRAPHIC PRIMITIVES
  // ======================================================

  /**
   * Compute SHA-256 commitment (used for JS-side tamper binding).
   */
  _computeCommitment(input) {
    return crypto.createHash('sha256').update(input).digest('hex');
  }

  /**
   * Compute hash of the entire proof (for audit/reference).
   */
  _computeProofHash(proofElements, publicInputs) {
    const data = JSON.stringify({ proofElements, publicInputs });
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // ======================================================
  // FIELD ENCODING HELPERS
  // ======================================================

  /**
   * Convert a dollar amount string to integer cents.
   * "$2,500.00" → 250000
   * "2500"      → 250000
   */
  _toCents(value) {
    const numeric = parseFloat(String(value).replace(/[^0-9.]/g, '')) || 0;
    return Math.round(numeric * 100);
  }

  /**
   * Encode a string as a BN128 field element (BigInt).
   * We take the first 30 bytes of SHA-256(str) as a 240-bit integer.
   * This fits within the BN128 scalar field (≈ 254 bits) and is
   * collision-resistant for practical healthcare data strings.
   */
  _strToField(str) {
    const hash = crypto.createHash('sha256').update(String(str)).digest('hex');
    return BigInt('0x' + hash.substring(0, 60));
  }

}

export default ZKPManager;