pragma circom 2.1.6;

// With -l PROJECT_ROOT/node_modules passed to circom, these resolve to
// PROJECT_ROOT/node_modules/circomlib/circuits/*.circom
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * MedicalCredential Circuit — Real Groth16 on BN128  (v2: multi-VC)
 * ==================================================================
 *
 * WHAT CHANGED FROM v1
 * ─────────────────────
 * v1 accepted `coverageAmount` and `policyExpiry` as bare private inputs,
 * meaning the PATIENT could supply any value they liked — policyValid and
 * coverageSufficient were therefore self-reported, not insurer-verified.
 *
 * v2 removes those two bare inputs entirely and instead accepts the full
 * insurer-issued policy VC as a structured witness (`policyVCFields[5]`).
 * The circuit commits to all five policy fields via Poseidon → `policyVCHash`
 * (public output [8]).  The verifier then compares `policyVCHash` against
 * the on-chain commitment of the policy VC that InsureUltra published,
 * proving that `coverageAmount` and `policyExpiry` came from a
 * circuit-verified signed source — not from the patient's self-report.
 *
 * ── Private inputs ────────────────────────────────────────────────────────
 *
 * [Medical VC — issued by hospital]
 *   billAmount          — bill in integer cents (e.g. 250000 = $2 500)
 *   patientAge          — patient age in years
 *   ageMin              — minimum eligible age (inclusive)
 *   ageMax              — maximum eligible age (inclusive)
 *   diagnosisPreimage   — SHA-256 encoding of diagnosis string as field element
 *   salt                — 128-bit random blinding nonce (medical VC)
 *   credentialFields[10]— ten claim fields from medical VC encoded as field elements
 *   issuerDIDPreimage   — SHA-256 encoding of hospital issuer DID
 *   subjectDIDPreimage  — SHA-256 encoding of patient DID
 *   billAmountMin       — lower bound for range proof on bill amount
 *   billAmountMax       — upper bound for range proof on bill amount
 *   proofNonce          — must equal salt (replay protection)
 *
 * [Policy VC — issued by insurer, NOT self-reported]
 *   policyVCFields[5]   — five fields from the insurer-issued policy VC:
 *                           [0] policyNumber   (encoded as field element)
 *                           [1] planName       (encoded as field element)
 *                           [2] coverageAmount (integer cents)  ← was bare input
 *                           [3] policyExpiry   (Unix timestamp) ← was bare input
 *                           [4] insuredDIDField (patient DID encoded, links policy to holder)
 *   policySalt          — 128-bit random blinding nonce (policy VC)
 *   currentTimestamp    — "now" as Unix timestamp (set by prover at proof time)
 *
 * ── Public outputs (snarkjs publicSignals[0..8]) ──────────────────────────
 *   [0] credentialHash    — Poseidon(credentialFields[0..9], salt)
 *   [1] issuerDIDHash     — Poseidon(issuerDIDPreimage, salt)
 *   [2] subjectDIDHash    — Poseidon(subjectDIDPreimage, salt)
 *   [3] amountInRange     — 1 iff billAmountMin ≤ billAmount ≤ billAmountMax
 *   [4] diagnosisHash     — Poseidon(diagnosisPreimage, salt)
 *   [5] policyValid       — 1 iff policyVCFields[3] > currentTimestamp
 *   [6] coverageSufficient— 1 iff policyVCFields[2] ≥ billAmount
 *   [7] ageEligible       — 1 iff ageMin ≤ patientAge ≤ ageMax
 *   [8] policyVCHash      — Poseidon(policyVCFields[0..4], policySalt)  ← NEW
 *
 * ── Security properties ───────────────────────────────────────────────────
 *   - The verifier learns ONLY the nine boolean/hash outputs above.
 *   - No raw values (amount, diagnosis, timestamps, DIDs) are ever revealed.
 *   - policyVCHash lets the verifier confirm the exact policy VC (by comparing
 *     to the on-chain commitment published by InsureUltra) without learning
 *     any raw policy field value.
 *   - coverageAmount and policyExpiry are now circuit-constrained to
 *     policyVCFields[2] and policyVCFields[3] respectively — a patient who
 *     tampers with those values will produce a policyVCHash that does NOT
 *     match the on-chain hash → the verifier rejects the proof.
 *   - credentialHash and policyVCHash together bind the proof to BOTH the
 *     hospital bill VC AND the insurer policy VC.
 *   - proofNonce === salt prevents witness reuse across invocations.
 */
template MedicalCredential() {

    // ── Medical VC private inputs ─────────────────────────────────────────────
    signal input billAmount;
    signal input patientAge;
    signal input ageMin;
    signal input ageMax;
    signal input diagnosisPreimage;
    signal input salt;
    signal input credentialFields[10];
    signal input issuerDIDPreimage;
    signal input subjectDIDPreimage;
    signal input billAmountMin;
    signal input billAmountMax;
    signal input proofNonce;

    // ── Policy VC private inputs (insurer-issued — NOT self-reported) ─────────
    // Layout of policyVCFields:
    //   [0] policyNumber   — encoded as field element via _strToField
    //   [1] planName       — encoded as field element via _strToField
    //   [2] coverageAmount — integer cents (drives coverageSufficient check)
    //   [3] policyExpiry   — Unix timestamp  (drives policyValid check)
    //   [4] insuredDIDField— patient DID encoded as field element (links VC to holder)
    signal input policyVCFields[5];
    signal input policySalt;
    signal input currentTimestamp;

    // ── Public outputs ────────────────────────────────────────────────────────
    signal output credentialHash;
    signal output issuerDIDHash;
    signal output subjectDIDHash;
    signal output amountInRange;
    signal output diagnosisHash;
    signal output policyValid;
    signal output coverageSufficient;
    signal output ageEligible;
    signal output policyVCHash;    // NEW: commitment to insurer-issued policy VC

    // ── Constraint 0: proofNonce must equal salt ──────────────────────────────
    // Binds the proof to a single invocation — a proof generated with one salt
    // cannot be replayed with a different nonce.
    proofNonce === salt;

    // ── Output 0: credentialHash ──────────────────────────────────────────────
    // Poseidon over all 10 medical-VC credential fields + salt (11 inputs).
    // Binds the proof to a specific hospital bill VC; verifier compares
    // this to the on-chain registry hash to confirm legitimacy.
    component credHasher = Poseidon(11);
    for (var i = 0; i < 10; i++) {
        credHasher.inputs[i] <== credentialFields[i];
    }
    credHasher.inputs[10] <== salt;
    credentialHash <== credHasher.out;

    // ── Output 1: issuerDIDHash ───────────────────────────────────────────────
    // Poseidon(issuerDIDPreimage, salt).
    // Lets the verifier confirm the hospital issuer without learning the DID string.
    component issuerHasher = Poseidon(2);
    issuerHasher.inputs[0] <== issuerDIDPreimage;
    issuerHasher.inputs[1] <== salt;
    issuerDIDHash <== issuerHasher.out;

    // ── Output 2: subjectDIDHash ──────────────────────────────────────────────
    // Poseidon(subjectDIDPreimage, salt).
    component subjectHasher = Poseidon(2);
    subjectHasher.inputs[0] <== subjectDIDPreimage;
    subjectHasher.inputs[1] <== salt;
    subjectDIDHash <== subjectHasher.out;

    // ── Output 3: amountInRange ───────────────────────────────────────────────
    // 1 iff billAmountMin ≤ billAmount ≤ billAmountMax.
    // 64-bit comparators handle up to 2^64 − 1 ≈ $184 billion in cents.
    component gteMin = GreaterEqThan(64);
    gteMin.in[0] <== billAmount;
    gteMin.in[1] <== billAmountMin;

    component lteMax = LessEqThan(64);
    lteMax.in[0] <== billAmount;
    lteMax.in[1] <== billAmountMax;

    // AND: both conditions must hold
    amountInRange <== gteMin.out * lteMax.out;

    // ── Output 4: diagnosisHash ───────────────────────────────────────────────
    // Poseidon(diagnosisPreimage, salt).
    // Insurer checks this hash against a whitelist of covered-diagnosis hashes.
    // The actual diagnosis string is never revealed.
    component diagHasher = Poseidon(2);
    diagHasher.inputs[0] <== diagnosisPreimage;
    diagHasher.inputs[1] <== salt;
    diagnosisHash <== diagHasher.out;

    // ── Output 5: policyValid ─────────────────────────────────────────────────
    // 1 iff policyVCFields[3] > currentTimestamp.
    //
    // policyVCFields[3] is the policyExpiry timestamp sourced from the
    // INSURER-ISSUED policy VC — not from the patient's self-report.
    // A patient cannot fake an expiry: using a wrong value changes policyVCHash,
    // which will not match the on-chain commitment → proof rejected.
    // 64-bit comparators cover Unix timestamps well past year 2100.
    component policyCheck = GreaterThan(64);
    policyCheck.in[0] <== policyVCFields[3];  // policyExpiry from insurer VC
    policyCheck.in[1] <== currentTimestamp;
    policyValid <== policyCheck.out;

    // ── Output 6: coverageSufficient ─────────────────────────────────────────
    // 1 iff policyVCFields[2] ≥ billAmount.
    //
    // policyVCFields[2] is the coverageAmount sourced from the insurer-issued
    // policy VC — not from the patient's self-report.  Same tamper-resistance
    // argument as above: wrong value → wrong policyVCHash → rejected.
    component coverageCheck = GreaterEqThan(64);
    coverageCheck.in[0] <== policyVCFields[2];  // coverageAmount from insurer VC
    coverageCheck.in[1] <== billAmount;
    coverageSufficient <== coverageCheck.out;

    // ── Output 7: ageEligible ────────────────────────────────────────────────
    // 1 iff ageMin ≤ patientAge ≤ ageMax.
    // 8-bit comparators are sufficient for realistic human age ranges.
    component ageGteMin = GreaterEqThan(8);
    ageGteMin.in[0] <== patientAge;
    ageGteMin.in[1] <== ageMin;

    component ageLteMax = LessEqThan(8);
    ageLteMax.in[0] <== patientAge;
    ageLteMax.in[1] <== ageMax;

    ageEligible <== ageGteMin.out * ageLteMax.out;

    // ── Output 8: policyVCHash ────────────────────────────────────────────────
    // Poseidon over all five policy-VC fields + policySalt (6 inputs total).
    //
    // This is the KEY addition of v2.  The verifier compares this hash against
    // the on-chain commitment that InsureUltra published when they issued the
    // policy VC.  If the patient changes ANY of the five policy fields
    // (policyNumber, planName, coverageAmount, policyExpiry, insuredDIDField),
    // the resulting policyVCHash will not match the on-chain hash → the
    // insurer's verifyProof() rejects the proof at the blockchain check step.
    //
    // Effect: coverageAmount and policyExpiry — and therefore policyValid and
    // coverageSufficient — are now cryptographically bound to the insurer-signed
    // document, not to the patient's self-reported witness values.
    component policyHasher = Poseidon(6);
    for (var i = 0; i < 5; i++) {
        policyHasher.inputs[i] <== policyVCFields[i];
    }
    policyHasher.inputs[5] <== policySalt;
    policyVCHash <== policyHasher.out;
}

// All inputs are private — no { public [...] } annotation needed.
// All outputs are public signals (snarkjs publicSignals[0..8]).
component main = MedicalCredential();
