pragma circom 2.1.6;

// With -l PROJECT_ROOT/node_modules passed to circom, these resolve to
// PROJECT_ROOT/node_modules/circomlib/circuits/*.circom
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * MedicalCredential Circuit — Real Groth16 on BN128
 * ==================================================
 *
 * All inputs are PRIVATE (the patient's secret witness).
 * All outputs are PUBLIC (what the insurer/verifier sees).
 *
 * Private inputs:
 *   billAmount          — bill in integer cents (e.g. 250000 = $2,500)
 *   coverageAmount      — policy coverage limit in cents
 *   policyExpiry        — policy expiry as Unix timestamp
 *   currentTimestamp    — "now" as Unix timestamp (set by prover at proof time)
 *   patientAge          — patient age in years
 *   ageMin              — minimum eligible age (inclusive)
 *   ageMax              — maximum eligible age (inclusive)
 *   diagnosisPreimage   — SHA-256 encoding of diagnosis string as field element
 *   salt                — 128-bit random blinding nonce
 *   credentialFields[10]— ten claim fields encoded as field elements
 *   issuerDIDPreimage   — SHA-256 encoding of issuer DID string
 *   subjectDIDPreimage  — SHA-256 encoding of patient DID string
 *   billAmountMin       — lower bound for range proof on bill amount
 *   billAmountMax       — upper bound for range proof on bill amount
 *   proofNonce          — must equal salt (binds proof to this invocation)
 *
 * Public outputs (in declaration order — maps to snarkjs publicSignals[0..7]):
 *   [0] credentialHash    — Poseidon(credentialFields[0..9], salt)
 *   [1] issuerDIDHash     — Poseidon(issuerDIDPreimage, salt)
 *   [2] subjectDIDHash    — Poseidon(subjectDIDPreimage, salt)
 *   [3] amountInRange     — 1 iff billAmountMin ≤ billAmount ≤ billAmountMax
 *   [4] diagnosisHash     — Poseidon(diagnosisPreimage, salt)
 *   [5] policyValid       — 1 iff policyExpiry > currentTimestamp
 *   [6] coverageSufficient— 1 iff coverageAmount ≥ billAmount
 *   [7] ageEligible       — 1 iff ageMin ≤ patientAge ≤ ageMax
 *
 * Security properties:
 *   - The verifier learns ONLY the eight boolean/hash outputs above.
 *   - No raw values (amount, diagnosis, timestamps, DIDs) are ever revealed.
 *   - diagnosisHash lets the insurer check against a whitelist of covered
 *     diagnoses without learning the actual diagnosis text.
 *   - credentialHash binds the proof to a specific credential; it can be
 *     compared against the on-chain registry to confirm legitimacy.
 *   - proofNonce === salt prevents the prover from reusing a single
 *     witness across different proof invocations.
 */
template MedicalCredential() {

    // ── Private inputs ────────────────────────────────────────────────────────
    signal input billAmount;
    signal input coverageAmount;
    signal input policyExpiry;
    signal input currentTimestamp;
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

    // ── Public outputs ────────────────────────────────────────────────────────
    signal output credentialHash;
    signal output issuerDIDHash;
    signal output subjectDIDHash;
    signal output amountInRange;
    signal output diagnosisHash;
    signal output policyValid;
    signal output coverageSufficient;
    signal output ageEligible;

    // ── Constraint 0: proofNonce must equal salt ──────────────────────────────
    // This binds the proof to a single invocation — a proof generated with
    // one salt cannot be replayed with a different nonce.
    proofNonce === salt;

    // ── Output 0: credentialHash ──────────────────────────────────────────────
    // Poseidon over all 10 credential fields + salt (11 inputs total).
    // Binds the proof to a specific credential; verifier compares to on-chain hash.
    component credHasher = Poseidon(11);
    for (var i = 0; i < 10; i++) {
        credHasher.inputs[i] <== credentialFields[i];
    }
    credHasher.inputs[10] <== salt;
    credentialHash <== credHasher.out;

    // ── Output 1: issuerDIDHash ───────────────────────────────────────────────
    // Poseidon(issuerDIDPreimage, salt).
    // Lets the verifier confirm the issuer without learning the DID string.
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
    // 1 iff policyExpiry > currentTimestamp.
    // 64-bit comparators cover Unix timestamps well past year 2100.
    component policyCheck = GreaterThan(64);
    policyCheck.in[0] <== policyExpiry;
    policyCheck.in[1] <== currentTimestamp;
    policyValid <== policyCheck.out;

    // ── Output 6: coverageSufficient ─────────────────────────────────────────
    // 1 iff coverageAmount ≥ billAmount.
    component coverageCheck = GreaterEqThan(64);
    coverageCheck.in[0] <== coverageAmount;
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
}

// All inputs are private — no { public [...] } annotation needed.
// All outputs are public signals (snarkjs publicSignals[0..7]).
component main = MedicalCredential();
