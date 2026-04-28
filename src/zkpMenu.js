import chalk from 'chalk';
import inquirer from 'inquirer';

// Inquirer adds error/close listeners on every prompt call.
// In a long-running CLI loop this exceeds Node's default limit of 10.
// Setting to 0 disables the warning entirely (unlimited listeners).
process.stdout.setMaxListeners(0);
process.stderr.setMaxListeners(0);
process.stdin.setMaxListeners(0);

/**
 * ====================================================================
 * ZKP MENU - CLI Menu Items for Zero-Knowledge Proof Operations
 * ====================================================================
 * 
 * This module provides the inquirer menu handlers for ZKP operations.
 * 
 * HOW TO INTEGRATE INTO YOUR EXISTING index.js:
 * 
 *   1. Import this module:
 *      import { addZKPMenuItems, handleZKPAction } from './zkpMenu.js';
 *   
 *   2. Add ZKP choices to your main menu:
 *      const choices = [
 *        ...existingChoices,
 *        new inquirer.Separator('═══ ZERO-KNOWLEDGE PROOFS ═══'),
 *        ...addZKPMenuItems(),
 *      ];
 *   
 *   3. In your action handler switch statement, add:
 *      case 'zkp-request':
 *      case 'zkp-generate':
 *      case 'zkp-submit':
 *      case 'zkp-verify':
 *      case 'zkp-list':
 *      case 'zkp-received':
 *        await handleZKPAction(action, agentManager);
 *        break;
 * ====================================================================
 */

// ======================================================
// MENU ITEMS (add to existing inquirer choices)
// ======================================================

export function addZKPMenuItems() {
  return [
    { name: '🔐  Generate ZK Proof (Patient)', value: 'zkp-generate' },
    { name: '📤  Submit ZK Proof to Verifier', value: 'zkp-submit' },
    { name: '🔍  Verify ZK Proof + Calculate Reimbursement (Insurer)', value: 'zkp-verify' },
    { name: '📋  List My ZK Proofs', value: 'zkp-list' },
    { name: '📥  List Received Proofs', value: 'zkp-received' },
    { name: '💸  List Reimbursements (Insurer)', value: 'zkp-reimbursements' },
  ];
}

// ======================================================
// ACTION HANDLER (dispatches to correct function)
// ======================================================

export async function handleZKPAction(action, agentManager) {
  switch (action) {
    case 'zkp-generate':
      await handleGenerateProof(agentManager);
      break;
    case 'zkp-submit':
      await handleSubmitProof(agentManager);
      break;
    case 'zkp-verify':
      await handleVerifyProof(agentManager);
      break;
    case 'zkp-list':
      await handleListProofs(agentManager);
      break;
    case 'zkp-received':
      await handleListReceived(agentManager);
      break;
    case 'zkp-reimbursements':
      await handleListReimbursements(agentManager);
      break;
  }
}

// ======================================================
// GENERATE ZK PROOF (Patient selects credential + fields)
// ======================================================

// ── Helper: describe what predicate will be generated for a field ────────────
// Shown in the checkbox UI so the patient understands what will be proven.
// Fields always disclosed as exact values (insurer needs them for reimbursement)
const EXACT_VALUE_FIELDS = new Set(['amount']); // amount always disclosed as exact value

// Fields that MUST be disclosed in a bill proof for reimbursement to work.
// The patient cannot uncheck these — hiding them would make fair payout impossible.
const MANDATORY_BILL_FIELDS = ['amount', 'diagnosis', 'age'];

function _describePredicateType(fieldName, rawValue) {
  const numericValue = parseFloat(String(rawValue).replace(/[^0-9.]/g, ''));
  const isNumeric    = !isNaN(numericValue) && String(rawValue).match(/[\d.]/);

  const RANGE_FIELDS  = ['age', 'coverageAmount', 'deductible', 'coveragePercent'];
  const DATE_FIELDS   = ['validUntil', 'serviceDate', 'issuedDate', 'paymentDate'];
  const STATUS_FIELDS = ['status'];

  // Exact-value fields: actual value is disclosed (mandatory for reimbursement)
  if (EXACT_VALUE_FIELDS.has(fieldName)) {
    return chalk.green(`exact value disclosed  →  ${rawValue}  ⚠ mandatory`);
  }
  if (fieldName === 'age') {
    return chalk.cyan(`range proof  →  proves age < 60  (exact age hidden)`);
  }
  if (RANGE_FIELDS.includes(fieldName) || (isNumeric && !DATE_FIELDS.includes(fieldName))) {
    return chalk.cyan(`numeric range proof  (value hidden, range proven)`);
  }
  if (DATE_FIELDS.includes(fieldName)) {
    return chalk.cyan(`date predicate  (proves not expired, date hidden)`);
  }
  if (STATUS_FIELDS.includes(fieldName)) {
    return chalk.cyan(`equality proof  (proves status = "${rawValue}")`);
  }
  if (fieldName === 'diagnosis' || fieldName === 'coveredDiagnoses') {
    return chalk.cyan(`category proof  (proves covered/not-covered, value hidden)`);
  }
  return chalk.gray(`presence proof  (proves field exists, value hidden)`);
}

async function handleGenerateProof(agentManager) {
  const agents = agentManager.listAgents();
  const patients = agents.filter(a => a.type === 'patient');

  if (patients.length === 0) {
    console.log(chalk.yellow('\n⚠️  No patient agents found. Create a patient first.\n'));
    return;
  }

  console.log(chalk.magenta.bold('\n╔══════════════════════════════════════════════╗'));
  console.log(chalk.magenta.bold('║   🔐  Generate ZK Proof (Patient)             ║'));
  console.log(chalk.magenta.bold('╚══════════════════════════════════════════════╝'));
  console.log(chalk.gray('   Proven statements replace raw values — the insurer'));
  console.log(chalk.gray('   learns WHAT is satisfied, never the actual data.\n'));

  // ── Select patient ──────────────────────────────────────────────────────────
  const { patientId } = await inquirer.prompt([{
    type: 'list',
    name: 'patientId',
    message: '🧑  Select patient:',
    choices: patients.map(p => ({
      name: `${p.name}  (${p.credentials?.length || 0} credentials)`,
      value: p.id,
    })),
  }]);

  const patient = agentManager.getAgent(patientId);

  if (!patient.credentials || patient.credentials.length === 0) {
    console.log(chalk.yellow('\n⚠️  This patient has no credentials.'));
    console.log(chalk.gray('   Issue a policy + bill first.\n'));
    return;
  }
  let selectedRequest = null;
  const incomingRequests = await agentManager.listProofRequests(patientId, 'incoming');
  const pendingRequests = incomingRequests.filter(r => r.status === 'pending');

  if (pendingRequests.length > 0) {
    const { useRequest } = await inquirer.prompt([{
      type: 'confirm',
      name: 'useRequest',
      message: `Use one of ${pendingRequests.length} pending proof request(s)?`,
      default: true,
    }]);

    if (useRequest) {
      const { requestId } = await inquirer.prompt([{
        type: 'list',
        name: 'requestId',
        message: 'Select pending proof request:',
        choices: pendingRequests.map(r => ({
          name: `${r.proofType}  |  from ${r.requesterName}  |  ${r.proofSchema?.description || ''}`,
          value: r.id,
        })),
      }]);

      selectedRequest = pendingRequests.find(r => r.id === requestId) || null;
      if (selectedRequest) {
        console.log(chalk.cyan(`\n  Linked request: ${selectedRequest.proofType}`));
        if ((selectedRequest.requestedFields || []).length > 0) {
          console.log(chalk.gray(`  Requested fields: ${selectedRequest.requestedFields.join(', ')}`));
        }
        console.log('');
      }
    }
  }

  const compatibleCredentials = selectedRequest?.proofSchema?.appliesToCredential
    ? patient.credentials.filter(c => c.type === selectedRequest.proofSchema.appliesToCredential)
    : patient.credentials;

  if (compatibleCredentials.length === 0) {
    console.log(chalk.yellow('\n⚠️  No credential matches the selected proof request.\n'));
    return;
  }

  // ── Select credential ───────────────────────────────────────────────────────
  const { credentialId } = await inquirer.prompt([{
    type: 'list',
    name: 'credentialId',
    message: '📄  Select credential to generate proof for:',
    choices: compatibleCredentials.map(c => ({
      name: `${c.type.padEnd(20)}  |  from ${c.issuer}  |  ${new Date(c.issuedAt).toLocaleDateString()}`,
      value: c.id,
    })),
  }]);

  const credRecord = patient.credentials.find(c => c.id === credentialId);
  const claims     = credRecord.credential?.credentialSubject || {};
  const allFields  = Object.keys(claims).filter(k => k !== 'id');

  if (allFields.length === 0) {
    console.log(chalk.yellow('\n⚠️  No claim fields found in this credential.\n'));
    return;
  }

  // ── Select fields to prove ──────────────────────────────────────────────────
  // The UI shows the PREDICATE TYPE for each field — not the raw value.
  // This makes it clear the patient is choosing *which statements to prove*,
  // not which raw values to hand over.
  const RECOMMENDED = {
    MedicalBill:      ['amount', 'diagnosis', 'age', 'serviceDate'],
    InsurancePolicy:  ['coverageAmount', 'coveragePercent', 'deductible', 'coveredDiagnoses', 'validUntil', 'status'],
  };
  const recommended = [...new Set([
    ...(RECOMMENDED[credRecord.type] || []),
    ...(selectedRequest?.requestedFields || []),
  ])];

  // For bill credentials, some fields are mandatory (cannot be hidden).
  const isBill       = credRecord.type === 'MedicalBill';
  const billMandatory = isBill ? MANDATORY_BILL_FIELDS.filter(f => allFields.includes(f)) : [];
  const requestMandatory = (selectedRequest?.requestedFields || []).filter(f => allFields.includes(f));
  const mandatorySet = new Set([...billMandatory, ...requestMandatory]);

  if (mandatorySet.size > 0) {
    const mandatoryReason = selectedRequest
      ? 'required by the selected proof request and cannot be hidden:'
      : 'MANDATORY for bill proofs and cannot be hidden:';
    console.log(chalk.yellow(`\n   ⚠️  The following fields are ${mandatoryReason}`));
    for (const f of mandatorySet) {
      console.log(chalk.green(`      • ${f}  →  ${_describePredicateType(f, claims[f])}`));
    }
  }

  console.log(chalk.yellow(`\n   Choose which ADDITIONAL fields to prove (as ZK statements).`));
  console.log(chalk.gray(`   ✅ Checked  → insurer sees the proven statement (NOT the raw value)`));
  console.log(chalk.gray(`   ☐  Unchecked → field completely omitted (name + value both hidden)\n`));

  const optionalFields = allFields.filter(f => !mandatorySet.has(f));

  let disclosedFields;
  if (optionalFields.length > 0) {
    const { optionalSelected } = await inquirer.prompt([{
      type: 'checkbox',
      name: 'optionalSelected',
      message: `Optional fields to prove (${credRecord.type}):`,
      choices: optionalFields.map(f => ({
        name: `${f.padEnd(22)}  →  ${_describePredicateType(f, claims[f])}`,
        value: f,
        checked: recommended.includes(f) && !mandatorySet.has(f),
      })),
    }]);
    disclosedFields = [...mandatorySet, ...optionalSelected];
  } else {
    disclosedFields = [...mandatorySet];
    console.log(chalk.gray('   (all relevant fields are mandatory — no optional fields to select)'));
  }

  const hiddenFields = allFields.filter(f => !disclosedFields.includes(f));

  // ── Summary ─────────────────────────────────────────────────────────────────
  console.log('');
  console.log(chalk.cyan('  What the insurer will receive:'));
  if (disclosedFields.length > 0) {
    for (const f of disclosedFields) {
      const tag = mandatorySet.has(f) ? chalk.red(' [mandatory]') : '';
      console.log(chalk.green(`  ✅ ${f}${tag}: ${_describePredicateType(f, claims[f])}`));
    }
  } else {
    console.log(chalk.yellow('  (no proven statements — fully opaque proof)'));
  }
  if (hiddenFields.length > 0) {
    console.log(chalk.yellow(`\n  🙈 ${hiddenFields.length} field(s) completely omitted (names not revealed)`));
  }
  console.log('');

  // ── Locate the insurer-issued policy VC (required by v2 circuit) ────────────
  // coverageAmount and policyExpiry must come from this signed document —
  // the circuit binds them to policyVCHash so the insurer can verify they
  // were not self-reported by the patient.
  //
  // This block only applies to MedicalBill proofs.  Policy proofs don't
  // need a second policy credential in the witness.
  let policyCredentialId = null;

  if (credRecord.type === 'MedicalBill') {
    const policyCredentials = patient.credentials.filter(c => c.type === 'InsurancePolicy');

    if (policyCredentials.length === 0) {
      console.log(chalk.red('\n❌  No InsurancePolicy credential found in your wallet.'));
      console.log(chalk.gray('   → Ask your insurer to issue a policy first  (use "Insurance Issues Insurance Policy").'));
      console.log(chalk.gray('   → The circuit requires an insurer-signed policy VC to prove'));
      console.log(chalk.gray('     coverageAmount and policyExpiry without self-reporting them.\n'));
      return;
    }

    if (policyCredentials.length === 1) {
      // Auto-select the only available policy — no prompt needed.
      policyCredentialId = policyCredentials[0].id;
      const ps = policyCredentials[0].credential?.credentialSubject || {};
      console.log(chalk.cyan(`  🔒 Policy VC auto-selected (insurer-issued, not self-reported):`));
      console.log(chalk.gray(`     Plan    : ${ps.planName     || policyCredentials[0].issuer}`));
      console.log(chalk.gray(`     Coverage: ${ps.coverageAmount || 'N/A'}`));
      console.log(chalk.gray(`     Expires : ${ps.validUntil   || ps.policyExpiry || 'N/A'}`));
      console.log('');
    } else {
      // Multiple policies — let the patient choose which one to commit to.
      console.log(chalk.cyan('\n  🔒 Select the insurer-issued policy VC to commit to in the proof:\n'));
      const { selectedPolicyId } = await inquirer.prompt([{
        type: 'list',
        name: 'selectedPolicyId',
        message: '💳  Select InsurancePolicy credential:',
        choices: policyCredentials.map(c => {
          const ps = c.credential?.credentialSubject || {};
          return {
            name: `${(ps.planName || c.issuer).padEnd(28)}  |  coverage ${ps.coverageAmount || 'N/A'}  |  expires ${ps.validUntil || 'N/A'}`,
            value: c.id,
          };
        }),
      }]);
      policyCredentialId = selectedPolicyId;
    }
  }

  try {
    await agentManager.generateZKProof(
      patientId,
      credentialId,
      disclosedFields,
      selectedRequest?.id || null,
      policyCredentialId            // v2: insurer-issued policy VC (required for MedicalBill proofs)
    );
  } catch (error) {
    console.log(chalk.red(`\n❌ Error: ${error.message}\n`));
  }
}

// ======================================================
// SUBMIT PROOF (Patient → Insurer)
// ======================================================

async function handleSubmitProof(agentManager) {
  const agents = agentManager.listAgents();
  const patients = agents.filter(a => a.type === 'patient');

  if (patients.length === 0) {
    console.log(chalk.yellow('\n⚠️  No patient agents found.\n'));
    return;
  }

  // Select patient
  const { patientId } = await inquirer.prompt([{
    type: 'list',
    name: 'patientId',
    message: 'Select patient (proof sender):',
    choices: patients.map(p => ({ name: p.name, value: p.id })),
  }]);

  // List patient's proofs
  const proofs = await agentManager.listZKProofs(patientId);
  
  if (proofs.length === 0) {
    console.log(chalk.yellow('\n⚠️  No ZK proofs found. Generate one first.\n'));
    return;
  }

  // Select proof
  const { proofId } = await inquirer.prompt([{
    type: 'list',
    name: 'proofId',
    message: 'Select proof to submit:',
    choices: proofs.map(p => ({
      name: `${p.publicInputs?.credentialType || p.type || 'Unknown'} - ${p.id.substring(0, 12)}... (${new Date(p.generatedAt).toLocaleString()})`,
      value: p.id,
    })),
  }]);

  // Select verifier (insurers)
  const insurers = agents.filter(a => a.type === 'insurer');
  if (insurers.length === 0) {
    console.log(chalk.yellow('\n⚠️  No insurer agents found.\n'));
    return;
  }

  const { verifierId } = await inquirer.prompt([{
    type: 'list',
    name: 'verifierId',
    message: 'Select verifier (insurer):',
    choices: insurers.map(i => ({ name: i.name, value: i.id })),
  }]);

  try {
    await agentManager.submitZKProof(patientId, verifierId, proofId);
  } catch (error) {
    console.log(chalk.red(`\n❌ Error: ${error.message}\n`));
  }
}

// ======================================================
// VERIFY PROOF (Insurer) + POLICY COMPLIANCE + REIMBURSEMENT
// ======================================================

async function handleVerifyProof(agentManager) {
  const agents   = agentManager.listAgents();
  const insurers = agents.filter(a => a.type === 'insurer');

  if (insurers.length === 0) {
    console.log(chalk.yellow('\n⚠️  No insurer agents found.\n'));
    return;
  }

  console.log(chalk.cyan.bold('\n╔══════════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║   🔍  Insurer: Verify ZK Proofs & Reimburse   ║'));
  console.log(chalk.cyan.bold('╚══════════════════════════════════════════════╝'));
  console.log(chalk.gray('   Insurer sees only proven statements — never raw patient data.\n'));

  // ── Select insurer ─────────────────────────────────────────────────────────
  const { insurerId } = await inquirer.prompt([{
    type: 'list',
    name: 'insurerId',
    message: '🏢  Select insurer:',
    choices: insurers.map(i => ({ name: i.name, value: i.id })),
  }]);

  const received = await agentManager.listReceivedProofs(insurerId);
  if (received.length === 0) {
    console.log(chalk.yellow('\n⚠️  No received proofs. Patient must submit proofs first.\n'));
    return;
  }

  // ── Classify received proofs by credentialType (not raw claim values) ──────
  const billProofs   = received.filter(p => p.publicInputs?.credentialType === 'MedicalBill');
  const policyProofs = received.filter(p => p.publicInputs?.credentialType === 'InsurancePolicy');
  const otherProofs  = received.filter(p =>
    p.publicInputs?.credentialType !== 'MedicalBill' &&
    p.publicInputs?.credentialType !== 'InsurancePolicy'
  );

  // ── Step 1: Select bill proof ──────────────────────────────────────────────
  const allBillOptions = [...billProofs, ...otherProofs];
  if (allBillOptions.length === 0) {
    console.log(chalk.yellow('\n⚠️  No Medical Bill proof received from patient.'));
    console.log(chalk.gray('   → Patient must generate + submit a bill proof first.\n'));
    return;
  }

  console.log(chalk.yellow('\n🧾  Step 1/2 — Select the Medical Bill proof\n'));
  const { billProofId } = await inquirer.prompt([{
    type: 'list',
    name: 'billProofId',
    message: '🏥  Select bill proof:',
    choices: allBillOptions.map(p => ({
      name: `${p.publicInputs?.credentialType || 'Unknown'}  |  ${p.verified === null ? '⏳ Pending' : p.verified ? '✅ Verified' : '❌ Failed'}  |  from ${p.submittedBy || 'unknown'}  |  ${p.id.substring(0, 14)}...`,
      value: p.id,
    })),
  }]);

  // ── Step 2: Select policy proof ────────────────────────────────────────────
  console.log(chalk.yellow('\n💳  Step 2/2 — Select the Insurance Policy proof\n'));

  let policyProofId = null;
  if (policyProofs.length === 0) {
    console.log(chalk.yellow('   ⚠️  No Insurance Policy proof received — will use insurer wallet policy only.\n'));
  } else {
    const { selectedPolicyProofId } = await inquirer.prompt([{
      type: 'list',
      name: 'selectedPolicyProofId',
      message: '💳  Select policy proof:',
      choices: [
        { name: '— Use insurer wallet policy only —', value: null },
        ...policyProofs.map(p => ({
          name: `InsurancePolicy  |  ${p.verified === null ? '⏳ Pending' : p.verified ? '✅ Verified' : '❌ Failed'}  |  from ${p.submittedBy || 'unknown'}  |  ${p.id.substring(0, 14)}...`,
          value: p.id,
        })),
      ],
    }]);
    policyProofId = selectedPolicyProofId;
  }

  // ── Verify bill proof ──────────────────────────────────────────────────────
  console.log(chalk.cyan('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.cyan('  🔍  Verifying Medical Bill proof...'));
  console.log(chalk.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));

  let billVerification;
  try {
    billVerification = await agentManager.verifyZKProof(insurerId, billProofId);
  } catch (error) {
    console.log(chalk.red(`\n❌ Error verifying bill proof: ${error.message}\n`));
    return;
  }

  if (!billVerification?.valid) {
    console.log(chalk.red('\n🚫 Bill proof FAILED — cannot proceed.\n'));
    return;
  }

  // ── Verify policy proof (if submitted) ────────────────────────────────────
  let policyVerification = null;
  if (policyProofId) {
    console.log(chalk.cyan('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log(chalk.cyan('  🔍  Verifying Insurance Policy proof...'));
    console.log(chalk.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
    try {
      policyVerification = await agentManager.verifyZKProof(insurerId, policyProofId);
      if (!policyVerification?.valid) {
        console.log(chalk.yellow('\n⚠️  Policy proof failed — falling back to insurer wallet policy.\n'));
        policyVerification = null;
      }
    } catch {
      console.log(chalk.yellow('\n⚠️  Policy proof error — falling back to insurer wallet policy.\n'));
    }
  }

  // Extract disclosedClaims from each verified proof.
  // amount is intentionally disclosed as exact value for reimbursement.
  const billDisclosed   = billVerification.disclosedClaims   || {};
  const policyDisclosed = policyVerification?.disclosedClaims || {};

  // ── Load authoritative policy from insurer wallet ──────────────────────────
  const patientDid  = billVerification.publicInputs?.subjectDID;
  let insurerPolicy = null;
  if (patientDid && agentManager.zkp) {
    try {
      insurerPolicy = await agentManager.zkp.loadPolicyFromInsurerWallet(insurerId, patientDid);
      if (insurerPolicy) console.log(chalk.green('\n✅  Loaded authoritative policy from insurer wallet.'));
    } catch { /* fall through */ }
  }

  // ── Policy Summary (shown to insurer before compliance check) ───────────────
  if (insurerPolicy) {
    const ps = insurerPolicy;
    const rawCovAmt  = parseFloat(String(ps.coverageAmount  || '0').replace(/[^0-9.]/g, '')) || 0;
    const rawPct     = parseFloat(String(ps.coveragePercent || '0').replace(/[^0-9.]/g, '')) || 0;
    const rawDeduct  = parseFloat(String(ps.deductible      || '0').replace(/[^0-9.]/g, '')) || 0;
    const billAmt    = parseFloat(String(billDisclosed?.amount || '0').replace(/[^0-9.]/g, '')) || 0;

    // Load prior reimbursements to show remaining coverage
    let priorTotal = 0;
    try {
      const allRecs = await agentManager.zkp.listReimbursements(insurerId);
      const patientRecs = allRecs.filter(
        r => r.patientDID === patientDid && r.status === 'approved'
      );
      priorTotal = patientRecs.reduce(
        (sum, r) => sum + (r.breakdown?.reimbursementAmount || 0), 0
      );
    } catch { /* no prior records */ }

    const remainingCov = rawCovAmt > 0 ? Math.max(0, rawCovAmt - priorTotal) : 0;

    // Max possible reimbursement = min(remainingCoverage, (billAmt - deductible) * pct%)
    const afterDeductEst = Math.max(0, billAmt - rawDeduct);
    const maxPossible    = rawCovAmt > 0
      ? Math.min(afterDeductEst * (rawPct / 100), remainingCov)
      : afterDeductEst * (rawPct / 100);

    console.log(chalk.cyan('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log(chalk.cyan('  📄  Policy Summary  (from insurer wallet)'));
    console.log(chalk.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log(chalk.white(`  Plan Name        : `) + chalk.yellow(ps.planName        || 'N/A'));
    console.log(chalk.white(`  Policy Holder    : `) + chalk.yellow(ps.policyHolder    || 'N/A'));
    console.log(chalk.white(`  Policy Number    : `) + chalk.gray(ps.policyNumber      || 'N/A'));
    console.log(chalk.white(`  Coverage Amount  : `) + chalk.green(`$${rawCovAmt.toFixed(2)}`));
    console.log(chalk.white(`  Coverage %       : `) + chalk.green(`${rawPct}%`));
    console.log(chalk.white(`  Annual Deductible: `) + chalk.yellow(`$${rawDeduct.toFixed(2)}`));
    console.log(chalk.white(`  Covered Diagnoses: `) + chalk.cyan(ps.coveredDiagnoses  || 'ALL'));
    console.log(chalk.white(`  Valid Until      : `) + chalk.cyan(ps.validUntil        || 'N/A'));
    console.log(chalk.white(`  Status           : `) + chalk.cyan(ps.status            || 'N/A'));
    if (priorTotal > 0 && rawCovAmt > 0) {
      console.log(chalk.white(`  Prior Reimbursed : `) + chalk.yellow(`$${priorTotal.toFixed(2)}`));
      console.log(chalk.white(`  Remaining Cover. : `) + chalk.cyan(`$${remainingCov.toFixed(2)}`));
    }
    console.log('');
    if (billAmt > 0) {
      console.log(chalk.white(`  Bill Amount      : `) + chalk.yellow(`$${billAmt.toFixed(2)}`));
      console.log(chalk.green.bold(`  Max Possible Reimbursement: $${maxPossible.toFixed(2)}`));
      console.log(chalk.gray(`    (= min(remainingCoverage, (bill − deductible) × coverage%))`));
    } else {
      console.log(chalk.gray(`  Max Possible Reimbursement: (bill amount not yet disclosed)`));
    }
    console.log('');
  }

  // ── Policy Compliance Check ────────────────────────────────────────────────
  console.log(chalk.cyan('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.cyan('  📋  Policy Compliance Check'));
  console.log(chalk.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));

  // All compliance logic uses the insurer's own wallet policy as source of truth.
  // The patient's predicate proofs are used only when insurer wallet has no data.
  const policySource = insurerPolicy || {};

  const policyStatus    = String(policySource.status || 'Active');
  const validUntil      = policySource.validUntil || null;

  // Check 1: Policy active?
  const policyActive = policyStatus.toLowerCase() === 'active';
  console.log(`  Policy Status  : ${policyActive ? chalk.green('Active ✅') : chalk.red(`${policyStatus} ❌`)}`);

  // Check 2: Policy not expired?
  let policyNotExpired = true;
  if (validUntil) {
    policyNotExpired = new Date(validUntil) >= new Date();
    console.log(`  Policy Expiry  : ${policyNotExpired
      ? chalk.green(`Valid until ${validUntil} ✅`)
      : chalk.red(`EXPIRED on ${validUntil} ❌`)}`);
  } else {
    console.log(`  Policy Expiry  : ${chalk.yellow('Not specified ⚠️')}`);
  }

  // Check 3: Diagnosis covered?
  // With predicate proofs, billDisclosed.diagnosis is a token like
  // "diagnosis_covered" or "diagnosis_not_covered" (from category predicate),
  // or a raw string for legacy proofs.
  const diagnosisField  = String(billDisclosed.diagnosis || '').trim();
  let diagnosisCovered  = true;

  if (diagnosisField === 'diagnosis_covered') {
    diagnosisCovered = true;
    console.log(`  Diagnosis      : ${chalk.green('Covered by policy ✅')} (proven by ZK category predicate)`);
  } else if (diagnosisField === 'diagnosis_not_covered') {
    diagnosisCovered = false;
    console.log(`  Diagnosis      : ${chalk.red('NOT covered ❌')} (proven by ZK category predicate)`);
  } else if (diagnosisField.endsWith('_present') || diagnosisField === '') {
    // Presence-only: can't confirm coverage without raw value
    const coveredDiags = String(policySource.coveredDiagnoses || 'ALL').toUpperCase();
    diagnosisCovered   = coveredDiags === 'ALL';
    console.log(`  Diagnosis      : ${chalk.yellow('Presence-only proof ⚠️')} — ${diagnosisCovered ? 'policy covers ALL' : 'coverage cannot be confirmed'}`);
  } else {
    // Legacy raw value — compare against policy list
    const coveredDiags = String(policySource.coveredDiagnoses || 'ALL').trim();
    if (coveredDiags.toUpperCase() !== 'ALL') {
      const list = coveredDiags.split(',').map(d => d.trim().toLowerCase());
      diagnosisCovered = list.some(d => diagnosisField.toLowerCase().includes(d) || d.includes(diagnosisField.toLowerCase()));
    }
    console.log(`  Diagnosis      : "${diagnosisField}"  →  ${diagnosisCovered ? chalk.green('Covered ✅') : chalk.red('NOT covered ❌')}`);
  }

  // Check 4: Age eligibility (age range proof: proves age < 60)
  const rawAgeProof = String(billDisclosed?.age || '').trim();
  let ageEligible = false;
  if (rawAgeProof.startsWith('age_in_range_')) {
    ageEligible = rawAgeProof === 'age_in_range_0_59';
    console.log(`  Age Eligibility: ${ageEligible
      ? chalk.green('age < 60 ✅  (proven by ZK range proof — exact age hidden)')
      : chalk.red('age >= 60 ❌  (patient outside policy age limit)')}`);
  } else if (rawAgeProof.startsWith('age_out_of_range_')) {
    ageEligible = false;
    console.log(`  Age Eligibility: ${chalk.red('out of allowed range ❌  (proven by circuit age check)')}`);
  } else if (rawAgeProof !== '') {
    const n = parseFloat(rawAgeProof.replace(/[^0-9.]/g, ''));
    ageEligible = !isNaN(n) && n < 60;
    console.log(`  Age Eligibility: ${ageEligible ? chalk.green(`${n} < 60 ✅`) : chalk.red(`${n} >= 60 ❌`)}`);
  } else {
    console.log(`  Age Eligibility: ${chalk.red('Not proven ❌  (treated as ineligible)')}`);
  }

  // Check 5: Bill amount within policy limit (informational — triggers partial reimbursement)
  const maxCoverage = parseFloat(String(policySource.coverageAmount || '0').replace(/[^0-9.]/g, '')) || 0;
  console.log(`  Max Coverage   : ${maxCoverage > 0 ? chalk.cyan(`$${maxCoverage.toFixed(2)}`) : chalk.yellow('not specified')}`);

  // ── Overall compliance ─────────────────────────────────────────────────────
  const compliant = policyActive && policyNotExpired && diagnosisCovered && ageEligible;
  console.log('');
  if (!compliant) {
    console.log(chalk.red.bold('  🚫 POLICY COMPLIANCE FAILED'));
    if (!policyActive)     console.log(chalk.red('     Policy is not Active'));
    if (!policyNotExpired) console.log(chalk.red('     Policy has expired'));
    if (!diagnosisCovered) console.log(chalk.red('     Diagnosis not covered under this policy'));
    if (!ageEligible)      console.log(chalk.red('     Patient age is outside eligible range (must be < 60)'));
    console.log(chalk.red('\n  Reimbursement DENIED.\n'));
    return;
  }
  console.log(chalk.green.bold('  ✅ POLICY COMPLIANCE PASSED'));

  // ── Reimbursement Calculation ──────────────────────────────────────────────
  console.log(chalk.cyan('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.cyan('  💰  Reimbursement Calculation'));
  console.log(chalk.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));

  if (!agentManager.zkp) {
    console.log(chalk.yellow('\n⚠️  ZKP module not available.\n'));
    return;
  }

  // ── Load prior reimbursements for this patient ──────────────────────────
  // Sum all previously approved reimbursements so calculateReimbursement
  // can reduce the remaining coverage pool for successive claims.
  let priorReimbursedTotal = 0;
  try {
    const allReimbursements = await agentManager.zkp.listReimbursements(insurerId);
    const patientReimbursements = allReimbursements.filter(
      r => r.patientDID === patientDid && r.status === 'approved'
    );
    priorReimbursedTotal = patientReimbursements.reduce(
      (sum, r) => sum + (r.breakdown?.reimbursementAmount || 0), 0
    );
    if (patientReimbursements.length > 0) {
      console.log(chalk.yellow(`\n   📊 Found ${patientReimbursements.length} prior reimbursement(s) for this patient: $${priorReimbursedTotal.toFixed(2)} total`));
    }
  } catch {
    // No prior reimbursements or ZKP module error — proceed with 0
  }

  const breakdown = agentManager.zkp.calculateReimbursement(
    policyDisclosed,
    billDisclosed,
    insurerPolicy,
    priorReimbursedTotal
  );

  // ── Confirm and save ───────────────────────────────────────────────────────
  const { confirm } = await inquirer.prompt([{
    type: 'confirm',
    name: 'confirm',
    message: chalk.green(`\n  💸  Approve reimbursement of $${breakdown.reimbursementAmount.toFixed(2)}?`),
    default: true,
  }]);

  if (confirm) {
    const crypto = await import('crypto');
    const record = {
      id:             crypto.randomUUID ? crypto.randomUUID() : crypto.default.randomBytes(16).toString('hex'),
      billProofId,
      policyProofId:  policyProofId || null,
      insurerId,
      patientDID:     patientDid || 'unknown',
      credentialType: 'MedicalBill',
      status:         'approved',
      complianceChecks: { policyActive, policyNotExpired, diagnosisCovered, ageEligible },
      breakdown,
      approvedAt:     new Date().toISOString(),
    };
    try {
      await agentManager.zkp.saveReimbursement(insurerId, record);
      console.log(chalk.green.bold(`\n✅  Reimbursement of $${breakdown.reimbursementAmount.toFixed(2)} APPROVED and recorded.`));
      console.log(chalk.cyan(`   Record ID    : ${record.id.substring(0, 18)}...`));
      console.log(chalk.cyan(`   Patient DID  : ${record.patientDID.substring(0, 42)}...`));
      console.log(chalk.cyan(`   Bill Amount  : $${breakdown.billAmount.toFixed(2)}`));
      console.log(chalk.cyan(`   Patient Owes : $${breakdown.patientOwes.toFixed(2)}`));
      console.log(chalk.gray('\n   Saved in insurer wallet → "List Reimbursements" to view.\n'));
    } catch (error) {
      console.log(chalk.red(`❌ Failed to save: ${error.message}\n`));
    }
  } else {
    console.log(chalk.yellow('\n⏸  Reimbursement NOT approved.\n'));
  }
}

// ======================================================
// LIST MY PROOFS
// ======================================================

async function handleListProofs(agentManager) {
  const agents = agentManager.listAgents();

  const { agentId } = await inquirer.prompt([{
    type: 'list',
    name: 'agentId',
    message: 'Select agent:',
    choices: agents.map(a => ({
      name: `${a.name} (${a.type})`,
      value: a.id,
    })),
  }]);

  const proofs = await agentManager.listZKProofs(agentId);

  if (proofs.length === 0) {
    console.log(chalk.yellow('\n⚠️  No ZK proofs found for this agent.\n'));
    return;
  }

  console.log(chalk.magenta(`\n🔐 ZK Proofs for ${agentManager.getAgent(agentId).name}:\n`));

  for (const proof of proofs) {
    const status = proof.verified === true ? chalk.green('✅ Verified') :
                   proof.verified === false ? chalk.red('❌ Failed') :
                   chalk.yellow('⏳ Pending');
    
    console.log(chalk.white(`  ${proof.id.substring(0, 12)}...`));
    console.log(chalk.gray(`    Type:      ${proof.publicInputs?.credentialType || proof.type || 'Unknown'}`));
    console.log(chalk.gray(`    Protocol:  ${proof.protocol || 'N/A'}`));
    console.log(chalk.gray(`    Generated: ${proof.generatedAt || 'N/A'}`));
    console.log(`    Status:    ${status}`);
    
    if (proof.publicInputs?.predicates && Object.keys(proof.publicInputs.predicates).length > 0) {
      console.log(chalk.green(`    Proven : `));
      for (const [f, p] of Object.entries(proof.publicInputs.predicates)) {
        console.log(chalk.green(`             ✅ ${p.statement}`));
      }
    } else if (proof.publicInputs?.disclosedClaims) {
      const disclosed = Object.keys(proof.publicInputs.disclosedClaims);
      console.log(chalk.green(`    Proven : ${disclosed.join(', ') || 'none'}`));
    }
    if (proof.publicInputs?.hiddenFieldCount > 0) {
      console.log(chalk.yellow(`    Hidden : ${proof.publicInputs.hiddenFieldCount} field(s) (names not revealed)`));
    } else if (proof.commitments) {
      console.log(chalk.yellow(`    Hidden : ${Object.keys(proof.commitments).join(', ')}`));
    }
    console.log('');
  }

  // Option to view full proof
  const { viewFull } = await inquirer.prompt([{
    type: 'confirm',
    name: 'viewFull',
    message: 'View full proof details?',
    default: false,
  }]);

  if (viewFull && agentManager.zkp) {
    const { proofId } = await inquirer.prompt([{
      type: 'list',
      name: 'proofId',
      message: 'Select proof:',
      choices: proofs.map(p => ({
        name: `${p.id.substring(0, 12)}... - ${p.publicInputs?.credentialType || 'Unknown'}`,
        value: p.id,
      })),
    }]);

    const fullProof = proofs.find(p => p.id === proofId);
    if (fullProof) {
      agentManager.zkp.displayProof(fullProof);
    }
  }
}

// ======================================================
// LIST RECEIVED PROOFS (Insurer)
// ======================================================

async function handleListReceived(agentManager) {
  const agents = agentManager.listAgents();
  const insurers = agents.filter(a => a.type === 'insurer');

  if (insurers.length === 0) {
    console.log(chalk.yellow('\n⚠️  No insurer agents found.\n'));
    return;
  }

  const { insurerId } = await inquirer.prompt([{
    type: 'list',
    name: 'insurerId',
    message: 'Select insurer:',
    choices: insurers.map(i => ({ name: i.name, value: i.id })),
  }]);

  const received = await agentManager.listReceivedProofs(insurerId);

  if (received.length === 0) {
    console.log(chalk.yellow('\n⚠️  No received proofs for this insurer.\n'));
    return;
  }

  console.log(chalk.cyan(`\n📥 Received Proofs for ${agentManager.getAgent(insurerId).name}:\n`));

  for (const proof of received) {
    const status = proof.verified === true ? chalk.green('✅ Verified') :
                   proof.verified === false ? chalk.red('❌ Failed') :
                   chalk.yellow('⏳ Not Verified');

    console.log(chalk.white(`  ${proof.id.substring(0, 12)}...`));
    console.log(chalk.gray(`    Type:      ${proof.publicInputs?.credentialType || 'Unknown'}`));
    console.log(chalk.gray(`    From:      ${proof.submittedBy || 'unknown'}`));
    console.log(chalk.gray(`    Submitted: ${proof.submittedAt || 'N/A'}`));
    console.log(`    Status:    ${status}`);
    
    if (proof.publicInputs?.predicates && Object.keys(proof.publicInputs.predicates).length > 0) {
      console.log(chalk.green(`    Proven statements:`));
      for (const [f, p] of Object.entries(proof.publicInputs.predicates)) {
        console.log(chalk.green(`      ✅ ${p.statement}`));
      }
    } else if (proof.publicInputs?.disclosedClaims) {
      console.log(chalk.green(`    Proven: ${JSON.stringify(proof.publicInputs.disclosedClaims)}`));
    }
    console.log('');
  }
}

// ======================================================
// LIST REIMBURSEMENTS (Insurer)
// ======================================================

async function handleListReimbursements(agentManager) {
  const agents = agentManager.listAgents();
  const insurers = agents.filter(a => a.type === 'insurer');

  if (insurers.length === 0) {
    console.log(chalk.yellow('\n⚠️  No insurer agents found.\n'));
    return;
  }

  const { insurerId } = await inquirer.prompt([{
    type: 'list',
    name: 'insurerId',
    message: 'Select insurer:',
    choices: insurers.map(i => ({ name: i.name, value: i.id })),
  }]);

  if (!agentManager.zkp) {
    console.log(chalk.yellow('\n⚠️  ZKP module not available.\n'));
    return;
  }

  const records = await agentManager.zkp.listReimbursements(insurerId);

  if (records.length === 0) {
    console.log(chalk.yellow('\n⚠️  No reimbursement records found for this insurer.\n'));
    return;
  }

  const insurerName = agentManager.getAgent(insurerId).name;
  console.log(chalk.green.bold(`\n💸 Reimbursement Records for ${insurerName}:\n`));

  let totalPaid = 0;

  for (const r of records) {
    const b = r.breakdown || {};
    totalPaid += b.reimbursementAmount || 0;

    console.log(chalk.white(`  📄 ${r.id.substring(0, 16)}...`));
    console.log(chalk.gray(`     Proof ID    : ${r.proofId?.substring(0, 16) || 'N/A'}...`));
    console.log(chalk.gray(`     Patient DID : ${(r.patientDID || 'N/A').substring(0, 40)}...`));
    console.log(chalk.gray(`     Cred Type   : ${r.credentialType || 'N/A'}`));
    console.log(chalk.yellow(`     Bill Amount : $${(b.billAmount || 0).toFixed(2)}`));
    console.log(chalk.yellow(`     Deductible  : $${(b.deductible || 0).toFixed(2)}`));
    console.log(chalk.yellow(`     Coverage %  : ${b.coveragePercent || 0}%`));
    console.log(chalk.green(`     Reimbursed  : $${(b.reimbursementAmount || 0).toFixed(2)}`));
    console.log(chalk.cyan(`     Patient Owes: $${(b.patientOwes || 0).toFixed(2)}`));
    if (b.priorReimbursedTotal > 0 || b.remainingAfterThis != null) {
      console.log(chalk.yellow(`     Prior Total : $${(b.priorReimbursedTotal || 0).toFixed(2)}`));
      console.log(chalk.cyan(`     Remaining   : $${(b.remainingAfterThis != null ? b.remainingAfterThis : 'N/A')}`));
    }
    console.log(chalk.gray(`     Approved At : ${r.approvedAt || 'N/A'}`));

    const statusColor = r.status === 'approved' ? chalk.green : chalk.yellow;
    console.log(`     Status      : ${statusColor((r.status || 'unknown').toUpperCase())}`);
    console.log('');
  }

  console.log(chalk.green.bold(`   Total Reimbursed (all records): $${totalPaid.toFixed(2)}\n`));
}