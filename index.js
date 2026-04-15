import chalk from 'chalk';
import Table from 'cli-table3';
import fs from 'fs/promises';
import inquirer from 'inquirer';
import { AGENT_TYPES, CREDENTIAL_SCHEMAS } from './src/agentConfig-blockchain.js';
import { AgentManager } from './src/agentManager-blockchain.js';
import { addZKPMenuItems, handleZKPAction } from './src/zkpMenu.js';


const agentManager = new AgentManager(true, process.env.BLOCKCHAIN_NETWORK || 'sepolia');

// Display enhanced banner
function displayBanner() {
  console.clear();
  console.log(chalk.cyan.bold('╔═══════════════════════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║   SSI HEALTHCARE - BLOCKCHAIN ENABLED BILLING SYSTEM      ║'));
  console.log(chalk.cyan.bold('╚═══════════════════════════════════════════════════════════╝'));
  console.log('');
}

// Display statistics
function displayStats() {
  const stats = agentManager.getStatistics();
  
  if (stats.totalAgents === 0) return;

  console.log(chalk.gray('┌─────────────────────────────────────────────────────┐'));
  console.log(chalk.gray('│ ') + chalk.white.bold('System Statistics') + chalk.gray('                               │'));
  console.log(chalk.gray('├─────────────────────────────────────────────────────┤'));
  console.log(chalk.gray('│ ') + chalk.cyan('Agents:        ') + chalk.white(stats.totalAgents.toString().padEnd(35)) + chalk.gray('│'));
  console.log(chalk.gray('│ ') + chalk.cyan('Connections:   ') + chalk.white(stats.totalConnections.toString().padEnd(35)) + chalk.gray('│'));
  console.log(chalk.gray('│ ') + chalk.cyan('Credentials:   ') + chalk.white(stats.totalCredentials.toString().padEnd(35)) + chalk.gray('│'));
  console.log(chalk.gray('│ ') + chalk.cyan('Blockchain:    ') + chalk.white(stats.blockchainNetwork.padEnd(35)) + chalk.gray('│'));
  console.log(chalk.gray('└─────────────────────────────────────────────────────┘'));
  console.log('');
}

// Main menu
async function mainMenu() {
  const choices = [
    new inquirer.Separator(chalk.cyan('═══ AGENT MANAGEMENT ═══')),
    { name: '➕  Create New Agent', value: 'create' },
    { name: '📋  List All Agents', value: 'list' },
    { name: '👁️   View Agent Details', value: 'view' },
    { name: '📊  View Statistics', value: 'stats' },
    { name: '🗑️   Delete Agent', value: 'delete' },

    new inquirer.Separator(chalk.cyan('═══ CREDENTIALS & BILLING ═══')),
    { name: '🏥  Hospital Issues Bill', value: 'issue-bill' },
    { name: '💳  Insurance Issues Insurance Policy', value: 'issue-policy' },
    { name: '🔍  Verify Credential  (issuer testing only)', value: 'verify' },
    { name: '🚫  Revoke Credential', value: 'revoke' },
    { name: '📤  Export Agent Wallet', value: 'export' },

    new inquirer.Separator(chalk.magenta('═══ ZERO-KNOWLEDGE PROOFS ═══')),
    ...addZKPMenuItems(),

    new inquirer.Separator(chalk.cyan('═══ BLOCKCHAIN ═══')),
    { name: '💰  Check Balances', value: 'balances' },
    { name: '📊  Blockchain Info', value: 'blockchain-info' },

    new inquirer.Separator(chalk.cyan('═══ SYSTEM ═══')),
    { name: '🧹  Clean All Data', value: 'clean' },
    { name: '🚪  Exit', value: 'exit' }
  ];

  const answer = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: chalk.bold('What would you like to do?'),
      choices: choices,
      pageSize: 25,
      loop: false
    }
  ]);

  return answer.action;
}

// Create new agent
async function createAgent() {
  console.log(chalk.yellow.bold('\n➕ Create New Agent\n'));

  const typeChoices = Object.entries(AGENT_TYPES).map(([key, config]) => ({
    name: `${config.icon}  ${config.label.padEnd(20)} - ${config.description}`,
    value: key,
    short: config.label
  }));

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'name',
      message: 'Enter agent name:',
      validate: (input) => {
        if (!input.trim()) return 'Name cannot be empty';
        if (input.length < 3) return 'Name must be at least 3 characters';
        return true;
      }
    },
    {
      type: 'list',
      name: 'type',
      message: 'Select agent type:',
      choices: typeChoices,
      pageSize: 10
    },
    {
      type: 'input',
      name: 'description',
      message: 'Enter description (optional):',
      default: ''
    }
  ]);

  const metadata = {
    description: answers.description
  };

  try {
    const agent = await agentManager.createAgent(answers.name, answers.type, metadata);
    console.log(chalk.green('\n✅ Agent created successfully!'));
    console.log(chalk.cyan(`DID: ${agent.did}`));
    console.log(chalk.cyan(`Blockchain Address: ${agent.blockchainAddress || 'N/A'}\n`));
  } catch (error) {
    console.log(chalk.red(`❌ Error: ${error.message}\n`));
  }
}

// List all agents
function listAgents() {
  const agents = agentManager.listAgents();

  if (agents.length === 0) {
    console.log(chalk.yellow('\n⚠️  No agents found. Create one first!\n'));
    return;
  }

  console.log(chalk.cyan.bold('\n📋 All Agents\n'));

  const table = new Table({
    head: [
      chalk.white.bold('Name'),
      chalk.white.bold('Type'),
      chalk.white.bold('DID'),
      chalk.white.bold('Connections'),
      chalk.white.bold('Credentials')
    ],
    colWidths: [25, 20, 45, 13, 13]
  });

  for (const agent of agents) {
    const agentType = AGENT_TYPES[agent.type];
    const typeDisplay = agentType ? `${agentType.icon} ${agentType.label}` : agent.type;
    
    table.push([
      chalk.cyan(agent.name),
      typeDisplay,
      chalk.gray(agent.did.substring(0, 40) + '...'),
      chalk.green(agent.connections?.length || 0),
      chalk.blue(agent.credentials?.length || 0)
    ]);
  }

  console.log(table.toString());
  console.log('');
}

// View agent details
async function viewAgentDetails() {
  const agents = agentManager.listAgents();

  if (agents.length === 0) {
    console.log(chalk.yellow('\n⚠️  No agents found\n'));
    return;
  }

  const agentChoices = agents.map(a => {
    const agentType = AGENT_TYPES[a.type];
    const icon = agentType ? agentType.icon : '📦';
    return {
      name: `${icon}  ${a.name} (${a.type})`,
      value: a.id
    };
  });

  const answer = await inquirer.prompt([
    {
      type: 'list',
      name: 'agent',
      message: 'Select agent to view:',
      choices: agentChoices,
      pageSize: 10
    }
  ]);

  const agent = agentManager.getAgent(answer.agent);
  const agentType = AGENT_TYPES[agent.type];

  console.log(chalk.cyan.bold('\n╔═══════════════════════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold(`║  ${agentType?.icon || '📦'}  ${agent.name.toUpperCase().padEnd(53)}║`));
  console.log(chalk.cyan.bold('╚═══════════════════════════════════════════════════════════╝\n'));

  console.log(chalk.white.bold('Type:        ') + `${agentType?.icon || '📦'} ${agentType?.label || agent.type}`);
  console.log(chalk.white.bold('Agent ID:    ') + chalk.gray(agent.id));
  console.log(chalk.white.bold('DID:         ') + chalk.gray(agent.did));
  console.log(chalk.white.bold('Blockchain:  ') + chalk.gray(agent.blockchainAddress || 'N/A'));
  
  if (agent.metadata?.description) {
    console.log(chalk.white.bold('Description: ') + agent.metadata.description);
  }
  
  if (agent.metadata?.createdAt) {
    console.log(chalk.white.bold('Created:     ') + new Date(agent.metadata.createdAt).toLocaleString());
  }
  console.log('');

  if (agent.connections && agent.connections.length > 0) {
    console.log(chalk.yellow.bold('🔗 Connections:'));
    agent.connections.forEach(conn => {
      const connType = AGENT_TYPES[conn.type];
      const icon = connType ? connType.icon : '📦';
      console.log(`  ${icon}  ${conn.name.padEnd(30)} (${conn.type})`);
      console.log(chalk.gray(`      ${conn.did.substring(0, 60)}...`));
    });
    console.log('');
  } else {
    console.log(chalk.gray('No connections\n'));
  }

  if (agent.credentials && agent.credentials.length > 0) {
    console.log(chalk.yellow.bold('📄 Credentials:'));
    agent.credentials.forEach((cred, index) => {
      console.log(`  ${index + 1}. ${chalk.cyan(cred.type)}`);
      console.log(`     Issued by: ${cred.issuer}`);
      console.log(`     Date: ${new Date(cred.issuedAt).toLocaleString()}`);
      console.log(`     Status: ${cred.status === 'revoked' ? chalk.red(cred.status) : chalk.green(cred.status)}`);
    });
    console.log('');
  } else {
    console.log(chalk.gray('No credentials\n'));
  }

  // Show ZK proof count if any
  try {
    const proofs = await agentManager.listZKProofs(agent.id);
    const received = await agentManager.listReceivedProofs(agent.id);
    if (proofs.length > 0 || received.length > 0) {
      console.log(chalk.yellow.bold('🔐 Zero-Knowledge Proofs:'));
      if (proofs.length > 0) {
        console.log(`  Generated: ${chalk.magenta(proofs.length)} proof(s)`);
      }
      if (received.length > 0) {
        console.log(`  Received:  ${chalk.blue(received.length)} proof(s)`);
      }
      console.log('');
    }
  } catch {
    // ZKP module might not be initialized
  }
}

// Delete agent
async function deleteAgent() {
  const agents = agentManager.listAgents();

  if (agents.length === 0) {
    console.log(chalk.yellow('\n⚠️  No agents to delete\n'));
    return;
  }

  const agentChoices = agents.map(a => ({
    name: `${a.name} (${a.type})`,
    value: a.id
  }));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'agent',
      message: 'Select agent to delete:',
      choices: agentChoices
    },
    {
      type: 'confirm',
      name: 'confirm',
      message: chalk.red('⚠️  This will permanently delete the agent. Continue?'),
      default: false
    }
  ]);

  if (answers.confirm) {
    try {
      await agentManager.deleteAgent(answers.agent);
      console.log(chalk.green('\n✅ Agent deleted successfully\n'));
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}\n`));
    }
  } else {
    console.log(chalk.gray('Deletion cancelled\n'));
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// STEP 2  Hospital Issues Medical Bill to Patient
// ──────────────────────────────────────────────────────────────────────────────
async function hospitalIssueBill() {
  const agents = agentManager.listAgents();
  const hospitals = agents.filter(a => a.type === 'hospital');
  const patients  = agents.filter(a => a.type === 'patient');

  if (hospitals.length === 0) {
    console.log(chalk.yellow('\n⚠️  No hospital agents found.'));
    console.log(chalk.gray('   → Create a hospital agent first via "Create New Agent"\n'));
    return;
  }

  if (patients.length === 0) {
    console.log(chalk.yellow('\n⚠️  No patient agents found.'));
    console.log(chalk.gray('   → Create a patient agent first via "Create New Agent"\n'));
    return;
  }

  console.log(chalk.cyan.bold('\n╔══════════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║   🏥  Medical Bill Issuance                   ║'));
  console.log(chalk.cyan.bold('╚══════════════════════════════════════════════╝'));
  console.log(chalk.gray('   Hospital issues a signed bill credential to the patient.\n'));

  // ── Select parties ──────────────────────────────────────────────────────────
  const { hospitalId } = await inquirer.prompt([{
    type: 'list',
    name: 'hospitalId',
    message: '🏥  Select Hospital:',
    choices: hospitals.map(h => ({
      name: `${AGENT_TYPES.hospital?.icon || '🏥'}  ${h.name}`,
      value: h.id,
      short: h.name
    }))
  }]);

  const { patientId } = await inquirer.prompt([{
    type: 'list',
    name: 'patientId',
    message: '🧑  Select Patient:',
    choices: patients.map(p => {
      const hasPolicy = p.credentials?.some(c => c.type === 'InsurancePolicy');
      const tag = hasPolicy ? chalk.green(' ✔ has policy') : chalk.yellow(' ⚠ no policy yet');
      return {
        name: `${AGENT_TYPES.patient?.icon || '🧑'}  ${p.name}${tag}`,
        value: p.id,
        short: p.name
      };
    })
  }]);

  const patient = agentManager.getAgent(patientId);

  // ── Bill details ────────────────────────────────────────────────────────────
  console.log(chalk.yellow('\n📋  Bill Details\n'));

  const billDetails = await inquirer.prompt([
    {
      type: 'input',
      name: 'diagnosis',
      message: '  Diagnosis:',
      validate: input => input.trim() ? true : 'Diagnosis is required'
    },
    {
      type: 'input',
      name: 'treatment',
      message: '  Treatment / Procedure:',
      validate: input => input.trim() ? true : 'Treatment details are required'
    },
    {
      type: 'input',
      name: 'age',
      message: '  Patient Age (years):',
      validate: input => {
        const n = parseInt(input);
        return (!isNaN(n) && n >= 0 && n <= 150) ? true : 'Enter a valid age (0–150)';
      }
    },
    {
      type: 'input',
      name: 'amount',
      message: '  Total Bill Amount ($):',
      validate: input => !isNaN(parseFloat(input)) && parseFloat(input) > 0
        ? true : 'Enter a valid amount (e.g. 2500)'
    }
  ]);

  // ── Auto-derive ─────────────────────────────────────────────────────────────
  const billNumber  = `BILL-${Date.now()}`;
  const serviceDate = new Date().toISOString().split('T')[0];
  const issuedDate  = new Date().toISOString();

  const credentialData = {
    type: 'MedicalBill',
    claims: {
      billNumber,
      patientName: patient.name,
      age:         parseInt(billDetails.age),
      diagnosis:   billDetails.diagnosis,
      treatment:   billDetails.treatment,
      amount:      `$${parseFloat(billDetails.amount).toFixed(2)}`,
      date: serviceDate,
      issuedDate
    }
  };

  try {
    await agentManager.issueCredential(hospitalId, patientId, credentialData);

    console.log(chalk.green('\n✅  Medical bill issued successfully!'));
    console.log(chalk.cyan(`   Bill Number : ${billNumber}`));
    console.log(chalk.cyan(`   Patient     : ${patient.name}`));
    console.log(chalk.cyan(`   Age         : ${billDetails.age} years`));
    console.log(chalk.cyan(`   Diagnosis   : ${billDetails.diagnosis}`));
    console.log(chalk.cyan(`   Amount      : $${parseFloat(billDetails.amount).toFixed(2)}`));
    console.log(chalk.gray('\n   Bill credential stored in patient wallet.'));
    console.log(chalk.gray('   Next step → Patient generates a ZK Proof  (use "Generate ZK Proof")\n'));
  } catch (error) {
    console.log(chalk.red(`❌  Error issuing bill: ${error.message}\n`));
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// STEP 1  Insurance Issues Policy to Patient
// The insurer creates a policy credential and stores it in the patient's wallet.
// The patient will later use this (alongside the hospital bill) to generate a ZKP.
// ──────────────────────────────────────────────────────────────────────────────
async function insuranceIssuePolicy() {
  const agents = agentManager.listAgents();
  const insurers = agents.filter(a => a.type === 'insurer');
  const patients = agents.filter(a => a.type === 'patient');

  if (insurers.length === 0) {
    console.log(chalk.yellow('\n⚠️  No insurance company agents found.'));
    console.log(chalk.gray('   → Create an insurer agent first via "Create New Agent"\n'));
    return;
  }

  if (patients.length === 0) {
    console.log(chalk.yellow('\n⚠️  No patient agents found.'));
    console.log(chalk.gray('   → Create a patient agent first via "Create New Agent"\n'));
    return;
  }

  console.log(chalk.cyan.bold('\n╔══════════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║   💳  Insurance Policy Issuance               ║'));
  console.log(chalk.cyan.bold('╚══════════════════════════════════════════════╝'));
  console.log(chalk.gray('   Insurer issues a signed policy credential to the patient.\n'));

  // ── Select parties ──────────────────────────────────────────────────────────
  const { insurerId } = await inquirer.prompt([{
    type: 'list',
    name: 'insurerId',
    message: '🏢  Select Insurance Company:',
    choices: insurers.map(i => ({
      name: `${AGENT_TYPES.insurer?.icon || '💳'}  ${i.name}`,
      value: i.id,
      short: i.name
    }))
  }]);

  const { patientId } = await inquirer.prompt([{
    type: 'list',
    name: 'patientId',
    message: '🧑  Select Patient (policy holder):',
    choices: patients.map(p => ({
      name: `${AGENT_TYPES.patient?.icon || '🧑'}  ${p.name}`,
      value: p.id,
      short: p.name
    }))
  }]);

  const patient = agentManager.getAgent(patientId);

  // ── Policy details ──────────────────────────────────────────────────────────
  console.log(chalk.yellow('\n📋  Policy Details\n'));

  const policyDetails = await inquirer.prompt([
    {
      type: 'input',
      name: 'planName',
      message: '  Plan Name  (e.g. "Gold Health Plan"):',
      validate: input => input.trim() ? true : 'Plan name is required'
    },
    {
      type: 'input',
      name: 'coverageAmount',
      message: '  Maximum Coverage Amount ($):',
      validate: input => !isNaN(parseFloat(input)) && parseFloat(input) > 0
        ? true : 'Enter a valid amount (e.g. 50000)'
    },
    {
      type: 'input',
      name: 'coveragePercent',
      message: '  Coverage Percentage  (0–100):',
      default: '80',
      validate: input => {
        const n = parseInt(input);
        return (!isNaN(n) && n >= 0 && n <= 100) ? true : 'Enter a number between 0 and 100';
      }
    },
    {
      type: 'input',
      name: 'coveredDiagnoses',
      message: '  Covered Conditions  (comma-separated, or "ALL"):',
      default: 'ALL',
      validate: input => input.trim() ? true : 'Required'
    },
    {
      type: 'input',
      name: 'deductible',
      message: '  Annual Deductible ($):',
      default: '500',
      validate: input => !isNaN(parseFloat(input)) && parseFloat(input) >= 0
        ? true : 'Enter a valid amount (e.g. 500)'
    },
    {
      type: 'input',
      name: 'validUntil',
      message: '  Policy Valid Until  (YYYY-MM-DD):',
      default: (() => {
        const d = new Date();
        d.setFullYear(d.getFullYear() + 1);
        return d.toISOString().split('T')[0];
      })(),
      validate: input => /^\d{4}-\d{2}-\d{2}$/.test(input) ? true : 'Use format YYYY-MM-DD'
    }
  ]);

  // ── Auto-derive ─────────────────────────────────────────────────────────────
  const policyNumber = `POL-${Date.now()}`;
  const issuedDate  = new Date().toISOString();

  const credentialData = {
    type: 'InsurancePolicy',
    claims: {
      policyNumber,
      policyHolder:     patient.name,
      planName:         policyDetails.planName,
      coverageAmount:   `$${parseFloat(policyDetails.coverageAmount).toFixed(2)}`,
      coveragePercent:  `${policyDetails.coveragePercent}%`,
      coveredDiagnoses: policyDetails.coveredDiagnoses,
      deductible:       `$${parseFloat(policyDetails.deductible).toFixed(2)}`,
      issuedDate,
      validUntil:       policyDetails.validUntil,
      status:           'Active'
    }
  };

  try {
    await agentManager.issueCredential(insurerId, patientId, credentialData);

    console.log(chalk.green('\n✅  Insurance policy issued successfully!'));
    console.log(chalk.cyan(`   Policy Number : ${policyNumber}`));
    console.log(chalk.cyan(`   Plan          : ${policyDetails.planName}`));
    console.log(chalk.cyan(`   Coverage      : ${policyDetails.coveragePercent}% up to $${parseFloat(policyDetails.coverageAmount).toFixed(2)}`));
    console.log(chalk.cyan(`   Valid Until   : ${policyDetails.validUntil}`));
    console.log(chalk.gray('\n   Policy credential stored in patient wallet.\n'));
    console.log(chalk.gray('   Next step → Hospital issues a Medical Bill  (use "Hospital Issues Bill")\n'));
  } catch (error) {
    console.log(chalk.red(`❌  Error issuing policy: ${error.message}\n`));
  }
}

// Issue custom credential (kept for advanced use / dev testing)
async function issueCredential() {
  const agents = agentManager.listAgents();

  if (agents.length < 2) {
    console.log(chalk.yellow('\n⚠️  Need at least 2 agents to issue credentials\n'));
    return;
  }

  console.log(chalk.yellow.bold('\n📄 Issue Credential\n'));

  const agentChoices = agents.map(a => {
    const agentType = AGENT_TYPES[a.type];
    const icon = agentType ? agentType.icon : '📦';
    return {
      name: `${icon}  ${a.name.padEnd(25)} (${a.type})`,
      value: a.id,
      short: a.name
    };
  });

  const issuerAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'issuer',
      message: 'Select issuer:',
      choices: agentChoices,
      pageSize: 10
    }
  ]);

  const issuer = agentManager.getAgent(issuerAnswer.issuer);
  const issuerConfig = AGENT_TYPES[issuer.type];
  
  let availableSchemas = Object.keys(CREDENTIAL_SCHEMAS);
  
  if (issuerConfig && issuerConfig.canIssue && issuerConfig.canIssue.length > 0) {
    console.log(chalk.cyan(`\n${issuerConfig.icon} ${issuer.name} can issue: ${issuerConfig.canIssue.join(', ')}\n`));
    availableSchemas = issuerConfig.canIssue;
  }

  const credTypeChoices = availableSchemas.map(type => {
    const schema = CREDENTIAL_SCHEMAS[type];
    return {
      name: `${type.padEnd(25)} - ${schema.required?.join(', ') || 'Custom'}`,
      value: type,
      short: type
    };
  });

  const credTypeAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'credentialType',
      message: 'Select credential type:',
      choices: credTypeChoices,
      pageSize: 10
    }
  ]);

  const subjectAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'subject',
      message: 'Select subject (recipient):',
      choices: agentChoices.filter(c => c.value !== issuerAnswer.issuer),
      pageSize: 10
    }
  ]);

  const schema = CREDENTIAL_SCHEMAS[credTypeAnswer.credentialType];
  
  console.log(chalk.cyan(`\n📝 Enter credential details:\n`));
  
  const claimPrompts = [];
  
  for (const [field, config] of Object.entries(schema.properties)) {
    const isRequired = schema.required?.includes(field);
    
    claimPrompts.push({
      type: 'input',
      name: field,
      message: `${isRequired ? '* ' : '  '}${config.description}:`,
      default: config.format === 'date' ? new Date().toISOString().split('T')[0] : undefined,
      validate: (input) => {
        if (isRequired && !input.trim()) {
          return `${field} is required`;
        }
        return true;
      }
    });
  }

  const claims = await inquirer.prompt(claimPrompts);

  Object.keys(claims).forEach(key => {
    if (!claims[key]) delete claims[key];
  });

  const credentialData = {
    type: credTypeAnswer.credentialType,
    claims
  };

  try {
    await agentManager.issueCredential(
      issuerAnswer.issuer,
      subjectAnswer.subject,
      credentialData
    );
  } catch (error) {
    console.log(chalk.red(`❌ Error: ${error.message}\n`));
  }
}

// Verify credential
async function verifyCredential() {
  const agents = agentManager.listAgents();
  const agentsWithCredentials = agents.filter(a => a.credentials && a.credentials.length > 0);

  if (agentsWithCredentials.length === 0) {
    console.log(chalk.yellow('\n⚠️  No credentials found\n'));
    return;
  }

  if (agents.length < 2) {
    console.log(chalk.yellow('\n⚠️  Need at least 2 agents (one holder, one verifier)\n'));
    return;
  }

  console.log(chalk.yellow.bold('\n🔍 Verify Credential\n'));

  const holderAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'holder',
      message: 'Select credential holder:',
      choices: agentsWithCredentials.map(a => ({
        name: `${a.name.padEnd(25)} (${a.credentials.length} credential(s))`,
        value: a.id
      }))
    }
  ]);

  const holder = agentManager.getAgent(holderAnswer.holder);
  
  const credAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'credentialIndex',
      message: 'Select credential to verify:',
      choices: holder.credentials.map((cred, index) => {
        const date = new Date(cred.issuedAt).toLocaleDateString();
        const status = cred.status === 'revoked' ? chalk.red('[REVOKED]') : '';
        return {
          name: `${cred.type.padEnd(25)} - ${cred.issuer} ${status}`,
          value: index
        };
      })
    }
  ]);

  // Let user pick who is verifying (should be different from holder)
  const verifierChoices = agents
    .filter(a => a.id !== holderAnswer.holder)
    .map(a => {
      const agentType = AGENT_TYPES[a.type];
      const icon = agentType ? agentType.icon : '📦';
      return {
        name: `${icon}  ${a.name.padEnd(25)} (${a.type})`,
        value: a.id,
        short: a.name
      };
    });

  const verifierAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'verifier',
      message: 'Select verifier:',
      choices: verifierChoices,
      pageSize: 10
    }
  ]);

  try {
    const credential = holder.credentials[credAnswer.credentialIndex].credential;
    await agentManager.verifyCredential(verifierAnswer.verifier, credential);
  } catch (error) {
    console.log(chalk.red(`❌ Error: ${error.message}\n`));
  }
}

// Revoke credential
async function revokeCredential() {
  const agents = agentManager.listAgents();
  const agentsWithCreds = agents.filter(a => a.credentials && a.credentials.length > 0);

  if (agentsWithCreds.length === 0) {
    console.log(chalk.yellow('\n⚠️  No agents with credentials found\n'));
    return;
  }

  const agentAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'agentId',
      message: 'Select agent whose credential to revoke:',
      choices: agentsWithCreds.map(a => ({
        name: `${a.name} (${a.credentials.length} credential(s))`,
        value: a.id
      }))
    }
  ]);

  const selectedAgent = agentManager.getAgent(agentAnswer.agentId);

  const credChoices = selectedAgent.credentials.map((cred, idx) => ({
    name: `${cred.type} - Issued by ${cred.issuer} on ${new Date(cred.issuedAt).toLocaleDateString()}`,
    value: idx
  }));

  const credAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'credIndex',
      message: 'Select credential to revoke:',
      choices: credChoices
    },
    {
      type: 'confirm',
      name: 'confirm',
      message: chalk.red('⚠️  This will permanently revoke the credential. Continue?'),
      default: false
    }
  ]);

  if (credAnswer.confirm) {
    try {
      const credential = selectedAgent.credentials[credAnswer.credIndex];
      const issuers = agents.filter(a => a.did === credential.issuerDid);
      
      if (issuers.length === 0) {
        console.log(chalk.red('\n❌ Issuer agent not found\n'));
        return;
      }

      await agentManager.revokeCredential(issuers[0].id, credential.credential);
      credential.status = 'revoked';
      credential.revokedAt = Date.now();
      
      // Persist revocation status to wallet file
      await agentManager.saveToWallet(
        agentAnswer.agentId,
        'credentials',
        credential,
        `${credential.id}.json`
      );
      
      console.log(chalk.green('✅ Credential revoked successfully\n'));
    } catch (error) {
      console.log(chalk.red(`❌ Revocation failed: ${error.message}\n`));
    }
  }
}

// Export agent wallet
async function exportAgentWallet() {
  const agents = agentManager.listAgents();

  if (agents.length === 0) {
    console.log(chalk.yellow('\n⚠️  No agents found\n'));
    return;
  }

  const answer = await inquirer.prompt([
    {
      type: 'list',
      name: 'agent',
      message: 'Select agent to export:',
      choices: agents.map(a => ({
        name: `${a.name} (${a.type})`,
        value: a.id
      }))
    }
  ]);

  try {
    const exportData = await agentManager.exportAgentWallet(answer.agent);
    const agent = agentManager.getAgent(answer.agent);
    const filename = `./data/exports/${agent.name.toLowerCase().replace(/\s+/g, '-')}-wallet-export.json`;
    
    await fs.mkdir('./data/exports', { recursive: true });
    await fs.writeFile(filename, JSON.stringify(exportData, null, 2));
    
    console.log(chalk.green(`\n✅ Wallet exported to: ${filename}\n`));
  } catch (error) {
    console.log(chalk.red(`❌ Error: ${error.message}\n`));
  }
}

// Check balances
async function checkBalances() {
  const agents = agentManager.listAgents();

  if (agents.length === 0) {
    console.log(chalk.yellow('\n⚠️  No agents found\n'));
    return;
  }

  console.log(chalk.cyan.bold('\n💰 Agent Balances\n'));

  const table = new Table({
    head: [
      chalk.white.bold('Agent'),
      chalk.white.bold('Ethereum Address'),
      chalk.white.bold('Balance (ETH)')
    ],
    colWidths: [25, 45, 20]
  });

  for (const agent of agents) {
    if (agent.blockchainAddress) {
      try {
        const balance = await agentManager.getBlockchainBalance(agent.id);
        table.push([
          chalk.cyan(agent.name),
          chalk.gray(agent.blockchainAddress),
          chalk.green(balance.ether)
        ]);
      } catch (error) {
        table.push([
          chalk.cyan(agent.name),
          chalk.gray(agent.blockchainAddress),
          chalk.red('Error')
        ]);
      }
    }
  }

  console.log(table.toString());

  // Show funder wallet balance
  if (agentManager.blockchain?.funderWallet) {
    try {
      const funderInfo = await agentManager.blockchain.getFunderInfo();
      if (funderInfo.initialized) {
        console.log(chalk.magenta.bold('\n💳 Funder Wallet'));
        console.log(chalk.gray(`   Address: ${funderInfo.address}`));
        console.log(chalk.gray(`   Balance: ${funderInfo.balance} ETH`));
        if (parseFloat(funderInfo.balance) < 0.01) {
          console.log(chalk.yellow(`   ⚠️  Low! Fund at https://sepoliafaucet.com/`));
        }
      }
    } catch {
      // Not critical
    }
  }
  console.log('');
}

// Show blockchain info
async function showBlockchainInfo() {
  console.log(chalk.cyan.bold('\n📊 Blockchain Information\n'));

  try {
    if (!agentManager.blockchain) {
      console.log(chalk.yellow('⚠️  Blockchain not initialized. Running in offline mode.\n'));
      return;
    }

    const config = await agentManager.blockchain.loadConfig();
    const table = new Table({
      head: [chalk.white.bold('Property'), chalk.white.bold('Value')],
      colWidths: [30, 50]
    });

    table.push(
      ['Network', chalk.cyan(agentManager.network)],
      ['Contract Address', config.contractAddress ? chalk.green(config.contractAddress) : chalk.red('Not deployed')],
      ['Deployed At', config.deployedAt || 'N/A'],
      ['ZKP Module', agentManager.zkp ? chalk.green('Active') : chalk.yellow('Not initialized')]
    );

    if (agentManager.blockchain.contract) {
      const count = await agentManager.blockchain.getCredentialCount();
      table.push(['Credentials On-Chain', chalk.cyan(count.toString())]);
    }

    console.log(table.toString());
    console.log('');

    if (config.contractAddress) {
      const explorerUrl = agentManager.blockchain.getExplorerUrl('address', config.contractAddress);
      if (explorerUrl) {
        console.log(chalk.gray(`🔍 View on Explorer: ${explorerUrl}\n`));
      }
    }
  } catch (error) {
    console.log(chalk.red(`❌ Error: ${error.message}\n`));
  }
}

// View statistics
function viewStatistics() {
  const stats = agentManager.getStatistics();

  console.log(chalk.cyan.bold('\n📊 System Statistics\n'));

  const table = new Table({
    head: [chalk.white.bold('Metric'), chalk.white.bold('Value')],
    colWidths: [30, 20]
  });

  table.push(
    ['Total Agents', chalk.cyan(stats.totalAgents)],
    ['Total Connections', chalk.green(stats.totalConnections)],
    ['Total Credentials', chalk.blue(stats.totalCredentials)],
    ['Blockchain Network', chalk.yellow(stats.blockchainNetwork)],
    ['ZKP Module', agentManager.zkp ? chalk.magenta('Active') : chalk.gray('Inactive')]
  );

  console.log(table.toString());
  console.log('');

  if (Object.keys(stats.agentsByType).length > 0) {
    console.log(chalk.yellow.bold('Agents by Type:\n'));
    
    const typeTable = new Table({
      head: [chalk.white.bold('Type'), chalk.white.bold('Count')],
      colWidths: [30, 20]
    });

    for (const [type, count] of Object.entries(stats.agentsByType)) {
      const agentType = AGENT_TYPES[type];
      const label = agentType ? `${agentType.icon} ${agentType.label}` : type;
      typeTable.push([label, chalk.cyan(count)]);
    }

    console.log(typeTable.toString());
    console.log('');
  }
}

// Clean all data
async function cleanData() {
  const confirm = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: chalk.red('⚠️  Delete ALL agents and data? This cannot be undone.'),
      default: false
    }
  ]);

  if (confirm.confirm) {
    const doubleConfirm = await inquirer.prompt([
      {
        type: 'input',
        name: 'confirmation',
        message: 'Type "DELETE ALL" to confirm:',
        validate: (input) => input === 'DELETE ALL' ? true : 'Type DELETE ALL'
      }
    ]);

    if (doubleConfirm.confirmation === 'DELETE ALL') {
      try {
        await agentManager.cleanAll();
        console.log(chalk.green('\n✅ All data cleaned\n'));
      } catch (error) {
        console.log(chalk.red(`❌ Error: ${error.message}\n`));
      }
    }
  } else {
    console.log(chalk.gray('Cancelled\n'));
  }
}

// Main application loop
async function main() {
  displayBanner();
  
  // Initialize blockchain (this also initializes ZKP module now)
  try {
    await agentManager.initializeBlockchain();
    console.log(chalk.green('✅ Blockchain initialized\n'));
  } catch (error) {
    console.log(chalk.yellow('⚠️  Blockchain offline mode\n'));
  }

  // Load existing agents
  const count = await agentManager.loadAgents();
  if (count > 0) {
    console.log(chalk.green(`✅ Loaded ${count} agent${count !== 1 ? 's' : ''}\n`));
  } else {
    console.log(chalk.gray('No existing agents. Create your first agent!\n'));
  }

  displayStats();

  let running = true;

  while (running) {
    const action = await mainMenu();

    try {
      switch (action) {
        case 'create':
          await createAgent();
          break;
        case 'list':
          listAgents();
          break;
        case 'view':
          await viewAgentDetails();
          break;
        case 'stats':
          viewStatistics();
          break;
        case 'delete':
          await deleteAgent();
          break;
        case 'issue-bill':
          await hospitalIssueBill();
          break;
        case 'issue-policy':
          await insuranceIssuePolicy();
          break;
        case 'verify':
          await verifyCredential();
          break;
        case 'revoke':
          await revokeCredential();
          break;
        case 'export':
          await exportAgentWallet();
          break;
        case 'balances':
          await checkBalances();
          break;
        case 'blockchain-info':
          await showBlockchainInfo();
          break;
        case 'clean':
          await cleanData();
          break;
        case 'exit':
          console.log(chalk.cyan.bold('\n👋 Thank you for using SSI Healthcare System!\n'));
          running = false;
          break;
        // ZKP actions — delegated to zkpMenu.js handler
        case 'zkp-request':
        case 'zkp-generate':
        case 'zkp-submit':
        case 'zkp-verify':
        case 'zkp-list':
        case 'zkp-received':
        case 'zkp-reimbursements':
          await handleZKPAction(action, agentManager);
          break;
      }
    } catch (error) {
      console.error(chalk.red('\n❌ Error:'), error.message);
      console.log('');
    }

    if (running && action !== 'exit') {
      await inquirer.prompt([
        {
          type: 'input',
          name: 'continue',
          message: chalk.gray('\nPress Enter to continue...')
        }
      ]);
      displayBanner();
      displayStats();
    }
  }
}

// Graceful shutdown helper
async function gracefulShutdown() {
  try {
    if (agentManager.blockchain?.provider) {
      try { agentManager.blockchain.provider.destroy(); } catch {}
    }
    for (const agent of agentManager.agents.values()) {
      try {
        if (agent.agent?._context?.dataStore?.dbConnection?.isInitialized) {
          await agent.agent._context.dataStore.dbConnection.destroy();
        }
      } catch {}
    }
  } catch {}
  process.exit(0);
}

process.on('SIGINT', async () => {
  console.log(chalk.cyan.bold('\n\n👋 Shutting down...\n'));
  await gracefulShutdown();
});

// Error handling
main().then(() => gracefulShutdown()).catch(error => {
  console.error(chalk.red('\n❌ Fatal Error:'), error);
  console.error(error.stack);
  process.exit(1);
});
