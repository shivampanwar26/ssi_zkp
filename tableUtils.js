/**
 * tableUtils.js — Beautiful CLI table components for SSI Healthcare
 *
 * Usage:
 *   import { Table, dashboardStats, agentTable, credentialTable,
 *            zkProofTable, verificationResult, blockchainStatus } from './tableUtils.js';
 */

import chalk from 'chalk';

// ═══════════════════════════════════════════════════════════
// CORE TABLE ENGINE
// ═══════════════════════════════════════════════════════════

const ICONS = {
  hospital : '🏥',
  patient  : '👤',
  insurer  : '🏢',
  active   : '✅',
  revoked  : '❌',
  pending  : '⏳',
  verified : '✅',
  failed   : '❌',
  unknown  : '❓',
  chain    : '⛓ ',
  key      : '🔑',
  cred     : '📋',
  zkp      : '🔐',
  wallet   : '💳',
  block    : '📦',
  tx       : '🔗',
  sep      : '─',
};

// Strip ANSI codes to get real string length for padding
function visibleLen(str) {
  return String(str).replace(/\x1b\[[0-9;]*m/g, '').replace(/[^\x00-\x7F]/g, '  ').length;
}

function pad(str, width, align = 'left') {
  const s   = String(str ?? '');
  const len = visibleLen(s);
  const gap = Math.max(0, width - len);
  if (align === 'right')  return ' '.repeat(gap) + s;
  if (align === 'center') return ' '.repeat(Math.floor(gap / 2)) + s + ' '.repeat(Math.ceil(gap / 2));
  return s + ' '.repeat(gap);
}

// ═══════════════════════════════════════════════════════════
// GENERIC TABLE — columnar data
// ═══════════════════════════════════════════════════════════

export class Table {
  /**
   * @param {string[]} headers  — column headers
   * @param {string[]} aligns   — 'left' | 'right' | 'center' per column
   */
  constructor(headers, aligns = []) {
    this.headers = headers;
    this.aligns  = aligns;
    this.rows    = [];
    this.title   = null;
    this.footer  = null;
  }

  setTitle(t)  { this.title  = t; return this; }
  setFooter(t) { this.footer = t; return this; }

  addRow(...cells) {
    this.rows.push(cells.map(String));
    return this;
  }

  addDivider() {
    this.rows.push('__DIVIDER__');
    return this;
  }

  render() {
    const cols = this.headers.length;

    // Compute column widths
    const widths = this.headers.map((h, i) => visibleLen(h));
    for (const row of this.rows) {
      if (row === '__DIVIDER__') continue;
      row.forEach((cell, i) => {
        widths[i] = Math.max(widths[i] ?? 0, visibleLen(cell));
      });
    }

    const totalInner = widths.reduce((s, w) => s + w + 2, 0) + (cols - 1);
    const innerW     = totalInner;

    // Border chars
    const tl = '╔', tr = '╗', bl = '╚', br = '╝';
    const hl = '═', vl = '║';
    const ml = '╠', mr = '╣', mt = '╦', mb = '╩', mx = '╬';
    const sl = '╟', sr = '╢', sh = '─', sx = '╫';

    const topLine    = tl + widths.map(w => hl.repeat(w + 2)).join(mt) + tr;
    const midLine    = ml + widths.map(w => hl.repeat(w + 2)).join(mx) + mr;
    const softLine   = sl + widths.map(w => sh.repeat(w + 2)).join(sx) + sr;
    const botLine    = bl + widths.map(w => hl.repeat(w + 2)).join(mb) + br;
    const titleLine  = (t) => tl + hl.repeat(innerW) + tr + '\n' +
                               vl + chalk.bold.white(pad(t, innerW, 'center')) + vl;

    const lines = [];

    if (this.title) {
      const tTop = tl + hl.repeat(innerW) + tr;
      const tMid = ml + widths.map(w => hl.repeat(w + 2)).join(mx) + mr;
      lines.push(chalk.cyan(tTop));
      lines.push(chalk.cyan(vl) + chalk.bold.white(pad(' ' + this.title, innerW)) + chalk.cyan(vl));
      lines.push(chalk.cyan(tMid));
    } else {
      lines.push(chalk.cyan(topLine));
    }

    // Header row
    const headerCells = this.headers.map((h, i) =>
      chalk.bold.yellow(pad(' ' + h + ' ', widths[i] + 2, this.aligns[i]))
    );
    lines.push(chalk.cyan(vl) + headerCells.join(chalk.cyan(vl)) + chalk.cyan(vl));
    lines.push(chalk.cyan(midLine));

    // Data rows
    for (const row of this.rows) {
      if (row === '__DIVIDER__') {
        lines.push(chalk.gray(softLine));
        continue;
      }
      const cells = row.map((cell, i) => {
        const align = this.aligns[i] || 'left';
        return ' ' + pad(cell, widths[i], align) + ' ';
      });
      lines.push(chalk.cyan(vl) + cells.join(chalk.cyan(vl)) + chalk.cyan(vl));
    }

    lines.push(chalk.cyan(botLine));

    if (this.footer) {
      lines.push(chalk.gray('  ' + this.footer));
    }

    console.log(lines.join('\n'));
  }
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD STATS
// ═══════════════════════════════════════════════════════════

export function dashboardStats(stats, blockchainInfo = {}) {
  const width = 55;
  const hl = '═', vl = '║';
  const tl = '╔', tr = '╗', bl = '╚', br = '╝';
  const ml = '╠', mr = '╣';

  const row = (label, value, color = chalk.white) => {
    const l = chalk.gray(pad('  ' + label, 22));
    const v = color(pad(String(value), width - 24));
    return chalk.cyan(vl) + l + chalk.cyan('│') + v + chalk.cyan(vl);
  };

  const divider = chalk.cyan(ml + hl.repeat(22) + '╪' + hl.repeat(width - 23) + mr);
  const top     = chalk.cyan(tl + hl.repeat(width) + tr);
  const bot     = chalk.cyan(bl + hl.repeat(width) + br);

  const titleStr = '  🏥  SSI Healthcare Dashboard';
  const titlePad = pad(titleStr, width);
  const title    = chalk.cyan(vl) + chalk.bold.white(titlePad) + chalk.cyan(vl);

  const netColor = blockchainInfo.connected ? chalk.green : chalk.red;
  const netVal   = blockchainInfo.connected
    ? `${blockchainInfo.network} (block ${blockchainInfo.block})`
    : `${blockchainInfo.network || 'unknown'} — offline`;

  console.log([
    top, title,
    divider,
    row('Agents',       stats.totalAgents,       chalk.cyan),
    row('Hospitals',    stats.agentsByType?.hospital  || 0, chalk.cyan),
    row('Patients',     stats.agentsByType?.patient   || 0, chalk.cyan),
    row('Insurers',     stats.agentsByType?.insurer   || 0, chalk.cyan),
    divider,
    row('Connections',  stats.totalConnections,  chalk.blue),
    row('Credentials',  stats.totalCredentials,  chalk.green),
    divider,
    row('Network',      netVal,                  netColor),
    row('Contract',     blockchainInfo.contract
          ? blockchainInfo.contract.substring(0, 20) + '...'
          : 'not configured',                    chalk.yellow),
    row('On-chain creds', blockchainInfo.credCount ?? '—', chalk.yellow),
    bot,
  ].join('\n'));
}

// ═══════════════════════════════════════════════════════════
// AGENT TABLE
// ═══════════════════════════════════════════════════════════

export function agentTable(agents) {
  if (agents.length === 0) {
    console.log(chalk.yellow('\n  ⚠️  No agents created yet.\n'));
    return;
  }

  const t = new Table(
    ['#', 'Type', 'Name', 'Credentials', 'Wallet', 'DID (short)'],
    ['center', 'center', 'left', 'center', 'left', 'left']
  );
  t.setTitle('👥  Registered Agents');

  agents.forEach((a, i) => {
    const icon    = ICONS[a.type] || '?';
    const typeStr = icon + ' ' + (a.type.charAt(0).toUpperCase() + a.type.slice(1));
    const wallet  = a.blockchainAddress
      ? a.blockchainAddress.substring(0, 10) + '...'
      : chalk.gray('none');
    const did     = a.did
      ? chalk.gray(a.did.substring(0, 24) + '...')
      : chalk.gray('—');
    const creds   = a.credentials?.length > 0
      ? chalk.green(a.credentials.length.toString())
      : chalk.gray('0');

    t.addRow(
      String(i + 1),
      typeStr,
      chalk.white(a.name),
      creds,
      wallet,
      did
    );
  });

  t.render();
}

// ═══════════════════════════════════════════════════════════
// CREDENTIAL TABLE
// ═══════════════════════════════════════════════════════════

export function credentialTable(agentName, credentials) {
  if (!credentials || credentials.length === 0) {
    console.log(chalk.yellow(`\n  ⚠️  ${agentName} has no credentials.\n`));
    return;
  }

  const t = new Table(
    ['#', 'Type', 'Issued By', 'Date', 'Status', 'On-chain'],
    ['center', 'left', 'left', 'left', 'center', 'center']
  );
  t.setTitle(`📋  Credentials — ${agentName}`);

  credentials.forEach((c, i) => {
    const date   = new Date(c.issuedAt).toLocaleDateString();
    const status = c.status === 'active'
      ? chalk.green('✅ Active')
      : chalk.red('❌ Revoked');
    const onChain = c.blockchainTxHash
      ? chalk.green('⛓  Yes')
      : chalk.gray('—  No');

    t.addRow(
      String(i + 1),
      chalk.cyan(c.type),
      c.issuer,
      date,
      status,
      onChain
    );
  });

  t.render();
}

// ═══════════════════════════════════════════════════════════
// ZK PROOF TABLE
// ═══════════════════════════════════════════════════════════

export function zkProofTable(agentName, proofs) {
  if (!proofs || proofs.length === 0) {
    console.log(chalk.yellow(`\n  ⚠️  No ZK proofs found for ${agentName}.\n`));
    return;
  }

  const t = new Table(
    ['#', 'Type', 'Disclosed', 'Hidden', 'Generated', 'Status'],
    ['center', 'left', 'left', 'left', 'left', 'center']
  );
  t.setTitle(`🔐  ZK Proofs — ${agentName}`);

  proofs.forEach((p, i) => {
    const credType  = p.publicInputs?.credentialType || p.type || '—';
    const disclosed = Object.keys(p.publicInputs?.disclosedClaims || {}).join(', ') || chalk.gray('none');
    const hidden    = Object.keys(p.commitments || {}).join(', ') || chalk.gray('none');
    const date      = p.generatedAt
      ? new Date(p.generatedAt).toLocaleString()
      : '—';
    const status    = p.verified === true  ? chalk.green('✅ Verified')
                    : p.verified === false ? chalk.red('❌ Failed')
                    :                        chalk.yellow('⏳ Pending');

    t.addRow(
      String(i + 1),
      chalk.cyan(credType),
      chalk.green(disclosed),
      chalk.yellow(hidden),
      date,
      status
    );
  });

  t.render();
}

// ═══════════════════════════════════════════════════════════
// VERIFICATION RESULT
// ═══════════════════════════════════════════════════════════

export function verificationResult(result) {
  const width = 57;
  const hl = '═', vl = '║';
  const tl = '╔', tr = '╗', bl = '╚', br = '╝';
  const ml = '╠', mr = '╣';

  const check = (val) =>
    val === true  ? chalk.green('✅ Pass') :
    val === false ? chalk.red('❌ Fail') :
                    chalk.yellow('⚠️  Skip');

  const row = (label, val) => {
    const l = chalk.gray(pad('  ' + label, 26));
    const v = pad(val, width - 28);
    return chalk.cyan(vl) + l + chalk.cyan('│') + ' ' + v + chalk.cyan(vl);
  };

  const divider = chalk.cyan(ml + hl.repeat(26) + '╪' + hl.repeat(width - 27) + mr);
  const top     = chalk.cyan(tl + hl.repeat(width) + tr);
  const bot     = chalk.cyan(bl + hl.repeat(width) + br);

  const overall = result.valid
    ? chalk.green.bold('  🎉  VERIFIED SUCCESSFULLY')
    : chalk.red.bold('  🚫  VERIFICATION FAILED');
  const overallRow = chalk.cyan(vl) + pad(overall, width) + chalk.cyan(vl);

  const lines = [
    top,
    chalk.cyan(vl) + chalk.bold.white(pad('  🔍  ZK Proof Verification Result', width)) + chalk.cyan(vl),
    divider,
    row('Structure',    check(result.checks.structureValid)),
    row('Freshness',    check(result.checks.freshnessValid)),
    row('Integrity',    check(result.checks.integrityValid)),
    row('Math Proof',   check(result.checks.proofMathValid)),
    row('Commitments',  check(result.checks.commitmentsValid)),
    row('Issuer DID',   check(result.checks.issuerDIDOnChain)),
    row('Credential',   check(result.checks.credentialOnChain)),
    divider,
    overallRow,
  ];

  // Disclosed data section
  const disclosed = result.disclosedClaims || {};
  if (Object.keys(disclosed).length > 0) {
    lines.push(chalk.cyan(ml + hl.repeat(width) + mr));
    lines.push(
      chalk.cyan(vl) + chalk.bold.yellow(pad('  📤  Disclosed Claims', width)) + chalk.cyan(vl)
    );
    lines.push(divider);
    for (const [k, v] of Object.entries(disclosed)) {
      lines.push(row(k, chalk.white(String(v))));
    }
  }

  lines.push(bot);
  console.log(lines.join('\n'));
}

// ═══════════════════════════════════════════════════════════
// BLOCKCHAIN TX RECEIPT
// ═══════════════════════════════════════════════════════════

export function txReceipt(label, result, network = 'sepolia') {
  if (!result?.transactionHash) return;

  const explorerBase = network === 'sepolia' ? 'https://sepolia.etherscan.io' : null;
  const width = 57;
  const hl = '═', vl = '║';
  const tl = '╔', tr = '╗', bl = '╚', br = '╝';
  const ml = '╠', mr = '╣';

  const row = (k, v) => {
    const l = chalk.gray(pad('  ' + k, 14));
    const val = pad(String(v ?? '—'), width - 16);
    return chalk.cyan(vl) + l + chalk.cyan('│') + ' ' + val + chalk.cyan(vl);
  };

  const div = chalk.cyan(ml + hl.repeat(14) + '╪' + hl.repeat(width - 15) + mr);

  console.log([
    chalk.cyan(tl + hl.repeat(width) + tr),
    chalk.cyan(vl) + chalk.bold.green(pad(`  ⛓   ${label}`, width)) + chalk.cyan(vl),
    div,
    row('TX Hash',  result.transactionHash?.substring(0, 42) + '...'),
    row('Block',    result.blockNumber),
    row('Gas Used', result.gasUsed || '—'),
    explorerBase
      ? row('Explorer', explorerBase + '/tx/' + result.transactionHash)
      : null,
    chalk.cyan(bl + hl.repeat(width) + br),
  ].filter(Boolean).join('\n'));
}

// ═══════════════════════════════════════════════════════════
// BLOCKCHAIN STATUS BAR (single line, always visible)
// ═══════════════════════════════════════════════════════════

export function blockchainStatusBar(blockchainManager) {
  if (!blockchainManager) {
    console.log(chalk.gray('  ⛓  Blockchain: offline'));
    return;
  }

  const connected = !!blockchainManager.contract;
  const network   = blockchainManager.network || 'unknown';
  const address   = blockchainManager.contractAddress;

  const status = connected
    ? chalk.green(`⛓  ${network}`) + chalk.gray(' │ ') +
      chalk.yellow(address?.substring(0, 14) + '...')
    : chalk.red('⛓  Blockchain offline');

  console.log('  ' + status + '\n');
}

// ═══════════════════════════════════════════════════════════
// QUICK INFO BOX (single key-value list)
// ═══════════════════════════════════════════════════════════

export function infoBox(title, rows, width = 55) {
  const hl = '═', vl = '║';
  const tl = '╔', tr = '╗', bl = '╚', br = '╝';
  const ml = '╠', mr = '╣';

  const inner = width;
  const div   = chalk.cyan(ml + hl.repeat(inner) + mr);
  const lines = [
    chalk.cyan(tl + hl.repeat(inner) + tr),
    chalk.cyan(vl) + chalk.bold.white(pad('  ' + title, inner)) + chalk.cyan(vl),
    div,
  ];

  for (const [k, v, color] of rows) {
    const colorFn = color || chalk.white;
    const l = chalk.gray(pad('  ' + k, 20));
    const val = colorFn(pad(String(v ?? '—'), inner - 22));
    lines.push(chalk.cyan(vl) + l + chalk.cyan('│') + ' ' + val + chalk.cyan(vl));
  }

  lines.push(chalk.cyan(bl + hl.repeat(inner) + br));
  console.log(lines.join('\n'));
}