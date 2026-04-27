/**
 * plot_gas.js — Gas Usage per Operation bar chart
 *
 * Usage:
 *   node plot_gas.js
 *
 * Output:
 *   gas_usage_plot.png
 *
 * Dependencies:
 *   npm install canvas
 */

import { createCanvas } from 'canvas';
import fs from 'fs/promises';

// ── Data ──────────────────────────────────────────────────────────────────────
const operations = ['Register DID', 'Store Credential', 'Revoke Credential'];
const gasUsed    = [159595, 247486, 78945];

const colors  = ['#4E79A7', '#E15759', '#59A14F'];
const borders = ['#3b6490', '#c44648', '#478e3e'];

// ── Helpers ───────────────────────────────────────────────────────────────────
function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

// ── Chart ─────────────────────────────────────────────────────────────────────
async function plotGasUsage() {
  const W = 750, H = 420;
  const canvas = createCanvas(W, H);
  const ctx = canvas.getContext('2d');

  // Background
  const bg = ctx.createLinearGradient(0, 0, 0, H);
  bg.addColorStop(0, '#f8fafc');
  bg.addColorStop(1, '#e2e8f0');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, W, H);

  const margin = { top: 30, right: 50, bottom: 70, left: 100 };
  const chartW = W - margin.left - margin.right;
  const chartH = H - margin.top - margin.bottom;

  const yMax = Math.ceil(Math.max(...gasUsed) * 1.2 / 50000) * 50000;

  // ── Grid lines ──
  const nGrid = 5;
  for (let i = 0; i <= nGrid; i++) {
    const y = margin.top + chartH - (i / nGrid) * chartH;
    const val = Math.round((yMax / nGrid) * i);

    ctx.strokeStyle = '#cbd5e1';
    ctx.lineWidth = 0.8;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(margin.left, y);
    ctx.lineTo(W - margin.right, y);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.fillStyle = '#64748b';
    ctx.font = '12px "Segoe UI", Arial, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(val.toLocaleString(), margin.left - 12, y + 4);
  }

  // ── Y-axis label ──
  ctx.save();
  ctx.translate(22, margin.top + chartH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = '#475569';
  ctx.font = 'bold 14px "Segoe UI", Arial, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('Gas Used', 0, 0);
  ctx.restore();

  // ── Axes ──
  ctx.strokeStyle = '#94a3b8';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(margin.left, margin.top);
  ctx.lineTo(margin.left, margin.top + chartH);
  ctx.lineTo(W - margin.right, margin.top + chartH);
  ctx.stroke();

  // ── Bars ──
  const barGap = 40;
  const barW = (chartW - barGap * (operations.length + 1)) / operations.length;

  operations.forEach((op, i) => {
    const val = gasUsed[i];
    const x = margin.left + barGap + i * (barW + barGap);
    const barH = (val / yMax) * chartH;
    const y = margin.top + chartH - barH;

    // Shadow
    ctx.fillStyle = 'rgba(0,0,0,0.08)';
    roundRect(ctx, x + 3, y + 3, barW, barH, 6);
    ctx.fill();

    // Bar gradient
    const grad = ctx.createLinearGradient(x, y, x, y + barH);
    grad.addColorStop(0, colors[i]);
    grad.addColorStop(1, borders[i]);
    ctx.fillStyle = grad;
    roundRect(ctx, x, y, barW, barH, 6);
    ctx.fill();

    // Border
    ctx.strokeStyle = borders[i];
    ctx.lineWidth = 1;
    roundRect(ctx, x, y, barW, barH, 6);
    ctx.stroke();

    // Value label above bar
    ctx.fillStyle = '#1e293b';
    ctx.font = 'bold 14px "Segoe UI", Arial, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(val.toLocaleString(), x + barW / 2, y - 10);

    // X-axis label
    ctx.fillStyle = '#334155';
    ctx.font = 'bold 13px "Segoe UI", Arial, sans-serif';
    ctx.textAlign = 'center';

    const words = op.split(' ');
    if (words.length > 1) {
      ctx.fillText(words[0], x + barW / 2, margin.top + chartH + 22);
      ctx.fillText(words.slice(1).join(' '), x + barW / 2, margin.top + chartH + 38);
    } else {
      ctx.fillText(op, x + barW / 2, margin.top + chartH + 30);
    }
  });

  // ── X-axis label ──
  ctx.fillStyle = '#475569';
  ctx.font = 'bold 14px "Segoe UI", Arial, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('Operation', W / 2, H - 8);

  const buf = canvas.toBuffer('image/png');
  await fs.writeFile('gas_usage_plot.png', buf);
  console.log('✅  gas_usage_plot.png');
}

plotGasUsage().catch(err => {
  console.error('Plot failed:', err.message);
  console.error('Make sure you ran:  npm install canvas');
  process.exit(1);
});
