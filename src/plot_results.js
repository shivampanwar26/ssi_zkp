/**
 * ============================================================
 *  plot_results.js  —  Generate publication-quality graphs
 *                      from benchmark_results.json
 * ============================================================
 *
 *  Produces two PNG charts:
 *
 *    Fig 1 — Latency bar chart with error bars
 *            Register DID | Store VC | Proof Gen | Proof Verify
 *
 *    Fig 2 — Detailed per-run line chart (shows variance)
 *
 *  Usage:
 *    node plot_results.js                           # reads benchmark_results.json
 *    node plot_results.js --input my_results.json   # custom input
 *    node plot_results.js --demo                    # use built-in demo data
 *
 *  Dependencies:
 *    npm install canvas
 *
 *  Output:
 *    graph_latency_bar.png
 *    graph_latency_detail.png
 * ============================================================
 */

import { createCanvas } from 'canvas';
import fs from 'fs/promises';

// ── CLI ───────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const flagVal = (f, def) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : def; };

const INPUT_FILE = flagVal('--input', 'benchmark_results.json');
const USE_DEMO = flag('--demo');

// ── 4 operations we track ────────────────────────────────────────────────────
const OPS = ['Register DID', 'Store VC', 'Proof Generation', 'Proof Verification'];

// ── Colour palette — vibrant, print-safe ─────────────────────────────────────
const BAR_COLORS = ['#2563eb', '#16a34a', '#dc2626', '#f59e0b'];
const BAR_BORDERS = ['#1d4ed8', '#15803d', '#b91c1c', '#d97706'];

// ── Demo data ────────────────────────────────────────────────────────────────
const DEMO = {
  'Register DID':        { mean: 128, min: 112, max: 149, stddev: 13, raw: [112, 128, 149] },
  'Store VC':            { mean: 405, min: 372, max: 441, stddev: 24, raw: [372, 405, 441] },
  'Proof Generation':    { mean: 1757, min: 1630, max: 1880, stddev: 90, raw: [1630, 1757, 1880] },
  'Proof Verification':  { mean: 133, min: 118, max: 151, stddev: 12, raw: [118, 133, 151] },
};

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

function createGradient(ctx, x, y, h, c1, c2) {
  const g = ctx.createLinearGradient(x, y, x, y + h);
  g.addColorStop(0, c1);
  g.addColorStop(1, c2);
  return g;
}

// ══════════════════════════════════════════════════════════════════════════════
//  FIGURE 1 — Mean Latency Bar Chart with error bars
// ══════════════════════════════════════════════════════════════════════════════
async function plotBarChart(summary) {
  const W = 900, H = 520;
  const canvas = createCanvas(W, H);
  const ctx = canvas.getContext('2d');

  // Background gradient
  const bg = ctx.createLinearGradient(0, 0, 0, H);
  bg.addColorStop(0, '#f8fafc');
  bg.addColorStop(1, '#e2e8f0');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, W, H);

  const margin = { top: 40, right: 60, bottom: 80, left: 90 };
  const chartW = W - margin.left - margin.right;
  const chartH = H - margin.top - margin.bottom;

  const values = OPS.map(op => summary[op]?.mean || 0);
  const mins   = OPS.map(op => summary[op]?.min  || 0);
  const maxes  = OPS.map(op => summary[op]?.max  || 0);
  const yMax   = Math.ceil(Math.max(...maxes) * 1.2 / 200) * 200;

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
    ctx.fillText(val.toLocaleString(), margin.left - 10, y + 4);
  }

  // ── Y-axis label ──
  ctx.save();
  ctx.translate(20, margin.top + chartH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = '#475569';
  ctx.font = 'bold 14px "Segoe UI", Arial, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('Latency (ms)', 0, 0);
  ctx.restore();

  // ── Axes ──
  ctx.strokeStyle = '#94a3b8';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(margin.left, margin.top);
  ctx.lineTo(margin.left, margin.top + chartH);
  ctx.lineTo(W - margin.right, margin.top + chartH);
  ctx.stroke();

  // ── Explanation text ──
  ctx.fillStyle = '#334155';
  ctx.font = '12px "Segoe UI", Arial, sans-serif';
  ctx.textAlign = 'left';
  ctx.fillText('Bars: Mean latency', margin.left, 20);
  ctx.fillText('Error bars: Variability (min–max)', margin.left, 35);

  // ── Bars ──
  const barGap = 30;
  const barW = (chartW - barGap * (OPS.length + 1)) / OPS.length;

  OPS.forEach((op, i) => {
    const val = values[i];
    const x = margin.left + barGap + i * (barW + barGap);
    const barH = (val / yMax) * chartH;
    const y = margin.top + chartH - barH;

    // Bar shadow
    ctx.fillStyle = 'rgba(0,0,0,0.08)';
    roundRect(ctx, x + 3, y + 3, barW, barH, 6);
    ctx.fill();

    // Bar gradient
    ctx.fillStyle = createGradient(ctx, x, y, barH, BAR_COLORS[i], BAR_BORDERS[i]);
    roundRect(ctx, x, y, barW, barH, 6);
    ctx.fill();

    // Bar border
    ctx.strokeStyle = BAR_BORDERS[i];
    ctx.lineWidth = 1;
    roundRect(ctx, x, y, barW, barH, 6);
    ctx.stroke();

    // Error bar (min → max)
    const minY = margin.top + chartH - (mins[i] / yMax) * chartH;
    const maxY = margin.top + chartH - (maxes[i] / yMax) * chartH;
    const cx = x + barW / 2;

    ctx.strokeStyle = '#334155';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(cx, maxY);
    ctx.lineTo(cx, minY);
    ctx.stroke();

    // Caps
    ctx.beginPath();
    ctx.moveTo(cx - 8, maxY);
    ctx.lineTo(cx + 8, maxY);
    ctx.moveTo(cx - 8, minY);
    ctx.lineTo(cx + 8, minY);
    ctx.stroke();

    // ✅ Value label (FIXED: aligned with mean)
    ctx.fillStyle = '#1e293b';
    ctx.font = 'bold 15px "Segoe UI", Arial, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(Math.round(val) + ' ms', cx, y - 10);

    // X-axis label
    ctx.fillStyle = '#334155';
    ctx.font = 'bold 13px "Segoe UI", Arial, sans-serif';
    ctx.textAlign = 'center';

    const words = op.split(' ');
    if (words.length > 1) {
      ctx.fillText(words[0], cx, margin.top + chartH + 22);
      ctx.fillText(words.slice(1).join(' '), cx, margin.top + chartH + 38);
    } else {
      ctx.fillText(op, cx, margin.top + chartH + 30);
    }

    // ✅ Off-chain marking
    if (op === 'Register DID' || op === 'Store VC') {
      ctx.fillStyle = '#059669';
      ctx.font = 'bold 11px "Segoe UI", Arial, sans-serif';
      ctx.fillText('(off-chain)', cx, margin.top + chartH + 52);
    }
  });

  const buf = canvas.toBuffer('image/png');
  await fs.writeFile('graph_latency_bar.png', buf);
  console.log('✅  graph_latency_bar.png');
}

// ══════════════════════════════════════════════════════════════════════════════
//  FIGURE 2 — Per-run detail chart (grouped bars per run)
// ══════════════════════════════════════════════════════════════════════════════
async function plotDetailChart(summary) {
  const W = 900, H = 520;
  const canvas = createCanvas(W, H);
  const ctx = canvas.getContext('2d');

  // Background
  const bg = ctx.createLinearGradient(0, 0, 0, H);
  bg.addColorStop(0, '#f8fafc');
  bg.addColorStop(1, '#e2e8f0');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, W, H);

  const nRuns = summary[OPS[0]]?.raw?.length || 3;

  // No title — user adds caption in LaTeX

  const margin = { top: 40, right: 180, bottom: 80, left: 90 };
  const chartW = W - margin.left - margin.right;
  const chartH = H - margin.top - margin.bottom;

  // Get max value across all runs
  let globalMax = 0;
  OPS.forEach(op => {
    const raw = summary[op]?.raw || [];
    raw.forEach(v => { if (v > globalMax) globalMax = v; });
  });
  const yMax = Math.ceil(globalMax * 1.15 / 200) * 200;

  // Grid
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
    ctx.fillText(val.toLocaleString(), margin.left - 10, y + 4);
  }

  // Y-axis
  ctx.save();
  ctx.translate(20, margin.top + chartH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = '#475569';
  ctx.font = 'bold 14px "Segoe UI", Arial, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('Latency (ms)', 0, 0);
  ctx.restore();

  // Axes
  ctx.strokeStyle = '#94a3b8';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(margin.left, margin.top);
  ctx.lineTo(margin.left, margin.top + chartH);
  ctx.lineTo(W - margin.right, margin.top + chartH);
  ctx.stroke();

  // Grouped bars: each "group" = one run, bars = operations
  const groupGap = 24;
  const innerGap = 3;
  const groupW = (chartW - groupGap * (nRuns + 1)) / nRuns;
  const innerBarW = (groupW - innerGap * (OPS.length - 1)) / OPS.length;

  for (let r = 0; r < nRuns; r++) {
    const gx = margin.left + groupGap + r * (groupW + groupGap);

    OPS.forEach((op, oi) => {
      const raw = summary[op]?.raw || [];
      const val = raw[r] || 0;
      const x = gx + oi * (innerBarW + innerGap);
      const barH = (val / yMax) * chartH;
      const y = margin.top + chartH - barH;

      // Shadow
      ctx.fillStyle = 'rgba(0,0,0,0.06)';
      roundRect(ctx, x + 2, y + 2, innerBarW, barH, 4);
      ctx.fill();

      // Bar
      ctx.fillStyle = BAR_COLORS[oi];
      roundRect(ctx, x, y, innerBarW, barH, 4);
      ctx.fill();

      // Value on bar (only if bar tall enough)
      if (barH > 20) {
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 9px "Segoe UI", Arial, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(Math.round(val), x + innerBarW / 2, y + 14);
      }
    });

    // Run label
    ctx.fillStyle = '#334155';
    ctx.font = 'bold 12px "Segoe UI", Arial, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(`Run ${r + 1}`, gx + groupW / 2, margin.top + chartH + 22);
  }

  // Legend (right side)
  const lx = W - margin.right + 16;
  let ly = margin.top + 10;
  ctx.fillStyle = '#334155';
  ctx.font = 'bold 13px "Segoe UI", Arial, sans-serif';
  ctx.textAlign = 'left';
  ctx.fillText('Legend', lx, ly);
  ly += 22;

  OPS.forEach((op, i) => {
    // Color swatch
    roundRect(ctx, lx, ly - 10, 14, 14, 3);
    ctx.fillStyle = BAR_COLORS[i];
    ctx.fill();

    ctx.fillStyle = '#475569';
    ctx.font = '12px "Segoe UI", Arial, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(op, lx + 20, ly + 2);
    ly += 22;
  });



  const buf = canvas.toBuffer('image/png');
  await fs.writeFile('graph_latency_detail.png', buf);
  console.log('✅  graph_latency_detail.png');
}

// ── Entry point ───────────────────────────────────────────────────────────────
async function main() {
  let summary = { ...DEMO };

  if (!USE_DEMO) {
    try {
      const raw = await fs.readFile(INPUT_FILE, 'utf-8');
      const data = JSON.parse(raw);

      if (data.results) {
        // Raw results file → compute stats
        for (const [key, arr] of Object.entries(data.results)) {
          if (Array.isArray(arr) && arr.length) {
            const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
            const variance = arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
            summary[key] = {
              mean: +mean.toFixed(2),
              min:  +Math.min(...arr).toFixed(2),
              max:  +Math.max(...arr).toFixed(2),
              stddev: +Math.sqrt(variance).toFixed(2),
              raw:  arr,
            };
          }
        }
        console.log(`Loaded raw results from ${INPUT_FILE}`);
      } else {
        summary = data;
        console.log(`Loaded summary from ${INPUT_FILE}`);
      }
    } catch {
      console.log(`⚠  Could not read ${INPUT_FILE} — using demo data`);
    }
  } else {
    console.log('Using built-in demo data (--demo flag)');
  }

  console.log('Generating charts…\n');
  await plotBarChart(summary);
  await plotDetailChart(summary);

  console.log('\nDone! Generated:');
  console.log('  graph_latency_bar.png     — Mean latency with error bars');
  console.log('  graph_latency_detail.png  — Per-run grouped bar chart');
}

main().catch(err => {
  console.error('Plot failed:', err.message);
  console.error('Make sure you ran:  npm install canvas');
  process.exit(1);
});