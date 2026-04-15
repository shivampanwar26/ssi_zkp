#!/usr/bin/env bash
# =============================================================================
# circuits/setup.sh — One-time trusted setup for MedicalCredential circuit
# =============================================================================
# Run from the circuits/ directory:
#   cd src/circuits
#   chmod +x setup.sh
#   ./setup.sh
# =============================================================================

set -e

# ── Resolve directories ───────────────────────────────────────────────────────
CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# src/circuits/ → go up two levels to reach project root
PROJECT_ROOT="$(cd "$CIRCUITS_DIR/../.." && pwd)"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ZKP Trusted Setup — MedicalCredential Circuit          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "   Circuits dir : $CIRCUITS_DIR"
echo "   Project root : $PROJECT_ROOT"
echo ""

# ── Install ZKP deps into project root ───────────────────────────────────────
echo "📦 Installing dependencies into project root..."
cd "$PROJECT_ROOT"
npm install --save snarkjs circomlibjs
npm install --save-dev circom2 circomlib

# circom2 npm package installs a compiled Rust binary, NOT a JS file.
# The binary lands at node_modules/.bin/circom2 (not circom2/cli.js).
CIRCOM_BIN="$PROJECT_ROOT/node_modules/.bin/circom2"
if [ ! -f "$CIRCOM_BIN" ]; then
    CIRCOM_BIN="$PROJECT_ROOT/node_modules/.bin/circom"
fi
SNARKJS="$PROJECT_ROOT/node_modules/snarkjs/cli.js"
CIRCOMLIB="$PROJECT_ROOT/node_modules/circomlib"

[ -f "$CIRCOM_BIN" ] || { echo "❌ circom binary not found at $CIRCOM_BIN"; exit 1; }
[ -f "$SNARKJS"    ] || { echo "❌ snarkjs not found at $SNARKJS";          exit 1; }
[ -d "$CIRCOMLIB"  ] || { echo "❌ circomlib not found at $CIRCOMLIB";      exit 1; }

echo "✅ Dependencies installed"
echo "   circom   : $CIRCOM_BIN"
echo "   snarkjs  : $SNARKJS"
echo "   circomlib: $CIRCOMLIB"
echo ""

# ── Back to circuits dir ──────────────────────────────────────────────────────
cd "$CIRCUITS_DIR"
mkdir -p build ptau

# ── Compile circuit ───────────────────────────────────────────────────────────
echo "⚙️  Compiling circuit (medical_credential.circom)..."
# -l tells circom where to search for includes (circomlib/circuits/*)
"$CIRCOM_BIN" \
  medical_credential.circom \
  --r1cs --wasm --sym \
  -l "$PROJECT_ROOT/node_modules" \
  -o build/

[ -f "build/medical_credential.r1cs" ] \
  || { echo "❌ R1CS missing — compilation failed"; exit 1; }
[ -f "build/medical_credential_js/medical_credential.wasm" ] \
  || { echo "❌ WASM missing — compilation failed"; exit 1; }

echo "✅ Circuit compiled"
echo "   R1CS : build/medical_credential.r1cs"
echo "   WASM : build/medical_credential_js/medical_credential.wasm"
echo ""

# ── Phase 1: Powers of Tau ────────────────────────────────────────────────────
echo "🔑 Phase 1: Powers of Tau (BN128, power 12)..."

node "$SNARKJS" powersoftau new bn128 12 ptau/pot12_0000.ptau

ENTROPY="SSI_$(date +%s)_$(cat /dev/urandom | head -c 16 | xxd -p 2>/dev/null || echo fallback)"
echo "   Contributing randomness..."
node "$SNARKJS" powersoftau contribute \
  ptau/pot12_0000.ptau ptau/pot12_0001.ptau \
  --name="healthcare_setup" -e="$ENTROPY"

echo "   Preparing phase 2 (~30s)..."
node "$SNARKJS" powersoftau prepare phase2 \
  ptau/pot12_0001.ptau ptau/pot12_final.ptau

echo "✅ Phase 1 complete"
echo ""

# ── Phase 2: Circuit-specific keys ───────────────────────────────────────────
echo "🔑 Phase 2: Circuit-specific proving key..."

node "$SNARKJS" groth16 setup \
  build/medical_credential.r1cs \
  ptau/pot12_final.ptau \
  build/proving_0000.zkey

ENTROPY2="circuit_$(date +%s)_$(cat /dev/urandom | head -c 16 | xxd -p 2>/dev/null || echo fallback2)"
echo "   Contributing randomness to zkey..."
node "$SNARKJS" zkey contribute \
  build/proving_0000.zkey build/proving.zkey \
  --name="healthcare_circuit" -e="$ENTROPY2"

echo "   Exporting verification key..."
node "$SNARKJS" zkey export verificationkey \
  build/proving.zkey build/vk.json

[ -f "build/proving.zkey" ] || { echo "❌ proving.zkey missing"; exit 1; }
[ -f "build/vk.json"      ] || { echo "❌ vk.json missing";      exit 1; }

echo "✅ Phase 2 complete"
echo ""

# ── Fix ESM/CJS conflict for witness generator ────────────────────────────────
# circom emits CommonJS files. If package.json has "type":"module", Node
# refuses to run .js files with require(). .cjs extension forces CommonJS.
cp build/medical_credential_js/generate_witness.js  build/medical_credential_js/generate_witness.cjs
cp build/medical_credential_js/witness_calculator.js build/medical_credential_js/witness_calculator.cjs
sed -i 's/witness_calculator\.js/witness_calculator.cjs/' \
    build/medical_credential_js/generate_witness.cjs

# ── Sanity test ───────────────────────────────────────────────────────────────
echo "🧪 Running sanity test..."
NODE_PATH="$PROJECT_ROOT/node_modules" node \
  "$CIRCUITS_DIR/test_circuit.js" \
  "$CIRCUITS_DIR/build/medical_credential_js/medical_credential.wasm" \
  "$CIRCUITS_DIR/build/proving.zkey" \
  "$CIRCUITS_DIR/build/vk.json"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ✅  Setup complete! Artifacts in circuits/build/         ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  medical_credential.wasm  —  witness generator           ║"
echo "║  proving.zkey             —  proving key                 ║"
echo "║  vk.json                  —  verification key            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
