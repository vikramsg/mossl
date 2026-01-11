#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "============================================================"
echo "Cryptography Micro-benchmark Comparison"
echo "============================================================"
echo ""

echo "---------------------------------------------------"
echo "Running Python Benchmarks..."
echo "---------------------------------------------------"
pixi run python "$SCRIPT_DIR/bench_crypto.py"
echo ""

echo "---------------------------------------------------"
echo "Running Mojo Benchmarks..."
echo "---------------------------------------------------"
pixi run mojo run -I "$PROJECT_ROOT/src" "$SCRIPT_DIR/bench_crypto.mojo"
echo ""

echo "============================================================"
