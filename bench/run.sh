#!/bin/bash
set -e

# 1. Run Mojo Benchmarks
echo "---------------------------------------------------"
echo "Running Mojo Benchmarks..."
# Using timeout to prevent the slow ECDSA from hanging indefinitely
timeout 60s pixi run mojo run -I src -I . bench/bench_crypto.mojo

# 2. Run Python Benchmarks
echo "---------------------------------------------------"
echo "Running Python Benchmarks (Reference)..."
pixi run python bench/bench_crypto.py
echo "---------------------------------------------------"