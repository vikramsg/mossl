#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo "HTTPS GET Benchmark Comparison"
echo "============================================================"
echo ""

# Run Python benchmark
echo "---------------------------------------------------"
echo "Running Python Benchmark..."
echo "---------------------------------------------------"
PYTHON_START=$(date +%s.%N)
PYTHON_OUTPUT=$(timeout 120s pixi run python "$PROJECT_ROOT/bench/bench_https_get.py" 2>&1)
PYTHON_EXIT=$?
PYTHON_END=$(date +%s.%N)
PYTHON_DURATION=$(python3 -c "print($PYTHON_END - $PYTHON_START)")

echo "$PYTHON_OUTPUT"
echo ""

if [ $PYTHON_EXIT -ne 0 ]; then
    echo "WARNING: Python benchmark exited with code $PYTHON_EXIT"
fi

echo "Python benchmark wall-clock time: ${PYTHON_DURATION}s"
echo ""

# Run Mojo benchmark
echo "---------------------------------------------------"
echo "Running Mojo Benchmark..."
echo "---------------------------------------------------"
MOJO_START=$(date +%s.%N)
MOJO_OUTPUT=$(timeout 120s pixi run mojo run -I src "$PROJECT_ROOT/bench/bench_https_get.mojo" 2>&1)
MOJO_EXIT=$?
MOJO_END=$(date +%s.%N)
MOJO_DURATION=$(python3 -c "print($MOJO_END - $MOJO_START)")

echo "$MOJO_OUTPUT"
echo ""

if [ $MOJO_EXIT -ne 0 ]; then
    echo "WARNING: Mojo benchmark exited with code $MOJO_EXIT"
fi

echo "Mojo benchmark wall-clock time: ${MOJO_DURATION}s"
echo ""

# Summary comparison
echo "============================================================"
echo "Timing Summary"
echo "============================================================"
printf "%-20s %10.3f seconds\n" "Python:" "$PYTHON_DURATION"
printf "%-20s %10.3f seconds\n" "Mojo:" "$MOJO_DURATION"

if [ -n "$PYTHON_DURATION" ] && [ -n "$MOJO_DURATION" ]; then
    SPEEDUP=$(python3 -c "ratio = $PYTHON_DURATION / $MOJO_DURATION if $MOJO_DURATION > 0 else 0; print(f'{ratio:.2f}')")
    if [ $(python3 -c "print(1 if $PYTHON_DURATION > $MOJO_DURATION else 0)") -eq 1 ]; then
        printf "%-20s %10.2fx faster\n" "Mojo is:" "$SPEEDUP"
    else
        SPEEDUP=$(python3 -c "ratio = $MOJO_DURATION / $PYTHON_DURATION if $PYTHON_DURATION > 0 else 0; print(f'{ratio:.2f}')")
        printf "%-20s %10.2fx faster\n" "Python is:" "$SPEEDUP"
    fi
fi

echo "============================================================"

