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

# Compile Mojo benchmark
echo "---------------------------------------------------"
echo "Compiling Mojo Benchmark..."
echo "---------------------------------------------------"
MOJO_BIN="/tmp/bench_https_get"
MOJO_COMPILE_START=$(date +%s.%N)
MOJO_BUILD_OUTPUT=$(timeout 120s pixi run mojo build -I src "$PROJECT_ROOT/bench/bench_https_get.mojo" -o "$MOJO_BIN" 2>&1)
MOJO_COMPILE_EXIT=$?
MOJO_COMPILE_END=$(date +%s.%N)
MOJO_COMPILE_DURATION=$(python3 -c "print($MOJO_COMPILE_END - $MOJO_COMPILE_START)")

echo "$MOJO_BUILD_OUTPUT"
echo ""

if [ $MOJO_COMPILE_EXIT -ne 0 ]; then
    echo "WARNING: Mojo benchmark compile exited with code $MOJO_COMPILE_EXIT"
fi

echo "Mojo compile wall-clock time: ${MOJO_COMPILE_DURATION}s"
echo ""

# Run Mojo benchmark
echo "---------------------------------------------------"
echo "Running Mojo Benchmark..."
echo "---------------------------------------------------"
MOJO_RUN_START=$(date +%s.%N)
MOJO_OUTPUT=$(timeout 120s pixi run "$MOJO_BIN" 2>&1)
MOJO_RUN_EXIT=$?
MOJO_RUN_END=$(date +%s.%N)
MOJO_RUN_DURATION=$(python3 -c "print($MOJO_RUN_END - $MOJO_RUN_START)")

echo "$MOJO_OUTPUT"
echo ""

if [ $MOJO_RUN_EXIT -ne 0 ]; then
    echo "WARNING: Mojo benchmark run exited with code $MOJO_RUN_EXIT"
fi

echo "Mojo run wall-clock time: ${MOJO_RUN_DURATION}s"
echo ""

# Summary comparison
echo "============================================================"
echo "Timing Summary"
echo "============================================================"
printf "%-20s %10.3f seconds\n" "Python:" "$PYTHON_DURATION"
printf "%-20s %10.3f seconds\n" "Mojo compile:" "$MOJO_COMPILE_DURATION"
printf "%-20s %10.3f seconds\n" "Mojo run:" "$MOJO_RUN_DURATION"

MOJO_TOTAL_DURATION=$(python3 -c "print($MOJO_COMPILE_DURATION + $MOJO_RUN_DURATION)")
printf "%-20s %10.3f seconds\n" "Mojo total:" "$MOJO_TOTAL_DURATION"

if [ -n "$PYTHON_DURATION" ] && [ -n "$MOJO_RUN_DURATION" ]; then
    RUN_SPEEDUP=$(python3 -c "ratio = $PYTHON_DURATION / $MOJO_RUN_DURATION if $MOJO_RUN_DURATION > 0 else 0; print(f'{ratio:.2f}')")
    if [ $(python3 -c "print(1 if $PYTHON_DURATION > $MOJO_RUN_DURATION else 0)") -eq 1 ]; then
        printf "%-20s %10.2fx faster\n" "Mojo run is:" "$RUN_SPEEDUP"
    else
        RUN_SPEEDUP=$(python3 -c "ratio = $MOJO_RUN_DURATION / $PYTHON_DURATION if $PYTHON_DURATION > 0 else 0; print(f'{ratio:.2f}')")
        printf "%-20s %10.2fx faster\n" "Python run is:" "$RUN_SPEEDUP"
    fi
fi

if [ -n "$PYTHON_DURATION" ] && [ -n "$MOJO_TOTAL_DURATION" ]; then
    TOTAL_SPEEDUP=$(python3 -c "ratio = $PYTHON_DURATION / $MOJO_TOTAL_DURATION if $MOJO_TOTAL_DURATION > 0 else 0; print(f'{ratio:.2f}')")
    if [ $(python3 -c "print(1 if $PYTHON_DURATION > $MOJO_TOTAL_DURATION else 0)") -eq 1 ]; then
        printf "%-20s %10.2fx faster\n" "Mojo total is:" "$TOTAL_SPEEDUP"
    else
        TOTAL_SPEEDUP=$(python3 -c "ratio = $MOJO_TOTAL_DURATION / $PYTHON_DURATION if $PYTHON_DURATION > 0 else 0; print(f'{ratio:.2f}')")
        printf "%-20s %10.2fx faster\n" "Python total is:" "$TOTAL_SPEEDUP"
    fi
fi

echo "============================================================"
