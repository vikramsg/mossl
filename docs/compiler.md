# Mojo Compiler Performance & Benchmarking

This document outlines how to benchmark the Mojo compiler and understand the performance trade-offs between compilation and execution time in this project.

## Compilation vs. Execution Time

In Mojo, running code via `mojo run` (or `pixi run mojo run`) includes the time taken to compile the code into LLVM IR and then into machine code. For complex projects like `ssl.mojo`, this compilation step can significantly dominate the total execution time.

- **Compilation Overhead**: ~10-12 seconds for the full TLS stack.
- **Execution Speed**: Competitive with or faster than Python's OpenSSL-backed libraries once compiled.

## Benchmarking the Compiler

To measure exactly how long the compiler takes to build a specific script or binary, use the `time` command:

```bash
time pixi run mojo build -I src bench/bench_https_get.mojo -o bench_bin
```

Look for the `real` time in the output to see the total duration of the build process.

## Testing a Compiled Version

To get an accurate measure of execution performance without compilation noise, always build a binary first and then run it:

1. **Build the binary**:
   ```bash
   pixi run mojo build -O3 -I src bench/bench_https_get.mojo -o bench_bin
   ```
   *Note: `-O3` enables maximum optimizations.*

2. **Run the binary**:
   ```bash
   time ./bench_bin
   ```

## Performance Bottlenecks

While the compiled code is fast, the following areas currently limit peak performance:

1. **Heap Allocations**: Frequent `UnsafePointer.alloc` calls in low-level math functions (e.g., `mont_mul`).
2. **PKI Re-parsing**: Repeated parsing of system trust stores (140+ certificates) during every handshake.
3. **BigInt Loops**: Usage of generic loops instead of unrolled scalar arithmetic for large integer operations.
