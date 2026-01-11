# Mojo Idiomatic Syntax Performance Benchmarks

This document provides a comprehensive overview of performance insights for Mojo-specific syntax features based on benchmarks conducted on Sunday, January 11, 2026.

## Summary Table

| Feature | Comparison | Winner | Impact |
| :--- | :--- | :--- | :--- |
| **Parallelism** | `vectorize` vs `parallelize` | `vectorize` | **Significant** for memory-bound tasks |
| **Collections** | `List` (Cap) vs `InlineArray` | `List` (Cap) | **~13% faster** |
| **Math** | `math.sqrt` vs `** 0.5` | `math.sqrt` | **~12x faster** |
| **Bitwise** | `bit` module vs Manual | `bit` module | **~1900x faster** |
| **SIMD** | `SIMD` vs Scalar | `SIMD` | **~6x faster** for Matrix Multiply |
| **Memory** | `UnsafePointer` vs `List` | `UnsafePointer` | **~4% faster** (bypasses safety) |
| **Arguments** | `borrowed` vs `owned` | `borrowed` | **~5% faster** |
| **Specialization**| `@parameter` vs Runtime | `@parameter` | Minimal overhead for simple loops |
| **Syntactic Sugar**| Comprehension vs Append | Manual Append | **~40% faster** for initialization |
| **Types** | `Optional` Overhead | Minimal | **<1% overhead** |

---

## Detailed Results & Insights

### 1. High-Performance Parallelism
**File:** `syntax_vectorize_parallel.mojo`, `syntax_simd.mojo`

Mojo provides high-level abstractions for hardware acceleration.

- **Vectorize**: Use the `vectorize` function to automatically apply SIMD across a range. It is the preferred way to write portable, high-performance loops as it handles the "tail" (remainder) elements automatically.
- **Parallelize**: Distributes tasks across multiple CPU cores. Use for computationally heavy tasks where the work per element is significant enough to offset the overhead of thread orchestration.
- **SIMD**: For manual control, use the `SIMD` type. For maximum efficiency, always use `simd_width_of[DType]()` to match the target architecture's register size (e.g., 512-bit for AVX-512).

### 2. Argument Conventions
**File:** `syntax_arguments.mojo`

| Convention | Workload | Mean Latency (ms) |
| :--- | :--- | :--- |
| `borrowed` (default) | 8KB Struct Access | 0.00054 |
| `owned` (move) | 8KB Struct Access | 0.00065 |
| `owned` (copy) | 8KB Struct Access | 0.00094 |

- **Insight:** `borrowed` is the default for `fn` and is the most efficient because it passes a read-only reference without copying.
- **Insight:** Use `owned` and the transfer operator `^` to move data into a function when the caller no longer needs it.

### 3. Specialization with `@parameter`
**File:** `syntax_parameter.mojo`, `syntax_unroll.mojo`

- **Insight:** Parameters are evaluated at compile-time. Using `@parameter` allows the compiler to generate specialized machine code for specific constants, enabling optimizations like full loop unrolling and constant folding.

### 4. Math & Bit Manipulation
**File:** `syntax_math.mojo`, `syntax_bit.mojo`

- **Insight:** Hardware intrinsics in the `bit` module (e.g., `count_leading_zeros`) are thousands of times faster than manual bit-twiddling loops.
- **Insight:** Always prefer specialized math functions (e.g., `math.sqrt`) over general operators (`** 0.5`).

### 5. Memory & Pointers
**File:** `syntax_pointers.mojo`, `syntax_collections.mojo`

- **Insight:** `UnsafePointer` provides a small performance gain by bypassing bounds checks but should be used sparingly where safety is managed manually.
- **Insight:** Pre-allocating `List` capacity is crucial to avoid expensive reallocations.

### 6. Syntactic Sugar & Types
**File:** `syntax_comprehension.mojo`, `syntax_optional.mojo`, `syntax_strings.mojo`

- **Insight:** Manual `for` loops with `append` are currently faster than list comprehensions in Mojo.
- **Insight:** Zero-cost abstractions: `Optional`, `StringLiteral`, and small `struct` wrappers have negligible runtime overhead.

## Methodology
Benchmarks were conducted using the Mojo `benchmark` module with `max_runtime_secs=0.5`. Each result represents the mean latency for the specified workload. Values were measured on Sunday, January 11, 2026.
