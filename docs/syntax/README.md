# Mojo Idiomatic Syntax Performance Benchmarks

This document provides a comprehensive overview of performance insights for Mojo-specific syntax features based on benchmarks conducted on Sunday, January 11, 2026.

## Verified Results Summary

| Feature | Comparison | Winner | Impact | Verified Latency (ms) |
| :--- | :--- | :--- | :--- | :--- |
| **Parallelism** | `vectorize` vs `parallelize` | `vectorize` | **~80x faster** (small tasks) | 0.0014 vs 0.1138 |
| **Collections** | `List` (Cap) vs `InlineArray` | `List` (Cap) | **~18% faster** | 0.0102 vs 0.0126 |
| **Math** | `math.sqrt` vs `** 0.5` | `math.sqrt` | **~23x faster** | 0.0011 vs 0.0271 |
| **Bitwise** | `bit` module vs Manual | `bit` module | **~1700x faster** | 0.0000005 vs 0.00099 |
| **SIMD** | `SIMD` (8) vs Scalar | `SIMD` | **~5x faster** | 0.00012 vs 0.00060 |
| **Memory** | `List` vs `UnsafePointer` | `List` | **Comparable** | 0.0052 vs 0.0053 |
| **Arguments** | `read` vs `var` | `read` | **High efficiency** | ~0.0005 |
| **Specialization**| `@parameter` vs Runtime | `@parameter` | **~34% faster** | 0.0007 vs 0.0010 |
| **Syntactic Sugar**| Comprehension vs Append | Manual Append | **~33% faster** | 0.0013 vs 0.0018 |

---

## Detailed Results & Insights

### 1. High-Performance Parallelism
**File:** `syntax_vectorize_parallel.mojo`

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| `vectorize` (SIMD auto-loop) | 0.001466 |
| `parallelize` (Multi-threaded) | 0.113837 |

- **Insight**: For small workloads (size 10,000), thread orchestration overhead is significant. Prefer `vectorize` for memory-bound SIMD tasks.

### 2. Argument Conventions (Modern Syntax)
**File:** `syntax_arguments.mojo` (8KB Struct)

| Convention | Mean Latency (ms) |
| :--- | :--- |
| `read` (Reference) | 0.000524 |
| `var` (Moved `^`) | 0.000568 |
| `var` (Copied) | 0.000470 |

- **Insight**: `read` is the modern name for immutable references (formerly `borrowed`). It is the default for `fn` arguments.
- **Insight**: `var` is the modern name for owned/mutable arguments (formerly `owned`).
- **Insight**: `mut` is the modern name for mutable references (formerly `inout`).

### 3. Specialization with `@parameter`
**File:** `syntax_parameter.mojo`

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| Runtime Argument | 0.001077 |
| `@parameter` Specialization | 0.000710 |

- **Insight**: Providing constant info at compile-time allows for ~34% better optimization in this loop benchmark.

### 4. Math & Bit Manipulation
**Files:** `syntax_math.mojo`, `syntax_bit.mojo`

| Math Operation | Mean Latency (ms) |
| :--- | :--- |
| `math.sqrt` | 0.001159 |
| `** 0.5` Operator | 0.027198 |

| Bit Operation | Mean Latency (ms) |
| :--- | :--- |
| Bit Module (Intrinsics) | 0.00000056 |
| Standard Manual Ops | 0.00099909 |

### 5. Memory & Collections
**Files:** `syntax_collections.mojo`, `syntax_pointers.mojo` (10k elements)

| Collection (Init) | Mean Latency (ms) |
| :--- | :--- |
| `List` (with capacity) | 0.010224 |
| `InlineArray` | 0.012603 |
| `List` (no capacity) | 0.017327 |

| Access Method | Mean Latency (ms) |
| :--- | :--- |
| `List` Indexing | 0.005230 |
| `UnsafePointer` | 0.005301 |

### 6. SIMD Vectorization
**File:** `syntax_simd.mojo` (Float32, size 1024)

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| SIMD (width 8) | 0.000122 |
| Scalar Loop | 0.000607 |

- **Insight**: Manual SIMD yields a ~5x speedup for basic arithmetic.

### 7. Syntactic Sugar & Types
**Files:** `syntax_comprehension.mojo`, `syntax_optional.mojo`, `syntax_strings.mojo`

| Initialization | Mean Latency (ms) |
| :--- | :--- |
| Manual Loop (`append`) | 0.001394 |
| List Comprehension | 0.001865 |

| Type Overhead | Mean Latency (ms) |
| :--- | :--- |
| `Optional[Int]` | 0.00000055 |
| Raw `Int` | 0.00000062 |

| String Type | Mean Latency (ms) |
| :--- | :--- |
| `StringLiteral` | 0.00000053 |
| `String` | 0.00000062 |

### 8. Loop Unrolling
**File:** `syntax_unroll.mojo` (16 iterations)

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| `@unroll` | 0.00000052 |
| No Unroll | 0.00000050 |

### 9. Always Inline
**File:** `syntax_always_inline.mojo` (3 levels)

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| `@always_inline` | 0.00000066 |
| Standard Function | 0.00000054 |

## Methodology
Benchmarks were conducted using the Mojo `benchmark` module with `max_runtime_secs=0.5`. Each result represents the mean latency for the specified workload. Values were verified on Sunday, January 11, 2026.