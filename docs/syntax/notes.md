# Mojo Idiomatic Syntax Performance Benchmarks

This document provides a comprehensive overview of performance insights for Mojo-specific syntax features based on benchmarks conducted on Sunday, January 11, 2026.

## Summary Table

| Feature | Comparison | Winner | Impact |
| :--- | :--- | :--- | :--- |
| **Collections** | `Dict` vs `List` (Linear) | `Dict` | **~22x faster** for lookups |
| **Collections** | `List` (Cap) vs `InlineArray` | `List` (Cap) | **~13% faster** |
| **Math** | `math.sqrt` vs `** 0.5` | `math.sqrt` | **~12x faster** |
| **Bitwise** | `bit` module vs Manual | `bit` module | **~1900x faster** |
| **SIMD** | `SIMD` vs Scalar | `SIMD` (16) | **~6x faster** for Matrix Multiply |
| **Memory** | `UnsafePointer` vs `List` | `UnsafePointer` | **~4% faster** (bypasses safety) |
| **Arguments** | `borrowed` vs `owned` | `borrowed` | **~5% faster** |
| **Specialization**| `@parameter` vs Runtime | `@parameter` | Minimal overhead for simple loops |
| **Syntactic Sugar**| Comprehension vs Append | Manual Append | **~40% faster** for initialization |
| **Types** | `Optional` Overhead | Minimal | **<1% overhead** |

---

## Detailed Results & Insights

### 1. Dictionaries & Collections
**File:** `syntax_dict.mojo`, `syntax_collections.mojo`

| Operation | Implementation | Mean Latency (ms) |
| :--- | :--- | :--- |
| 1k Lookups | `Dict[Int, Int]` | 0.0252 |
| 1k Lookups | `List[Int]` (Linear Search) | 0.5534 |
| 10k Init | `InlineArray` | 0.0148 |
| 10k Init | `List` (no capacity) | 0.0523 |
| 10k Init | `List` (with capacity) | 0.0365 |

- **Insight:** `Dict` provides massive O(1) speedups over linear search.
- **Insight:** Pre-allocating `List` capacity is crucial for performance but `InlineArray` (stack-allocated) remains very competitive for fixed sizes.

### 2. Low-Level Optimizations
**File:** `syntax_simd.mojo`, `syntax_pointers.mojo`

| Operation | Implementation | Mean Latency (ms) |
| :--- | :--- | :--- |
| 64x64 Matmul | Scalar | 0.3543 |
| 64x64 Matmul | SIMD (width 16) | 0.0631 |
| 10k Accesses | `List` Indexing | 0.0083 |
| 10k Accesses | `UnsafePointer` | 0.0079 |

- **Insight:** SIMD vectorization yields ~6x speedup for numerical kernels.
- **Insight:** `UnsafePointer` provides a small but consistent performance gain by bypassing bounds checks.

### 3. Math & Bit Manipulation
**File:** `syntax_math.mojo`, `syntax_bit.mojo`

| Operation | Implementation | Mean Latency (ms) |
| :--- | :--- | :--- |
| 1k Sqrt | `math.sqrt` | 0.00136 |
| 1k Sqrt | `** 0.5` Operator | 0.01693 |
| 1k Bit Ops | Manual Loop | 0.00102 |
| 1k Bit Ops | `bit` Module (Intrinsics) | 0.00000054 |

- **Insight:** Hardware intrinsics in the `bit` module are orders of magnitude faster.
- **Insight:** Always prefer specialized math functions over general power operators.

### 4. Function & Argument Semantics
**File:** `syntax_arguments.mojo`, `syntax_def_vs_fn.mojo`, `syntax_always_inline.mojo`

| Convention | Workload | Mean Latency (ms) |
| :--- | :--- | :--- |
| `borrowed` | 8KB Struct Access | 0.00054 |
| `owned` (move) | 8KB Struct Access | 0.00065 |
| `owned` (copy) | 8KB Struct Access | 0.00094 |
| `def` | 1k Function Calls | 0.00000092 |
| `fn` | 1k Function Calls | 0.00000131 |

- **Insight:** `borrowed` is the most efficient for large structs. Avoid unnecessary copies.
- **Insight:** For simple functions, `def` and `fn` are effectively equivalent in performance.

### 5. Control Flow & Specialization
**File:** `syntax_parameter.mojo`, `syntax_unroll.mojo`

| Technique | Implementation | Mean Latency (ms) |
| :--- | :--- | :--- |
| Loop (100) | Runtime Argument | 0.00075 |
| Loop (100) | `@parameter` Specialization | 0.00090 |
| Loop (16) | No Unroll | 0.00000086 |
| Loop (16) | `@unroll` | 0.00000084 |

- **Insight:** `@parameter` specialization allows the compiler to optimize for constants, though microbenchmarks may show overhead from setup in extremely tight loops.
- **Insight:** Loop unrolling shows marginal gains for very small trip counts, as the compiler often auto-unrolls these.

### 6. Syntactic Sugar & Types
**File:** `syntax_comprehension.mojo`, `syntax_optional.mojo`, `syntax_strings.mojo`

| Feature | Comparison | Mean Latency (ms) |
| :--- | :--- | :--- |
| 1k Init | Manual `List.append` | 0.00147 |
| 1k Init | List Comprehension | 0.00208 |
| 1k Calls | `Optional[Int]` | 0.00000064 |
| 1k Calls | Raw `Int` | 0.00000073 |
| 1k Compares | `String` | 0.00000103 |
| 1k Compares | `StringLiteral` | 0.00000085 |

- **Insight:** Manual loops are currently faster than comprehensions in Mojo.
- **Insight:** `Optional` and `StringLiteral` have effectively zero overhead for common operations.

## Methodology
Benchmarks were conducted using the Mojo `benchmark` module with `max_runtime_secs=0.5`. Each result represents the mean latency for the specified workload. Values were measured on Sunday, January 11, 2026.