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
| **Traits** | `ImplicitlyCopyable` | `N/A` | **Syntactic Sugar** | ~0.0006 |
| **Syntactic Sugar**| Comprehension vs Append | Manual Append | **~33% faster** | 0.0013 vs 0.0018 |

---

## Detailed Results & Insights

### 1. High-Performance Parallelism
...
### 7. Implicit Traits (Syntactic Sugar)
**File:** `syntax_implicit_traits.mojo`

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| Explicit `.copy()` | 0.000579 |
| `ImplicitlyCopyable` | 0.000636 |

- **Insight**: `ImplicitlyCopyable` is a marker trait that allows the compiler to automatically copy values when passed to `var` (owned) arguments.
- **Idiomatic Usage**: Use `ImplicitlyCopyable` for small, "plain old data" types where copying is cheap and expected (e.g., complex numbers, small vectors). Avoid it for types with expensive allocations (like `List` or `String`) to prevent hidden performance costs.
- **Note on Movability**: There is no `ImplicitlyMovable` trait; Mojo handles moves automatically when using the transfer operator `^` or when the compiler determines the value is no longer used.

### 8. Syntactic Sugar & Types
...

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