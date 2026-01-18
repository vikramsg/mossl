# Mojo Syntax

This document serves as a central reference for tracking Mojo's evolving syntax conventions and their associated performance benchmarks. It aims to provide grounded, data-driven recommendations for writing high-performance, idiomatic Mojo code.

## Recommendations

- **Parallelism**: Prefer `vectorize` for memory-bound SIMD operations on contiguous data; it is significantly faster than `parallelize` for small to medium workloads due to lower orchestration overhead.
- **Argument Conventions**:
    - Use `read` (default in `fn`) for immutable references to avoid copies.
    - Use `mut` for mutable references (replaces `inout`).
    - Use `var` for ownership transfer or locally mutable copies (replaces `owned`).
- **Math**: Always prefer specialized hardware intrinsics like `math.sqrt` over general-purpose operators like `** 0.5`.
- **Bit Manipulation**: Use the `bit` module for hardware-accelerated operations; it is orders of magnitude faster than manual bit-twiddling.
- **Collections**: Pre-allocate `List` capacity whenever the size is known to avoid expensive reallocations. `List` with capacity is highly competitive with `InlineArray`.
- **Compile-Time Specialization**: Use `@parameter` to evaluate variables at compile-time, allowing the compiler to generate optimized constants and specialized code paths.
- **SIMD**: Use `simd_width_of[DType]()` to write portable code that automatically scales to the target hardware's register width.
- **Traits**: 
    - Use `ImplicitlyCopyable` only for small, cheap-to-copy types to enable cleaner syntax; avoid it for heap-allocated types to prevent hidden performance costs.
    - **Non-Trivial Types**: Structs containing `List` or other heap-allocated data cannot automatically synthesize `__copyinit__`. You must manually implement `__copyinit__` (using `.copy()`) and `__moveinit__` (using `^`).
    - **Variant Compatibility**: To use a type in `utils.Variant`, it must conform to `Movable` and `Copyable`. If the type is not `ImplicitlyCopyable`, you must use the transfer operator `^` or an explicit `.copy()` when initializing the `Variant`.
- **Syntactic Sugar**: Be aware that manual `for` loops with `append` currently outperform list comprehensions in performance-critical sections.
- **Function Inlining**: Use `@always_inline` for small, frequently called helper functions to eliminate call overhead, especially in deep call stacks.
- **Data Structures & Typeclasses (Traits)**: 
    - Use **Traits** as the direct equivalent of **Typeclasses** for static dispatch and defining shared behavior.
    - **Frozen Dataclass**: Achieve "frozen" behavior by using `var` fields without providing setters, and using the `read` (default) convention for methods.
    - **Static Dispatch**: Use trait bounds (e.g., `[T: Summarizable]`) to allow the compiler to generate specialized, zero-overhead function versions for each type at compile-time.
- **Variants**: Use `utils.Variant` for explicit success/error returns and typestate transitions. Mojo's stdlib uses `Variant` (see `std/utils/variant.mojo` and `std/runtime/tracing.mojo`) to keep invalid states unrepresentable and to make error handling explicit.

---

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
| **Typeclasses** | Static Dispatch | `N/A` | **Zero Overhead** | ~0.0006 |
| **Traits** | `ImplicitlyCopyable` | `N/A` | **Syntactic Sugar** | ~0.0006 |
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
| `read` (Reference) | 0.000591 |
| `var` (Moved `^`) | 0.000579 |
| `var` (Copied) | 0.000668 |

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

### 9. Loop Unrolling
**File:** `syntax_unroll.mojo` (16 iterations)

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| `@unroll` | 0.00000052 |
| No Unroll | 0.00000050 |

### 10. Always Inline
**File:** `syntax_always_inline.mojo` (3 levels)

| Implementation | Mean Latency (ms) |
| :--- | :--- |
| `@always_inline` | 0.00000066 |
| Standard Function | 0.00000054 |

### 11. Data Structures & Typeclasses (Traits)
**File:** `syntax_typeclasses.mojo`

- **Concepts**: Mojo uses **Traits** to define shared behavior (Typeclasses). Generic functions use **Static Dispatch** to call trait methods, meaning the compiler specializes the function for each type at compile-time, resulting in zero runtime overhead (no vtables).
- **Frozen Pattern**: While `let` for struct fields is currently deprecated, immutability is enforced by using `var` fields without setters and leveraging the default `read` (immutable reference) convention for methods.
- **Composition**: Generic types (like `Wrapper[T]`) can interact with trait-based logic through standalone generic functions or specialized method calls, allowing for powerful, typesafe composition.

### 12. Variants and Typestate
**File:** `syntax_variant.mojo`

- **Use Case**: Explicit success/error unions and typestate transitions without exceptions.
- **Why**: `Variant` is the standard Mojo sum type in the stdlib (see `std/utils/variant.mojo`) and is used in core code (e.g., `std/runtime/tracing.mojo`) to constrain allowed values and avoid invalid states at compile time.

**Result-style Example (String/Error)**: This pattern is documented in the stdlib and is the recommended way to make error handling explicit without exceptions.

```mojo
from utils import Variant

comptime Result = Variant[String, Error]

fn process_data(data: String) -> Result:
    if len(data) == 0:
        return Result(Error("Empty data"))
    return Result(String("Processed: ", data))

var result = process_data("Hello")
if result.isa[String]():
    print("Success:", result[String])
else:
    print("Error:", result[Error])
```

## Methodology
Benchmarks were conducted using the Mojo `benchmark` module with `max_runtime_secs=0.5`. Each result represents the mean latency for the specified workload. Values were verified on Sunday, January 11, 2026.
