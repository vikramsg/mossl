# Mojo Performance Guide (v25.7)

Mojo is designed to provide C++ level performance with Python's ease of use. This document outlines the key strategies and features for achieving maximum performance in Mojo as of version 25.7.

## 1. Static Typing and Compiled Functions

Mojo provides two ways to define functions and types. For performance-critical code, use the static variants.

### `fn` vs `def`
`fn` functions are strictly typed and compiled, whereas `def` functions are dynamic and flexible. In `fn`, variables must be explicitly declared with `let` (immutable) or `var` (mutable).

```mojo
# FAST: Compiled, strictly typed
fn add_fast(a: Int, b: Int) -> Int:
    return a + b

# SLOWER: Dynamic, Python-like
def add_flexible(a, b):
    return a + b
```

### `struct` and Initialization
`struct` is a static type with a fixed memory layout. As of recent updates, constructors should use the `out self` convention.

```mojo
@value
struct Point:
    var x: Float64
    var y: Float64

    # Latest: Use 'out self' for constructors
    fn __init__(out self, x: Float64, y: Float64):
        self.x = x
        self.y = y
```

## 2. Fast Collections: Fixed vs Dynamic Length

Choosing the right collection is critical for performance.

### `InlineArray` (Preferred for Fixed Length)
If the size of your collection is known at compile-time, use `InlineArray`. It is significantly faster than `List` because:
- **Stack Allocation**: Small arrays can stay on the stack, avoiding heap overhead.
- **No Indirection**: Data is stored contiguously and accessed directly.
- **SIMD Optimized**: The compiler can easily vectorize operations on `InlineArray`.

```mojo
from collections import InlineArray

fn fixed_array_performance():
    # Size is fixed at compile-time (e.g., 16 elements)
    var arr = InlineArray[Int, 16](0)
    
    for i in range(16):
        arr[i] = i
```

### `List` (Use only for Dynamic Length)
`List` is Mojo's dynamic array. It is heap-allocated and supports resizing, but carries overhead for:
- **Heap Allocation/Deallocation**: Managing memory at runtime.
- **Resizing**: Copying elements when capacity is exceeded.
- **Indirection**: Accessing heap memory via a pointer.

## 3. SIMD (Single Instruction, Multiple Data)

SIMD allows the CPU to perform the same operation on multiple data points simultaneously. This is a core feature for performance in Mojo.

```mojo
from sys import simd_width_of

fn simd_add():
    alias type = DType.float32
    alias width = simd_width_of[type]()
    
    # Create SIMD vectors
    var a = SIMD[type, width](1.0)
    var b = SIMD[type, width](2.0)
    
    # Adds 'width' elements in parallel
    var c = a + b
    print(c)
```

## 4. Vectorization and Parallelization

Mojo's `algorithm.functional` module provides primitives to leverage multi-core and SIMD hardware.

### `vectorize`
Transforms a scalar loop into a SIMD-optimized operation using a closure.

```mojo
from algorithm.functional import vectorize
from memory import UnsafePointer

fn apply_offset(data: UnsafePointer[Float32], size: Int, offset: Float32):
    @parameter
    fn closure[width: Int](i: Int):
        # Load and store using SIMD width
        data.store(i, data.load[width=width](i) + offset)

    vectorize[width=simd_width_of[DType.float32]()](size, closure)
```

### `parallelize`
Distributes work across available CPU cores.

```mojo
from algorithm.functional import parallelize

fn process_chunk(i: Int):
    # Perform independent task
    print("Task:", i)

fn run_parallel():
    parallelize(100, process_chunk)
```

## 5. Argument Conventions (Latest v25.7 Syntax)

Mojo's ownership model avoids garbage collection. Older keywords (`borrowed`, `inout`) are being replaced by `read` and `mut`.

- **`read`** (replaces `borrowed`): Immutable reference. Default for `fn` arguments.
- **`mut`** (replaces `inout`): Mutable reference. Modifies the caller's variable in place.
- **`owned`**: Transfers ownership to the function.
- **`out`**: Identifies uninitialized variables the function must initialize.

```mojo
fn process(read a: Int, mut b: Int, owned c: String):
    # a is read-only
    # b is modified in-place
    # c is moved into this scope
    pass

fn main():
    var x = 10
    var y = 20
    var z = String("hello")
    process(x, y, z^) # '^' is the move operator
```

## 6. Memory Management: `UnsafePointer`

Mojo provides `UnsafePointer` for low-level memory operations, FFI, and building high-performance data structures. While powerful, **usage should be minimized** in favor of safer abstractions like `InlineArray` or `List` whenever possible.

### Correct Usage Patterns

`UnsafePointer` requires manual management of both memory allocation and the lifecycle of the objects stored within that memory.

```mojo
from memory import UnsafePointer

fn advanced_pointer_usage():
    # 1. Allocation: Allocates heap memory for 10 Integers
    var ptr = UnsafePointer[Int].alloc(10)
    
    # 2. Initialization: MUST initialize memory before loading
    # For complex types, use init_pointee_copy or init_pointee_move
    for i in range(10):
        (ptr + i).init_pointee_copy(i * i)
    
    # 3. Loading and Storing: Using subscripts or SIMD
    # Subscript access is generally preferred for clarity
    ptr[0] = 42
    print(ptr[0])
    
    # 4. Lifecycle Management: Destroying elements
    for i in range(10):
        (ptr + i).destroy_pointee()
    
    # 5. Deallocation: Freeing the heap memory
    ptr.free()

fn simd_pointer_usage(data: UnsafePointer[Float32]):
    # Use load/store with width for vectorized operations on DTypes
    var vec = data.load[width=8](0) 
    data.store(0, vec * 2.0)
```

### Key Considerations
- **Manual Safety**: You are responsible for bounds checking, null checks, and ensuring memory is initialized before use.
- **Lifecycle Methods**: Use `init_pointee_copy`, `init_pointee_move`, and `destroy_pointee` to correctly handle types with non-trivial constructors/destructors.
- **Minimize Usage**: `UnsafePointer` bypasses Mojo's ownership and safety model. Improper use leads to memory leaks, use-after-free, and segmentation faults. Only use it in hot paths where safe alternatives are insufficient.

## 7. Optimization Decorators

- **`@always_inline`**: Removes function call overhead by inlining the code.
- **`@parameter`**: Marks a closure to be captured at compile-time (essential for `vectorize`).
- **`@value`**: Generates boilerplate for move/copy constructors.

## 8. High-Performance Bit Manipulation: `bit` Module

Mojo provides the `bit` module for hardware-accelerated bitwise operations, which are essential for cryptography, compression, and low-level data processing. These functions typically map directly to specialized CPU instructions (like `LZCNT`, `POPCNT`, `ROR`/`ROL`) for maximum efficiency.

### Key Bitwise Functions

```mojo
from bit import count_leading_zeros, pop_count, rotate_bits_left

fn bit_tricks():
    let val: UInt64 = 0x0000FFFF00000000
    
    # Count leading zeros (useful for bigint normalization)
    let leading = count_leading_zeros(val) # Returns 16
    
    # Population count (number of set bits)
    let bits = pop_count(val) # Returns 16
    
    # Bit rotation (wrap-around shift)
    let rotated = rotate_bits_left(val, 8)
```

### Performance Benefits
- **Hardware Acceleration**: Functions like `count_leading_zeros` use dedicated CPU instructions, outperforming manual loop-based implementations.
- **SIMD Support**: Most `bit` functions are vectorized and can operate on `SIMD` types directly, enabling parallel bit manipulation across multiple data points.
- **Constant Time**: Many bitwise operations are inherently constant-time, which is critical for preventing side-channel attacks in cryptographic code.

```mojo
from bit import bit_reverse

fn vectorized_bit_reverse(data: SIMD[DType.uint32, 8]) -> SIMD[DType.uint32, 8]:
    # Reverses bits for all 8 elements in parallel
    return bit_reverse(data)
```

## 9. Benchmarking: `benchmark` Module

Mojo's `benchmark` module provides a robust framework for performance measurement, offering statistical analysis (mean, min, max) and detailed reports.

### Basic Usage
The `run` function executes a given function multiple times to collect performance data. Use `keep()` to prevent the compiler from optimizing away code that has no side effects but is essential for the benchmark.

```mojo
from benchmark import run, Unit, keep

fn my_target_function():
    var x: Int = 0
    for i in range(100):
        x += i
    keep(x) # Ensure x is not optimized away

fn main() raises:
    # Runs the benchmark and returns a Report object
    var report = run[my_target_function]()
    
    # Print the report in different units (s, ms, us, ns)
    report.print(Unit.ms)
    
    # Access specific metrics
    print("Mean time:", report.mean(Unit.ns), "ns")
```

### Benchmarking with Arguments
If your target function requires arguments, wrap it in a `@parameter` closure.

```mojo
from benchmark import run

fn work_with_args(size: Int):
    # ... expensive work ...
    pass

fn main() raises:
    @parameter
    fn wrapper():
        work_with_args(1024)
    
    var report = run[wrapper]()
    report.print()
```

### Key Features
- **Warmup**: `run` automatically performs warmup iterations to stabilize the CPU and cache state.
- **Statistical Analysis**: Reports include mean, total duration, fastest, and slowest iterations.
- **Optimization Guard**: `keep()` is critical for ensuring that code whose results are unused (typical in benchmarks) is actually executed by the compiler.

---
*Source: Verified against Mojo v25.7 release notes and official documentation.*
