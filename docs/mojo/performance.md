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

Mojo v25.7 introduced a new `UnsafePointer` type to replace the legacy version, improving safety by preventing implicit mutability casts.

```mojo
from memory import UnsafePointer

fn pointer_example():
    var x: Int = 42
    # New UnsafePointer usage
    var p = UnsafePointer[Int].address_of(x)
    print(p.load())
```

## 7. Optimization Decorators

- **`@always_inline`**: Removes function call overhead by inlining the code.
- **`@parameter`**: Marks a closure to be captured at compile-time (essential for `vectorize`).
- **`@value`**: Generates boilerplate for move/copy constructors.

---
*Source: Verified against Mojo v25.7 release notes and official documentation.*
