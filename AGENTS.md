# Agents

This document helps agents work within the project.
This project uses the Mojo programming language and the Pixi package manager.

## Spec Coverage
We aim to map every important operation to a Quint specification and verify each
spec via its corresponding Mojo implementation test (trace-based or vector-based).

## Coding guidelines

We follow the following process for coding:
1. Write a Quint specification for the operation.
2. Generate a trace for the specification.
3. Write a failing unit test for the operation.
4. Write the Mojo implementation to pass the unit test.
5. Run the unit test and trace test and ensure it passes.
6. If the tests fail, fix the implementation and repeat the process.
7. If the tests pass, move on to the next operation.

**Important:** Only stop after successfull doing `make test-all` and `make format`. 

## Running code

1. When running code, use `pixi run` to run the code.
2. Always add timeout when running code, eg `timeout 60s pixi run ...`.
    - If the code is expected to take longer than 60 seconds, use a larger timeout.
    - This ensures if the code hangs, it will be killed and the test will fail.

## Mojo 

### Repo

https://github.com/modular/modular

### Functions

- Prefer **NEVER** mutating variables within a function. fn(mut a):a += 1.... Always return values.
- Never return Tuples. If multiple values have to be returned prefer creating a @fieldwise_init struct
- Prefer creating traits for reusable code.

### List Comprehension
Mojo supports list comprehensions. For example, to build a `List[UInt8]` of 16 zeros:

```mojo
var block: List[UInt8] = [UInt8(0) for _ in range(16)]
```

### Bit operations using bit module
Mojo supports bit operations using the `bit` module. For example, to count the number of leading zeros in a `UInt64`:
```mojo
from bit import count_leading_zeros
var count = count_leading_zeros(value)
```

Make sure to look at mojo documentation for more bit operations.

### Prefer @fieldwise_init When Appropriate
When a struct’s fields can be initialized directly from constructor arguments (no custom logic or defaults), prefer `@fieldwise_init` to reduce boilerplate in `__init__`.

### List vs InlineArray
Use `InlineArray` for fixed-size collections and `List` for dynamic-size collections.

```mojo
from collections import InlineArray
var arr = InlineArray[Int, 10](0)
```

### Mojo Tip: Standard Library

Prefer using the standard library modules instead of writing custom code.

- **algorithm**: High performance data operations: vectorization, parallelization, reduction, memory.
- **base64**: Binary data encoding: base64 and base16 encode/decode functions.
- **benchmark**: Performance benchmarking: statistical analysis and detailed reports.
- **bit**: Bitwise operations: manipulation, counting, rotation, and power-of-two utilities.
- **builtin**: Language foundation: built-in types, traits, and fundamental operations.
- **collections**: Core data structures: List, Dict, Set, Optional, plus specialized collections.
- **compile**: Runtime function compilation and introspection: assembly, IR, linkage, metadata.
- **complex**: Complex numbers: SIMD types, scalar types, and operations.
- **documentation**: Documentation built-ins: decorators and utilities for doc generation.
- **gpu**: GPU programming primitives: thread blocks, async memory, barriers, and sync.
- **hashlib**: Cryptographic and non-cryptographic hashing with customizable algorithms.
- **io**: Core I/O operations: console input/output, file handling, writing traits.
- **iter**: Iteration traits and utilities: Iterable, Iterator, enumerate, zip, map.
- **itertools**: Iterator tools: count, product, repeat for lazy sequence generation.
- **logger**: Logging with configurable severity levels.
- **math**: Math functions and constants: trig, exponential, logarithmic, and special functions.
- **memory**: Low-level memory management: pointers, allocations, address spaces.
- **os**: OS interface layer: environment, filesystem, process control.
- **pathlib**: Filesystem path manipulation and navigation.
- **prelude**: Standard library prelude: fundamental types, traits, and operations auto-imported.
- **pwd**: Password DB Lookups. User account information.
- **python**: Python interoperability: import modules, call functions, type conversion.
- **random**: Pseudorandom number generation with uniform and normal distributions.
- **runtime**: Runtime services: async execution and program tracing.
- **stat**: File type constants and detection from stat system calls.
- **subprocess**: Execute external processes and commands.
- **sys**: System runtime: I/O, hardware info, FFI, intrinsics, compile-time utils.
- **tempfile**: Manage temporary files and directories: create, locate, and cleanup.
- **testing**: Unit testing: Assertions (equal, true, raises) and test suites.
- **time**: Timing operations: monotonic clocks, performance counters, sleep, time_function.
- **utils**

## Working with github libraries

There are various situations where you may want to work with repositories on Github. 

1. Integrate an external library into the project, in which case we need to know the library's API's. 
2. Understand how another library works. 
3. Obtain data from it. 

In all these cases prefer cloning these repos into `/tmp`, using `git clone <REPO URL> /tmp/repo` and then searching through the repo.
Use web search only if you are not sure about the correct location of the repo.

## Pixi

Manage all mojo dependencies with Pixi.
Use Python only for scripts, benchmarks etc, but use Pixi for those dependencies.
Use `feature.python.dependencies` table in `pixi.toml` to install Python dependencies.

### Pixi Configuration

#### Channels
To work with Mojo and community packages, ensure the following channels are present in `pixi.toml`:
- `https://conda.modular.com/max`: Official Modular packages (Mojo, Max).
- `https://repo.prefix.dev/modular-community`: Community-contributed packages (e.g., `lightbug_http`).
- `conda-forge`: General dependencies.

#### Platform Solving
Pixi attempts to solve dependencies for **all** platforms listed in `pixi.toml`. If a package (like `mojo`) is missing for a specific platform (e.g., `osx-64`), the installation will fail even if you are on a different system. 
- **Tip:** Limit `platforms` to those known to have support (e.g., `linux-aarch64`, `osx-arm64`).

#### Mojo Versioning
Mojo versioning follows a `0.x.y` scheme.
- **Compatibility:** Packages are often strictly tied to a specific `mojo-compiler` version. A mismatch usually results in fatal compiler errors.

### Troubleshooting

#### MLIR / Internal Compiler Errors
Errors like:
`error: expected M::KGEN::LIT::DenseResourceElementsArrayAttr, but got: dense_resource<...>`
or
`error: expected mlir::BoolAttr, but got: loc("<unknown>":0:0)`
are almost always caused by **version mismatches** between the Mojo compiler and the pre-compiled `.mojopkg` dependency. 

**Fix:** Search for the exact `mojo-compiler` version the package was built with using `pixi search <package>`.
