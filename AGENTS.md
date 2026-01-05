# Agents

This document helps agents work within the project.
This project uses the Mojo programming language and the Pixi package manager.

## Spec Coverage
We aim to map every important operation to a Quint specification and verify each
spec via its corresponding Mojo implementation test (trace-based or vector-based).

## Mojo 

### Mojo Tip: List Comprehension
Mojo supports list comprehensions. For example, to build a `List[UInt8]` of 16 zeros:

```mojo
var block: List[UInt8] = [UInt8(0) for _ in range(16)]
```

### Mojo Tip: Bit operations using bit module
Mojo supports bit operations using the `bit` module. For example, to count the number of leading zeros in a `UInt64`:
```mojo
from bit import count_leading_zeros
var count = count_leading_zeros(value)
```

Make sure to look at mojo documentation for more bit operations.

### Mojo Tip: Prefer @fieldwise_init When Appropriate
When a struct’s fields can be initialized directly from constructor arguments (no custom logic or defaults), prefer `@fieldwise_init` to reduce boilerplate in `__init__`.

## Pixi

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
