# Agents

This document helps agents work within the project.
This project uses the Mojo programming language and the Pixi package manager.

## Mojo and Pixi

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
