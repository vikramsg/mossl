# Research: Mojo Argument Conventions (read, mut, var)

## Findings
Based on research in the Mojo standard library and changelogs (up to early 2025/2026 contexts), the terminology for argument conventions has evolved significantly. The keyword `borrowed` is now considered obsolete and has been replaced by more descriptive terms.

### Key Keyword Changes
| Old Keyword | New Keyword | Description |
| :--- | :--- | :--- |
| `borrowed` | `read` | Immutable reference. This is the default convention for `fn` arguments. |
| `inout` | `mut` | Mutable reference. |
| `owned` | `var` | Transfer of ownership or a locally mutable copy of the value. |
| N/A | `deinit` | Used specifically in `__moveinit__` to indicate that the source object will be destroyed after the move. |

## Web Context
- **Modular Official Blog/Docs**: The team has introduced these changes to make the code more readable and to distinguish between "how the data is passed" and "how it is used".
- **Community Tutorials**: Many newer tutorials (post-2024) use `read` and `mut` exclusively, while older ones still reference `borrowed` and `inout`.

## Codebase Context (Mojo Stdlib)
The official Mojo standard library (`stdlib`) has transitioned to these keywords:
- **`read`**: Found in `stdlib/std/collections/linked_list.mojo` for `__copyinit__`.
- **`mut`**: Extensively used in `stdlib/test/python/test_python_interop.mojo` and other performance-critical components.
- **`deinit`**: Used in `stdlib/std/builtin/value.mojo` for the `Movable` trait.

## Recommendations
- **Avoid `borrowed`**: Do not use the `borrowed` keyword in function signatures as it is deprecated/obsolete.
- **Use `read` for clarity**: If you want to be explicit about an immutable reference, use `read`. Otherwise, simply rely on the default `fn` behavior.
- **Use `mut` instead of `inout`**: All mutable reference arguments should use the `mut` keyword.
- **Use `var` for ownership**: When a function takes ownership of a value (equivalent to the old `owned`), use the `var` keyword in the argument list.
