# Plan: Mojo Implicit Traits & Documentation

## Checklist
- [x] Research `ImplicitlyCopyable` and `ImplicitlyMovable` in Mojo stdlib.
- [ ] Create `docs/syntax/syntax_implicit_traits.mojo` to demonstrate `ImplicitlyCopyable`.
- [ ] Update `docs/syntax/README.md` with idiomatic usage of `ImplicitlyCopyable`.
- [ ] Run benchmarks for `docs/syntax/syntax_implicit_traits.mojo`.
- [ ] Final review and formatting.

## Notes
- **Research**: `ImplicitlyCopyable` exists as a marker trait. `ImplicitlyMovable` does not exist; moving is handled by the transfer operator `^` or compiler heuristics.
- **Idiomatic Usage**: `ImplicitlyCopyable` should be used for small, cheap-to-copy types (like `Int`, `Float`) to allow them to be passed to `var` arguments without explicit `.copy()`.
