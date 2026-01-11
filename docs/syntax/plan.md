# Plan: Mojo Syntax Benchmarks & Modern Keyword Update

## Checklist
- [x] Create plan and initialize structure in `docs/syntax/plan.md`.
- [x] Clone Mojo standard library repository to `/tmp/mojo_stdlib_research`.
- [x] Search for `borrowed` keyword usage in `/tmp/mojo_stdlib_research` to verify status.
- [x] Document research findings in `docs/research/mojo_arg_conventions.md`.
- [ ] Update `docs/syntax/syntax_arguments.mojo` with `read`, `mut`, and `var` usage.
- [ ] Update `docs/syntax/README.md` with verified terminology (`read` instead of `borrowed`).
- [ ] Run benchmarks for `docs/syntax/syntax_arguments.mojo` and capture output.
- [ ] Final check: Ensure all changes are within `docs/`.
- [ ] Run `make format`.

## Notes
- **Keyword Update**: Replace `borrowed` with `read` (or implicit) and `owned` with `var`.
- **Verification**: Use `pixi run mojo docs/syntax/syntax_arguments.mojo` to confirm compilation.