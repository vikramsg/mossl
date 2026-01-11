# Development Plan: Mojo Syntax Benchmarks & Documentation

## Checklist
- [x] Create plan and initialize structure.
- [x] Execute `docs/syntax/syntax_always_inline.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_arguments.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_bit.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_collections.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_comprehension.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_math.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_optional.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_parameter.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_pointers.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_simd.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_strings.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_unroll.mojo` and capture results.
- [x] Execute `docs/syntax/syntax_vectorize_parallel.mojo` and capture results.
- [x] Update `docs/syntax/README.md` with **real** verified benchmark data.
- [x] Add detailed tables for ALL benchmarks in `docs/syntax/README.md`.
- [ ] Final review: Ensure all code comments and notes meet the user's requirements.
- [ ] Run `make format`.

## Notes
- **Always Inline**: Inlining vs Standard showed negligible difference in this microbenchmark, possibly due to auto-inlining.
- **Arguments**: Copied (0.00047 ms) actually showed slightly faster than Borrowed (0.00052 ms) in this specific run, which is counter-intuitive for large structs and might be noise or allocator effects.
- **Bitwise**: Bit module (5.6e-07 ms) is ~1700x faster than manual (0.00099 ms).
- **Collections**: List with capacity (0.010 ms) is faster than InlineArray (0.012 ms) and List without capacity (0.017 ms).
- **SIMD**: SIMD (width 8) (0.00012 ms) is ~5x faster than Scalar (0.00060 ms).
- **Vectorize**: Vectorize (0.0014 ms) is ~80x faster than Parallelize (0.11 ms) for this small workload (size 10000).
- **Terminology**: Verified that "borrowed" is handled as an argument convention in `syntax_arguments.mojo`.
