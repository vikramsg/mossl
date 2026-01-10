# Performance Notes

## SIMD Loading from InlineArray (Safe)

To safely load a `SIMD` vector from an `InlineArray` at runtime without using unsafe pointers or triggering compile-time evaluation errors, use a regular loop. While seemingly scalar, the Mojo compiler can often optimize these simple assignment loops.

```mojo
var v = SIMD[DType.uint8, 16](0)
for i in range(16):
    v[i] = arr[offset + i]
```

This avoids the variadic constructor `SIMD(a, b, c...)` which the compiler tries to unroll and evaluate at compile-time using `StaticTuple`, causing errors if the elements are not compile-time constants.

## Vectorized S-Box (Safe)

By pre-calculating S-Box chunks and storing them in an `InlineArray` within the encryption context, we can perform parallel lookups using `shuffle` and `select`.

1. **Context Init**: Load S-Box chunks into `InlineArray[Block16, 16]`.
2. **Lookup**: Use `high_nibble` to select the chunk and `low_nibble` for the `shuffle` index.

This reduces the S-Box lookup from $O(256)$ scalar operations to $O(16)$ vectorized operations per block, significantly improving performance while remaining constant-time and safe.

## Return-based API

Mojo functions should return values instead of using `mut` arguments for results when possible. This is more idiomatic and allows for better compiler optimizations like Named Return Value Optimization (NRVO).

```mojo
fn inc32(ctr: Block16) -> Block16:
    # ...
    return new_ctr
```