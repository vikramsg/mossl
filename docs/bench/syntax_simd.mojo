from benchmark import run, keep
from collections import List

fn main() raises:
    var data = List[Int64](capacity=1024)
    for i in range(1024):
        data.append(i)

    @parameter
    fn test_scalar():
        var total: Int64 = 0
        for i in range(1024):
            total += data[i]
        keep(total)

    @parameter
    fn test_simd():
        alias simd_width = 16
        var v = SIMD[DType.int64, simd_width](0)
        for i in range(0, 1024, simd_width):
            # Manual load
            var slice = SIMD[DType.int64, simd_width]()
            @parameter
            for j in range(simd_width):
                slice[j] = data[i + j]
            v += slice
        keep(v.reduce_add())

    print("--- SIMD vs Scalar (1024 elements) ---")
    var report_scalar = run[test_scalar](max_runtime_secs=0.5)
    print("Scalar:    Mean:", report_scalar.mean("ms"), "ms")

    var report_simd = run[test_simd](max_runtime_secs=0.5)
    print("SIMD (16): Mean:", report_simd.mean("ms"), "ms")