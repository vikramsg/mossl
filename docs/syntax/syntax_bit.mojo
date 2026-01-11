from benchmark import run, keep
from bit import count_leading_zeros, pop_count

fn main() raises:
    var x: UInt64 = 0x123456789ABCDEF0

    @parameter
    fn test_standard_ops():
        var y = x
        for _ in range(1000):
            y = (y << 1) | (y >> 63)
            y = y ^ 0xFFFFFFFFFFFFFFFF
        keep(y)

    @parameter
    fn test_bit_module():
        var total: UInt64 = 0
        for _ in range(1000):
            total += count_leading_zeros(x)
            total += pop_count(x)
        keep(total)

    print("--- Bit Module & Operations ---")
    var report_ops = run[test_standard_ops](max_runtime_secs=0.5)
    print("Standard Bit Ops: Mean:", report_ops.mean("ms"), "ms")

    var report_mod = run[test_bit_module](max_runtime_secs=0.5)
    print("Bit Module Fn:    Mean:", report_mod.mean("ms"), "ms")