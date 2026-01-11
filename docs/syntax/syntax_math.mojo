from math import sqrt

from benchmark import run, keep

fn main() raises:
    var val: Float64 = 1234.56

    @parameter
    fn test_math_sqrt():
        var res: Float64 = 0.0
        for i in range(1000):
            res += sqrt(val + Float64(i))
        keep(res)

    @parameter
    fn test_operator_sqrt():
        var res: Float64 = 0.0
        for i in range(1000):
            res += (val + Float64(i)) ** 0.5
        keep(res)

    print("--- math.sqrt vs ** 0.5 (1k calls) ---")
    var report_math = run[test_math_sqrt](max_runtime_secs=0.5)
    print("math.sqrt: Mean:", report_math.mean("ms"), "ms")

    var report_op = run[test_operator_sqrt](max_runtime_secs=0.5)
    print("Operator:  Mean:", report_op.mean("ms"), "ms")
