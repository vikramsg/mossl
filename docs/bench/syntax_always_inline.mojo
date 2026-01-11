from benchmark import run, keep

@always_inline
fn inlined_func(x: Int) -> Int:
    return x * 2 + 1

fn non_inlined_func(x: Int) -> Int:
    var res = x * 2
    res = res + 1
    return res

fn main() raises:
    var val = 42

    @parameter
    fn test_inlined():
        var total = 0
        for i in range(1000):
            total += inlined_func(val + i)
        keep(total)

    @parameter
    fn test_non_inlined():
        var total = 0
        for i in range(1000):
            total += non_inlined_func(val + i)
        keep(total)

    print("--- Always Inline Benchmark ---")
    var report_inlined = run[test_inlined](max_runtime_secs=0.5)
    print("Inlined (1000 calls):    Mean:", report_inlined.mean("ms"), "ms")

    var report_non_inlined = run[test_non_inlined](max_runtime_secs=0.5)
    print("Non-inlined (1000 calls): Mean:", report_non_inlined.mean("ms"), "ms")