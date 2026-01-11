from benchmark import run, keep

@always_inline
fn inline_1(x: Int) -> Int: return x * 2 + 3
@always_inline
fn inline_2(x: Int) -> Int: return inline_1(x) * 2 + 3
@always_inline
fn inline_3(x: Int) -> Int: return inline_2(x) * 2 + 3
@always_inline
fn inline_4(x: Int) -> Int: return inline_3(x) * 2 + 3
@always_inline
fn inline_5(x: Int) -> Int: return inline_4(x) * 2 + 3

fn call_1(x: Int) -> Int: return x * 2 + 3
fn call_2(x: Int) -> Int: return call_1(x) * 2 + 3
fn call_3(x: Int) -> Int: return call_2(x) * 2 + 3
fn call_4(x: Int) -> Int: return call_3(x) * 2 + 3
fn call_5(x: Int) -> Int: return call_4(x) * 2 + 3

fn main() raises:
    var val = 42

    @parameter
    fn test_inlined():
        var total = 0
        for i in range(1000):
            total += inline_5(val + i)
        keep(total)

    @parameter
    fn test_non_inlined():
        var total = 0
        for i in range(1000):
            total += call_5(val + i)
        keep(total)

    print("--- Deep Always Inline Benchmark (5 levels complex) ---")
    var report_inlined = run[test_inlined](max_runtime_secs=0.5)
    print("Inlined (5 levels, 1k calls):    Mean:", report_inlined.mean("ms"), "ms")

    var report_non_inlined = run[test_non_inlined](max_runtime_secs=0.5)
    print("Non-inlined (5 levels, 1k calls): Mean:", report_non_inlined.mean("ms"), "ms")
