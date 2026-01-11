from benchmark import run, keep

def def_func(x: Int) -> Int:
    return x + 1

fn fn_func(x: Int) -> Int:
    return x + 1

fn main() raises:
    @parameter
    fn test_def() raises:
        var total = 0
        for i in range(1000):
            total += def_func(i)
        keep(total)

    @parameter
    fn test_fn():
        var total = 0
        for i in range(1000):
            total += fn_func(i)
        keep(total)

    print("--- def vs fn (1000 calls) ---")
    var report_def = run[test_def](max_runtime_secs=0.5)
    print("def: Mean:", report_def.mean("ms"), "ms")

    var report_fn = run[test_fn](max_runtime_secs=0.5)
    print("fn:  Mean:", report_fn.mean("ms"), "ms")
