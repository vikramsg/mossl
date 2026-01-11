from benchmark import run, keep

@always_inline
fn with_optional(x: Optional[Int]) -> Int:
    if x:
        return x.value()
    return 0

@always_inline
fn without_optional(x: Int) -> Int:
    return x

fn main() raises:
    var val = 42

    @parameter
    fn test_optional():
        var total = 0
        for i in range(1000):
            total += with_optional(val + i)
        keep(total)

    @parameter
    fn test_raw():
        var total = 0
        for i in range(1000):
            total += without_optional(val + i)
        keep(total)

    print("--- Optional Overhead (1k calls) ---")
    var report_opt = run[test_optional](max_runtime_secs=0.5)
    print("Optional: Mean:", report_opt.mean("ms"), "ms")

    var report_raw = run[test_raw](max_runtime_secs=0.5)
    print("Raw Value: Mean:", report_raw.mean("ms"), "ms")
