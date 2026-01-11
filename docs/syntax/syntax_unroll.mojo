from benchmark import run, keep

fn main() raises:
    @parameter
    fn test_no_unroll():
        var total = 0
        for i in range(16):
            total += i
        keep(total)

    @parameter
    fn test_unroll():
        var total = 0
        @parameter
        for i in range(16):
            total += i
        keep(total)

    print("--- Loop Unrolling (16 iterations) ---")
    var report_no = run[test_no_unroll](max_runtime_secs=0.5)
    print("No Unroll: Mean:", report_no.mean("ms"), "ms")

    var report_un = run[test_unroll](max_runtime_secs=0.5)
    print("Unrolled:  Mean:", report_un.mean("ms"), "ms")