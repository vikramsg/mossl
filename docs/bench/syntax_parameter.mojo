from benchmark import run, keep

@always_inline
fn loop_runtime(iters: Int):
    var total = 0
    for i in range(iters):
        total += i
    keep(total)

@always_inline
fn loop_parameter[iters: Int]():
    var total = 0
    @parameter
    for i in range(iters):
        total += i
    keep(total)

fn test_runtime():
    for _ in range(1000):
        loop_runtime(100)

fn test_parameter():
    for _ in range(1000):
        loop_parameter[100]()

fn main() raises:
    print("--- @parameter specialization vs runtime argument ---")
    var report_rt = run[test_runtime](max_runtime_secs=0.5)
    print("Runtime argument:    Mean:", report_rt.mean("ms"), "ms")

    var report_param = run[test_parameter](max_runtime_secs=0.5)
    print("Parameter specialization: Mean:", report_param.mean("ms"), "ms")