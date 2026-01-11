from benchmark import run, keep

# @parameter variables and arguments are evaluated at compile-time.
# This allows for 'metaprogramming' or 'compile-time specialization'.
# When you use a parameter, the compiler generates a unique version of the 
# function (or loop) for that specific value, allowing for aggressive 
# optimizations like constant folding and dead code elimination.

@always_inline
fn loop_runtime(iters: Int):
    # 'iters' is a runtime value. The loop bound is checked every time.
    var total = 0
    for i in range(iters):
        total += i
    keep(total)

@always_inline
fn loop_parameter[iters: Int]():
    # 'iters' is a compile-time constant (parameter).
    # The compiler knows the exact number of iterations during compilation.
    var total = 0
    
    # @parameter on a loop forces the compiler to unroll or specialize the loop.
    # If 'iters' is 100, the compiler can optimize this loop specifically for 100.
    @parameter
    for i in range(iters):
        total += i
    keep(total)

fn test_runtime():
    # Calling with a runtime value
    for _ in range(1000):
        loop_runtime(100)

fn test_parameter():
    # Calling with a compile-time parameter [100]
    for _ in range(1000):
        loop_parameter[100]()

fn main() raises:
    print("--- @parameter specialization vs runtime argument ---")
    
    # Runtime version: flexible but potentially slower due to lack of constant info.
    var report_rt = run[test_runtime](max_runtime_secs=0.5)
    print("Runtime argument:    Mean:", report_rt.mean("ms"), "ms")

    # Parameter version: specialized for 100, allowing full optimization.
    var report_param = run[test_parameter](max_runtime_secs=0.5)
    print("Parameter specialization: Mean:", report_param.mean("ms"), "ms")
