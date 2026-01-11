from benchmark import run, keep

# @always_inline is useful for small, frequently called functions where the
# overhead of a function call (stack frame setup, jumping) is significant
# relative to the work being done. It is also critical for functions that
# take functional arguments (like closures) to allow the compiler to optimize
# across the call boundary.

@always_inline
fn add_and_multiply(x: Int, y: Int, z: Int) -> Int:
    # A tiny function where call overhead would be high
    return (x + y) * z

# Deeply nested calls benefit significantly from inlining because the compiler
# can see through the entire chain and optimize it as a single block of code.
@always_inline
fn level_1(x: Int) -> Int: return x + 1
@always_inline
fn level_2(x: Int) -> Int: return level_1(x) * 2
@always_inline
fn level_3(x: Int) -> Int: return level_2(x) - 3

# Non-inlined version for comparison
@ignore_builtin(id) # Prevent some auto-inlining for demonstration
fn noinline_1(x: Int) -> Int: return x + 1
@ignore_builtin(id)
fn noinline_2(x: Int) -> Int: return noinline_1(x) * 2
@ignore_builtin(id)
fn noinline_3(x: Int) -> Int: return noinline_2(x) - 3

fn main() raises:
    var val = 42

    @parameter
    fn test_inlined():
        var total = 0
        for i in range(1000):
            # The compiler will likely collapse this entire chain into:
            # total += ((val + i + 1) * 2) - 3
            total += level_3(val + i)
        keep(total)

    @parameter
    fn test_non_inlined():
        var total = 0
        for i in range(1000):
            total += noinline_3(val + i)
        keep(total)

    print("--- Always Inline vs Standard Function Calls ---")
    var report_inlined = run[test_inlined](max_runtime_secs=0.5)
    print("Inlined (3 levels):    Mean:", report_inlined.mean("ms"), "ms")

    var report_non_inlined = run[test_non_inlined](max_runtime_secs=0.5)
    print("Non-inlined (3 levels): Mean:", report_non_inlined.mean("ms"), "ms")