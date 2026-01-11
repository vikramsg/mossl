from benchmark import run, keep

# ImplicitlyCopyable is a marker trait that allows the Mojo compiler to 
# implicitly call __copyinit__ when a value is passed to a 'var' argument.
# Without it, you must use .copy() or the transfer operator ^.

struct ExplicitCopy(Copyable):
    var val: Int
    fn __init__(out self, val: Int): self.val = val
    fn __copyinit__(out self, read other: Self): self.val = other.val
    fn copy(self) -> Self: return Self(self.val)

struct ImplicitCopy(ImplicitlyCopyable):
    var val: Int
    fn __init__(out self, val: Int): self.val = val
    fn __copyinit__(out self, read other: Self): self.val = other.val
    # copy() is inherited from Copyable

fn consume_var(var x: ExplicitCopy):
    keep(x.val)

fn consume_var_implicit(var x: ImplicitCopy):
    keep(x.val)

fn test_explicit_copy():
    var x = ExplicitCopy(42)
    for _ in range(1000):
        # MUST use .copy() or compiler error
        consume_var(x.copy())

fn test_implicit_copy():
    var x = ImplicitCopy(42)
    for _ in range(1000):
        # Compiler inserts .copy() automatically
        consume_var_implicit(x)

fn main() raises:
    print("--- ImplicitlyCopyable vs Explicit Copying ---")
    
    var report_exp = run[test_explicit_copy](max_runtime_secs=0.5)
    print("Explicit .copy():  Mean:", report_exp.mean("ms"), "ms")

    var report_imp = run[test_implicit_copy](max_runtime_secs=0.5)
    print("Implicit Copy:     Mean:", report_imp.mean("ms"), "ms")
