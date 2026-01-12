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

# --- Complex Structs and Variant Compatibility ---
# Structs containing non-ImplicitlyCopyable types (like List) require
# manual trait implementations. They cannot be ImplicitlyCopyable because
# the compiler won't synthesize a deep copy for a heap-allocated field.

from utils import Variant

struct ComplexState(Movable, Copyable):
    var l: List[Int]

    fn __init__(out self, var l: List[Int]):
        self.l = l^

    fn __copyinit__(out self, read other: Self):
        # Manual deep copy required for the List
        self.l = other.l.copy()

    fn __moveinit__(out self, deinit other: Self):
        # Manual move required for the List
        self.l = other.l^

fn test_variant_with_complex_state():
    var l = List[Int](1, 2, 3)
    var state = ComplexState(l^)
    
    # Variant requires its types to be Copyable and Movable.
    # Because ComplexState is NOT ImplicitlyCopyable, we MUST use '^' (move)
    # or '.copy()' (explicit deep copy) when initializing the Variant.
    var v = Variant[ComplexState](state^)
    keep(len(v[ComplexState].l))

fn main() raises:
    print("--- ImplicitlyCopyable vs Explicit Copying ---")
    
    var report_exp = run[test_explicit_copy](max_runtime_secs=0.5)
    print("Explicit .copy():  Mean:", report_exp.mean("ms"), "ms")

    var report_imp = run[test_implicit_copy](max_runtime_secs=0.5)
    print("Implicit Copy:     Mean:", report_imp.mean("ms"), "ms")
