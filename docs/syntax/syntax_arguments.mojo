from collections import InlineArray

from benchmark import run, keep

# Mojo modern argument conventions:
# 1. read (default in fn): The function gets a read-only reference. No copy is made.
#    This replaces the obsolete 'borrowed' keyword.
# 2. mut: The function gets a mutable reference. Changes affect the caller.
#    This replaces the obsolete 'inout' keyword.
# 3. var: The function takes ownership (equivalent to the old 'owned'). 
#    This may involve a copy or a move (if the caller uses ^).

struct LargeStruct(Copyable, Movable):
    var data: InlineArray[Int, 1024]

    fn __init__(out self, data: InlineArray[Int, 1024]):
        self.data = data

    fn __copyinit__(out self, read other: Self):
        # Explicit copy logic using 'read' convention
        self.data = other.data

    fn __moveinit__(out self, deinit other: Self):
        # Efficient move logic using 'deinit' to signal destruction of source
        self.data = other.data

    fn copy(self) -> Self:
        return LargeStruct(self.data)

# 's' is read-only. We use the explicit 'read' keyword for demonstration.
fn pass_read_reference(read s: LargeStruct):
    var x = s.data[0]
    keep(x)

# 's' is owned/mutable copy. The function gets its own unique instance.
fn pass_var_owned(var s: LargeStruct):
    var x = s.data[0]
    keep(x)

fn test_read():
    var s = LargeStruct(InlineArray[Int, 1024](0))
    for _ in range(1000):
        # Passing by reference (read), very fast.
        pass_read_reference(s)

fn test_var_move():
    for _ in range(1000):
        var s = LargeStruct(InlineArray[Int, 1024](0))
        # Use '^' (transfer operator) to move ownership.
        pass_var_owned(s^)

fn test_var_copy():
    var s = LargeStruct(InlineArray[Int, 1024](0))
    for _ in range(1000):
        # Explicit copy when passing to a 'var' argument
        pass_var_owned(s.copy())

fn main() raises:
    print("--- Modern Argument Conventions (1024 Ints struct) ---")
    
    # 'read' is usually the fastest as it avoids all memory management/copying.
    var report_read = run[test_read](max_runtime_secs=0.5)
    print("Read Reference: Mean:", report_read.mean("ms"), "ms")

    # Move is efficient but requires setting up the object to be moved.
    var report_move = run[test_var_move](max_runtime_secs=0.5)
    print("Var (Moved):    Mean:", report_move.mean("ms"), "ms")

    # Copy is the slowest due to memory duplication.
    var report_copy = run[test_var_copy](max_runtime_secs=0.5)
    print("Var (Copied):   Mean:", report_copy.mean("ms"), "ms")