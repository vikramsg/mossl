from collections import InlineArray

from benchmark import run, keep

# Mojo argument conventions:
# 1. borrowed (default): The function gets a read-only reference. No copy is made.
#    This is the most efficient for large types.
# 2. inout: The function gets a mutable reference. Changes affect the caller.
# 3. owned: The function takes ownership. This may involve a copy (if the caller
#    doesn't use ^) or a move (if the caller uses ^).

struct LargeStruct(Copyable, Movable):
    var data: InlineArray[Int, 1024]

    fn __init__(out self, data: InlineArray[Int, 1024]):
        self.data = data

    fn __copyinit__(out self, other: Self):
        # Explicit copy logic
        self.data = other.data

    fn __moveinit__(out self, deinit other: Self):
        # Efficient move logic (transferring ownership)
        self.data = other.data

    fn copy(self) -> Self:
        return LargeStruct(self.data)

# 's' is borrowed by default in 'fn'. It's read-only and passed by reference.
fn pass_borrowed_reference(s: LargeStruct):
    var x = s.data[0]
    keep(x)

# 's' is owned. The function gets its own unique instance.
fn pass_owned_value(var s: LargeStruct):
    var x = s.data[0]
    keep(x)

fn test_borrowed():
    var s = LargeStruct(InlineArray[Int, 1024](0))
    for _ in range(1000):
        # Passing by reference, very fast.
        pass_borrowed_reference(s)

fn test_owned_move():
    for _ in range(1000):
        var s = LargeStruct(InlineArray[Int, 1024](0))
        # Use '^' (transfer operator) to move ownership instead of copying.
        pass_owned_value(s^)

fn test_owned_copy():
    var s = LargeStruct(InlineArray[Int, 1024](0))
    for _ in range(1000):
        # Explicit copy: expensive for large structures.
        pass_owned_value(s.copy())

fn main() raises:
    print("--- Argument Conventions (1024 Ints struct) ---")
    
    # Borrowed is usually the fastest as it avoids all memory management/copying.
    var report_borrowed = run[test_borrowed](max_runtime_secs=0.5)
    print("Borrowed Reference: Mean:", report_borrowed.mean("ms"), "ms")

    # Move is efficient but requires setting up the object to be moved.
    var report_move = run[test_owned_move](max_runtime_secs=0.5)
    print("Owned (Moved):      Mean:", report_move.mean("ms"), "ms")

    # Copy is the slowest due to memory duplication.
    var report_copy = run[test_owned_copy](max_runtime_secs=0.5)
    print("Owned (Copied):     Mean:", report_copy.mean("ms"), "ms")
