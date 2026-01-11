from collections import InlineArray

from benchmark import run, keep

struct LargeStruct(Copyable, Movable):
    var data: InlineArray[Int, 1024]

    fn __init__(out self, data: InlineArray[Int, 1024]):
        self.data = data

    fn __copyinit__(out self, other: Self):
        self.data = other.data

    fn __moveinit__(out self, deinit other: Self):
        self.data = other.data

    fn copy(self) -> Self:
        return LargeStruct(self.data)

fn pass_borrowed(s: LargeStruct):
    var x = s.data[0]
    keep(x)

fn pass_owned(var s: LargeStruct):
    var x = s.data[0]
    keep(x)

fn test_borrowed():
    var s = LargeStruct(InlineArray[Int, 1024](0))
    for _ in range(1000):
        pass_borrowed(s)

fn test_owned_move():
    for _ in range(1000):
        var s = LargeStruct(InlineArray[Int, 1024](0))
        pass_owned(s^)

fn test_owned_copy():
    var s = LargeStruct(InlineArray[Int, 1024](0))
    for _ in range(1000):
        pass_owned(s.copy())

fn main() raises:
    print("--- Argument Conventions (1024 Ints struct) ---")
    var report_borrowed = run[test_borrowed](max_runtime_secs=0.5)
    print("Borrowed:    Mean:", report_borrowed.mean("ms"), "ms")

    var report_move = run[test_owned_move](max_runtime_secs=0.5)
    print("Owned Move:  Mean:", report_move.mean("ms"), "ms")

    var report_copy = run[test_owned_copy](max_runtime_secs=0.5)
    print("Owned Copy:  Mean:", report_copy.mean("ms"), "ms")