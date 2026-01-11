from benchmark import run, keep
from collections import List
from memory import UnsafePointer

fn main() raises:
    alias size = 10000
    var data_list = List[Int](capacity=size)
    for i in range(size):
        data_list.append(i)
    
    var ptr = UnsafePointer[Int].alloc(size)
    for i in range(size):
        ptr[i] = i

    @parameter
    fn test_list_access():
        var total = 0
        for i in range(size):
            total += data_list[i]
        keep(total)

    @parameter
    fn test_pointer_access():
        var total = 0
        for i in range(size):
            total += ptr[i]
        keep(total)

    print("--- UnsafePointer vs List Indexing (10k elements) ---")
    var report_list = run[test_list_access](max_runtime_secs=0.5)
    print("List Indexing:    Mean:", report_list.mean("ms"), "ms")

    var report_ptr = run[test_pointer_access](max_runtime_secs=0.5)
    print("Pointer Access:   Mean:", report_ptr.mean("ms"), "ms")

    ptr.free()
