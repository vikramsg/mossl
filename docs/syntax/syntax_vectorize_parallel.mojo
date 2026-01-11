from sys import simd_width_of

from algorithm import vectorize, parallelize
from benchmark import run, keep
from memory import UnsafePointer

# Vectorize: Automatically handles the loop chunks and tail for SIMD.
# Parallelize: Distributes work across multiple CPU threads.

fn main() raises:
    alias size = 10000
    var p1 = UnsafePointer[Float32].alloc(size)
    var p2 = UnsafePointer[Float32].alloc(size)
    var res = UnsafePointer[Float32].alloc(size)

    # Initialize
    for i in range(size):
        p1[i] = 1.0
        p2[i] = 2.0

    @parameter
    fn test_vectorize():
        alias width = simd_width_of[DType.float32]()
        @parameter
        fn closure[w: Int](i: Int):
            res.store(i, p1.load[width=w](i) + p2.load[width=w](i))
        vectorize[closure, width](size)
        keep(res[0])

    @parameter
    fn test_parallelize():
        @parameter
        fn worker(i: Int):
            res[i] = p1[i] + p2[i]
        parallelize[worker](size)
        keep(res[0])

    print("--- Vectorize and Parallelize (Float32, size 10000) ---")
    
    var report_vec = run[test_vectorize](max_runtime_secs=0.5)
    print("Vectorize:    Mean:", report_vec.mean("ms"), "ms")

    var report_par = run[test_parallelize](max_runtime_secs=0.5)
    print("Parallelize:  Mean:", report_par.mean("ms"), "ms")

    p1.free()
    p2.free()
    res.free()
