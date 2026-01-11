from algorithm import vectorize, parallelize
from sys import simd_width_of
from benchmark import run, keep
from memory import UnsafePointer

# Vectorize: Automatically handles the loop chunks and tail for SIMD.
# Parallelize: Distributes work across multiple CPU threads.

fn run_vectorize(size: Int, p1: UnsafePointer[Float32], p2: UnsafePointer[Float32], res: UnsafePointer[Float32]):
    alias width = simd_width_of[DType.float32]()
    
    @always_inline
    fn closure[w: Int](i: Int):
        res.store(i, p1.load[width=w](i) + p2.load[width=w](i))
    
    # vectorize handles the looping and the 'remainder' (tail) elements automatically.
    vectorize[width](size, closure)

fn run_parallelize(size: Int, p1: UnsafePointer[Float32], p2: UnsafePointer[Float32], res: UnsafePointer[Float32]):
    # parallelize splits the range into chunks and runs them on different threads.
    # Note: For simple addition, the overhead of threading might exceed the gains
    # unless 'size' is very large.
    @always_inline
    fn worker(i: Int):
        res[i] = p1[i] + p2[i]
    
    parallelize(size, worker)

fn main() raises:
    alias size = 10000
    var p1 = UnsafePointer[Float32].alloc(size)
    var p2 = UnsafePointer[Float32].alloc(size)
    var res = UnsafePointer[Float32].alloc(size)

    @parameter
    fn test_vectorize():
        run_vectorize(size, p1, p2, res)
        keep(res[0])

    @parameter
    fn test_parallelize():
        run_parallelize(size, p1, p2, res)
        keep(res[0])

    print("--- Vectorize and Parallelize (Float32, size 10000) ---")
    
    var report_vec = run[test_vectorize](max_runtime_secs=0.5)
    print("Vectorize:    Mean:", report_vec.mean("ms"), "ms")

    var report_par = run[test_parallelize](max_runtime_secs=0.5)
    print("Parallelize:  Mean:", report_par.mean("ms"), "ms")

    p1.free()
    p2.free()
    res.free()
