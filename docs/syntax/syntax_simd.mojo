from sys import simd_width_of

from benchmark import run, keep

# SIMD (Single Instruction, Multiple Data) allows you to perform the same 
# operation on multiple data elements simultaneously.
#
# Efficient SIMD usage tips:
# 1. Use 'simd_width_of[DType]()' to auto-detect the optimal width for the current CPU.
# 2. Prefer power-of-two widths (e.g., 8, 16, 32) that match hardware registers (AVX, NEON).
# 3. Ensure data is contiguous in memory (like in a List or InlineArray).
# 4. Minimize branching inside SIMD loops, as masks can be expensive.

fn scalar_add(size: Int, p1: UnsafePointer[Float32], p2: UnsafePointer[Float32], res: UnsafePointer[Float32]):
    for i in range(size):
        res[i] = p1[i] + p2[i]

fn simd_add[width: Int](size: Int, p1: UnsafePointer[Float32], p2: UnsafePointer[Float32], res: UnsafePointer[Float32]):
    # Process 'width' elements at a time
    for i in range(0, size, width):
        # Load elements into a SIMD register
        var v1 = p1.load[width=width](i)
        var v2 = p2.load[width=width](i)
        # Perform the addition in parallel
        var v_res = v1 + v2
        # Store back to memory
        res.store(i, v_res)

fn main() raises:
    alias size = 1024
    alias width = simd_width_of[DType.float32]() * 2 # Typical width for demonstration
    
    var p1 = UnsafePointer[Float32].alloc(size)
    var p2 = UnsafePointer[Float32].alloc(size)
    var res = UnsafePointer[Float32].alloc(size)
    
    # Initialize data
    for i in range(size):
        p1[i] = 1.0
        p2[i] = 2.0

    @parameter
    fn test_scalar():
        scalar_add(size, p1, p2, res)
        keep(res[0])

    @parameter
    fn test_simd():
        simd_add[width](size, p1, p2, res)
        keep(res[0])

    print("--- SIMD vs Scalar Addition (Float32, size 1024) ---")
    print("Detected SIMD width for Float32:", simd_width_of[DType.float32]())
    
    var report_scalar = run[test_scalar](max_runtime_secs=0.5)
    print("Scalar: Mean:", report_scalar.mean("ms"), "ms")

    var report_simd = run[test_simd](max_runtime_secs=0.5)
    print("SIMD (width", width, "): Mean:", report_simd.mean("ms"), "ms")
    
    p1.free()
    p2.free()
    res.free()
