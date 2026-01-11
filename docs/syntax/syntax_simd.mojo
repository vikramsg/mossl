from collections import List

from benchmark import run, keep

fn main() raises:
    alias N = 64
    var A = List[Float32](capacity=N*N)
    var B = List[Float32](capacity=N*N)
    var C = List[Float32](capacity=N*N)
    for _ in range(N*N):
        A.append(1.0)
        B.append(1.0)
        C.append(0.0)

    @parameter
    fn test_scalar_matmul():
        for i in range(N):
            for j in range(N):
                var acc: Float32 = 0.0
                for k in range(N):
                    acc += A[i*N + k] * B[k*N + j]
                C[i*N + j] = acc
        keep(C[0])

    @parameter
    fn test_simd_matmul():
        alias simd_width = 16
        for i in range(N):
            for k in range(N):
                var aik = A[i*N + k]
                var vaik = SIMD[DType.float32, simd_width](aik)
                for j in range(0, N, simd_width):
                    # Manual load of B[k*N + j : k*N + j + simd_width]
                    var vb = SIMD[DType.float32, simd_width]()
                    @parameter
                    for s in range(simd_width):
                        vb[s] = B[k*N + j + s]
                    
                    # Load C[i*N + j : i*N + j + simd_width]
                    var vc = SIMD[DType.float32, simd_width]()
                    @parameter
                    for s in range(simd_width):
                        vc[s] = C[i*N + j + s]
                    
                    vc += vaik * vb
                    
                    # Store back to C
                    @parameter
                    for s in range(simd_width):
                        C[i*N + j + s] = vc[s]
        keep(C[0])

    print("--- SIMD Matrix Multiply (64x64) ---")
    var report_scalar = run[test_scalar_matmul](max_runtime_secs=0.5)
    print("Scalar Matmul:    Mean:", report_scalar.mean("ms"), "ms")

    var report_simd = run[test_simd_matmul](max_runtime_secs=0.5)
    print("SIMD (16) Matmul: Mean:", report_simd.mean("ms"), "ms")