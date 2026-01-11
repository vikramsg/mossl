from collections import List
from logger import Level, Logger
from math import sqrt
from time import perf_counter

from crypto.bytes import constant_time_compare


fn mean(data: List[Float64]) -> Float64:
    var sum: Float64 = 0
    for i in range(len(data)):
        sum += data[i]
    return sum / len(data)


fn variance(data: List[Float64], mean_val: Float64) -> Float64:
    var sum: Float64 = 0
    if len(data) < 2:
        return 0.0
    for i in range(len(data)):
        var diff = data[i] - mean_val
        sum += diff * diff
    return sum / (len(data) - 1)


fn t_test(data1: List[Float64], data2: List[Float64]) -> Float64:
    var m1 = mean(data1)
    var m2 = mean(data2)
    var v1 = variance(data1, m1)
    var v2 = variance(data2, m2)
    var n1 = Float64(len(data1))
    var n2 = Float64(len(data2))

    if v1 / n1 + v2 / n2 == 0:
        return 0.0
    return (m1 - m2) / sqrt(v1 / n1 + v2 / n2)


fn test_ct_compare_timing() raises:
    var log = Logger[Level.INFO]()
    log.info("Running side-channel timing test for constant_time_compare...")
    var n = 10000  # More samples for better statistics
    var data_same = List[Float64]()
    var data_diff = List[Float64]()

    var a = List[UInt8]()
    for _ in range(256):
        a.append(1)
    var b_same = a.copy()
    var b_diff_early = a.copy()
    b_diff_early[0] = 0  # Difference at the beginning

    # Warmup
    for _ in range(1000):
        _ = constant_time_compare(a, b_same)

    for _ in range(n):
        var t0 = perf_counter()
        _ = constant_time_compare(a, b_same)
        var t1 = perf_counter()
        data_same.append(Float64(t1 - t0))

        t0 = perf_counter()
        _ = constant_time_compare(a, b_diff_early)
        t1 = perf_counter()
        data_diff.append(Float64(t1 - t0))

    var t_stat = t_test(data_same, data_diff)
    var abs_t = t_stat
    if abs_t < 0:
        abs_t = -abs_t

    log.info("T-statistic (same vs diff-at-start):", t_stat)

    if abs_t > 10.0:
        log.warning(
            "Potential timing leak detected in constant_time_compare!"
        )
    else:
        log.info("No significant timing leak detected (within noise threshold).")


fn main() raises:
    test_ct_compare_timing()
