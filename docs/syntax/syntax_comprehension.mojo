from collections import List

from benchmark import run, keep

fn main() raises:
    @parameter
    fn test_manual_loop():
        var l = List[Int]()
        for i in range(1000):
            l.append(i)
        keep(len(l))

    @parameter
    fn test_comprehension():
        var l = List[Int]([i for i in range(1000)])
        keep(len(l))

    print("--- List Comprehension vs Manual Loop ---")
    var report_manual = run[test_manual_loop](max_runtime_secs=0.5)
    print("Manual Append: Mean:", report_manual.mean("ms"), "ms")

    var report_comp = run[test_comprehension](max_runtime_secs=0.5)
    print("Comprehension: Mean:", report_comp.mean("ms"), "ms")
