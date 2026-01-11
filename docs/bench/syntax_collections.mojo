from benchmark import run, keep
from collections import InlineArray, List

fn test_inline_array():
    var arr = InlineArray[Int, 1024](0)
    for i in range(1024):
        arr[i] = i
    var sum = 0
    for i in range(1024):
        sum += arr[i]
    keep(sum)

fn test_list():
    var l = List[Int]()
    for i in range(1024):
        l.append(i)
    var sum = 0
    for i in range(1024):
        sum += l[i]
    keep(sum)

fn test_list_capacity():
    var l = List[Int](capacity=1024)
    for i in range(1024):
        l.append(i)
    var sum = 0
    for i in range(1024):
        sum += l[i]
    keep(sum)

fn main() raises:
    print("--- InlineArray vs List (1024 elements) ---")
    var report_arr = run[test_inline_array](max_runtime_secs=0.5)
    print("InlineArray:        Mean:", report_arr.mean("ms"), "ms")

    var report_list = run[test_list](max_runtime_secs=0.5)
    print("List (no cap):     Mean:", report_list.mean("ms"), "ms")

    var report_list_cap = run[test_list_capacity](max_runtime_secs=0.5)
    print("List (with cap):   Mean:", report_list_cap.mean("ms"), "ms")