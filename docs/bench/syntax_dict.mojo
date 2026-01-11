from benchmark import run, keep
from collections import Dict, List

fn main() raises:
    alias size = 1000
    var d = Dict[Int, Int]()
    var keys = List[Int](capacity=size)
    for i in range(size):
        d[i] = i
        keys.append(i)

    @parameter
    fn test_dict_lookup() raises:
        var total = 0
        for i in range(size):
            total += d[i]
        keep(total)

    @parameter
    fn test_list_search():
        var total = 0
        for i in range(size):
            # Linear search
            for j in range(size):
                if keys[j] == i:
                    total += keys[j]
                    break
        keep(total)

    print("--- Dict Lookup vs List Linear Search (1k elements) ---")
    var report_dict = run[test_dict_lookup](max_runtime_secs=0.5)
    print("Dict Lookup: Mean:", report_dict.mean("ms"), "ms")

    var report_list = run[test_list_search](max_runtime_secs=0.5)
    print("List Search: Mean:", report_list.mean("ms"), "ms")