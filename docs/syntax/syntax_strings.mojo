from benchmark import run, keep

fn main() raises:
    var s_val: String = "hello world"
    alias sl_val = "hello world"

    @parameter
    fn test_string():
        var count = 0
        for _ in range(1000):
            if s_val == "hello world":
                count += 1
        keep(count)

    @parameter
    fn test_string_literal():
        var count = 0
        for _ in range(1000):
            if sl_val == "hello world":
                count += 1
        keep(count)

    print("--- String vs StringLiteral ---")
    var report_s = run[test_string](max_runtime_secs=0.5)
    print("String:        Mean:", report_s.mean("ms"), "ms")

    var report_sl = run[test_string_literal](max_runtime_secs=0.5)
    print("StringLiteral: Mean:", report_sl.mean("ms"), "ms")