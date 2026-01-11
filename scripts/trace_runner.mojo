from sys import argv

from subprocess import run
import emberjson


fn main() raises:
    var config_path = "tests/trace_config.json"
    if len(argv()) > 1:
        config_path = argv()[1]

    var f = open(config_path, "r")
    var config_str = f.read()
    f.close()

    var config_json = emberjson.parse(config_str)
    var max_steps = config_json["max_steps"].copy().string()
    var max_samples = config_json["max_samples"].copy().string()
    var seed = config_json["seed"].copy().string()

    var cases_val = config_json["cases"].copy()
    if not cases_val.is_array():
        raise Error("Expected cases to be an array")

    var cases = cases_val.array().copy()

    for i in range(len(cases)):
        var case_val = cases[i].copy()
        var name = case_val["name"].copy().string()
        var spec = case_val["spec"].copy().string()
        var test = case_val["test"].copy().string()
        var trace_path = "/tmp/quint_trace_" + name + ".json"

        var quint_cmd = "npx quint run --out-itf " + trace_path
        quint_cmd += " --max-steps " + max_steps
        quint_cmd += " --max-samples " + max_samples
        quint_cmd += " --seed " + seed
        quint_cmd += " " + spec

        var test_cmd = (
            "QUINT_TRACE_PATH=" + trace_path + " mojo run -I src " + test
        )
        var rm_cmd = "rm -f " + trace_path

        print("Running: " + quint_cmd)
        _ = run(quint_cmd)
        print("Running: " + test_cmd)
        _ = run(test_cmd)
        print("Running: " + rm_cmd)
        _ = run(rm_cmd)
