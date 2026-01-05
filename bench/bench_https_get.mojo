from collections import List
from time import perf_counter

from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient

@fieldwise_init
struct Result(Copyable, Movable, ImplicitlyCopyable):
    var url: String
    var success: Bool
    var duration: Float64


fn test_https_get_site(url: String, expected_text: String) -> Result:
    print("Testing " + url + "...", end=" ")
    
    var start = perf_counter()
    var success = False
    var error_name = ""
    
    try:
        var client = HTTPSClient(allow_redirects=True)
        var uri = URI.parse(url)
        var req = HTTPRequest(uri)
        var res = client.do(req^)
        
        if res.status_code == 200:
            var body = to_string(res.body_raw.copy())
            if expected_text == "" or expected_text in body:
                success = True
            else:
                error_name = "text not found"
        else:
            error_name = "status " + String(res.status_code)
    except:
        error_name = "Exception"
    
    var end = perf_counter()
    var duration = end - start
    
    if success:
        print("SUCCESS (" + String(duration)[:6] + "s)")
    else:
        if error_name != "":
            print("ERROR (" + error_name + ", " + String(duration)[:6] + "s)")
        else:
            print("FAILED (" + String(duration)[:6] + "s)")
    
    return Result(url, success, duration)


fn mean(values: List[Float64]) -> Float64:
    if len(values) == 0:
        return 0.0
    var sum: Float64 = 0.0
    for v in values:
        sum += v
    return sum / Float64(len(values))


fn median(values: List[Float64]) -> Float64:
    if len(values) == 0:
        return 0.0
    if len(values) == 1:
        return values[0]
    
    # Create a sorted copy
    var sorted_vals = List[Float64]()
    for v in values:
        sorted_vals.append(v)
    
    # Simple bubble sort (fine for small lists)
    for i in range(len(sorted_vals)):
        for j in range(len(sorted_vals) - 1 - i):
            if sorted_vals[j] > sorted_vals[j + 1]:
                var temp = sorted_vals[j]
                sorted_vals[j] = sorted_vals[j + 1]
                sorted_vals[j + 1] = temp
    
    var mid = len(sorted_vals) // 2
    if len(sorted_vals) % 2 == 0:
        return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0
    else:
        return sorted_vals[mid]


fn stdev(values: List[Float64]) -> Float64:
    if len(values) <= 1:
        return 0.0
    
    var m = mean(values)
    var sum_sq_diff: Float64 = 0.0
    for v in values:
        var diff = v - m
        sum_sq_diff += diff * diff
    
    var variance = sum_sq_diff / Float64(len(values) - 1)
    return variance ** 0.5


fn format_float(val: Float64) -> String:
    var s = String(val)
    # Truncate to 3 decimal places
    var dot_pos = -1
    for i in range(len(s)):
        if s[i] == '.':
            dot_pos = i
            break
    
    if dot_pos == -1:
        return s + ".000"
    
    if dot_pos + 4 <= len(s):
        return s[:dot_pos + 4]
    else:
        # Pad with zeros
        var result = s
        while len(result) < dot_pos + 4:
            result += "0"
        return result


fn main() raises:
    var sites = List[String]()
    sites.append("https://example.com/")
    sites.append("https://www.google.com/")
    sites.append("https://www.modular.com/")
    sites.append("https://www.github.com/")
    sites.append("https://www.wikipedia.org/")
    sites.append("https://www.cloudflare.com/")
    sites.append("https://letsencrypt.org/")
    sites.append("https://www.digitalocean.com/")
    sites.append("https://www.microsoft.com/")
    sites.append("https://www.apple.com/")
    
    print("============================================================")
    print("HTTPS GET Benchmark (Mojo)")
    print("============================================================")
    print()
    
    var results = List[Result]()
    
    # Run tests
    for i in range(len(sites)):
        var result = test_https_get_site(sites[i], "")
        results.append(result)
    
    print()
    print("============================================================")
    print("Benchmark Results")
    print("============================================================")
    
    # Separate successful and failed results
    var successful_durations = List[Float64]()
    var failed_results = List[Result]()
    
    for result in results:
        if result.success:
            successful_durations.append(result.duration)
        else:
            failed_results.append(result)
    
    if len(successful_durations) > 0:
        var total: Float64 = 0.0
        for d in successful_durations:
            total += d
        
        print("\nSuccessful requests: " + String(len(successful_durations)) + "/" + String(len(results)))
        print("Total time (successful): " + format_float(total) + "s")
        print("Average time: " + format_float(mean(successful_durations)) + "s")
        print("Median time: " + format_float(median(successful_durations)) + "s")
        
        if len(successful_durations) > 1:
            var min_val = successful_durations[0]
            var max_val = successful_durations[0]
            for d in successful_durations:
                if d < min_val:
                    min_val = d
                if d > max_val:
                    max_val = d
            print("Min time: " + format_float(min_val) + "s")
            print("Max time: " + format_float(max_val) + "s")
            
            if len(successful_durations) > 2:
                print("Std deviation: " + format_float(stdev(successful_durations)) + "s")
    
    if len(failed_results) > 0:
        print("\nFailed requests: " + String(len(failed_results)))
        for result in failed_results:
            print("  - " + result.url + " (" + format_float(result.duration) + "s)")
    
    print()
    print("Per-site timings:")
    for result in results:
        var status: String
        if result.success:
            status = "✓"
        else:
            status = "✗"
        # Format: status + url (padded to 40) + duration (7 chars)
        var url_padded = result.url
        while len(url_padded) < 40:
            url_padded += " "
        var duration_str = format_float(result.duration)
        while len(duration_str) < 7:
            duration_str = " " + duration_str
        print("  " + status + " " + url_padded + " " + duration_str + "s")
    
    print()
    if len(successful_durations) > 0:
        var total: Float64 = 0.0
        for d in successful_durations:
            total += d
        var req_per_sec = Float64(len(successful_durations)) / total
        print("Requests/sec (successful): " + format_float(req_per_sec))

