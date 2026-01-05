#!/usr/bin/env python3
"""
Benchmark script for HTTPS GET requests.
Equivalent to tests/integration/test_https_get.mojo but with timing measurements.
"""
import time
import statistics
from typing import List, Tuple

try:
    import requests
    USE_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    USE_REQUESTS = False


def test_https_get_site(url: str, expected_text: str = "") -> Tuple[bool, float]:
    """
    Test HTTPS GET request to a site and measure timing.
    
    Returns:
        Tuple of (success: bool, duration: float in seconds)
    """
    print(f"Testing {url}...", end=" ", flush=True)
    
    start_time = time.time()
    
    try:
        if USE_REQUESTS:
            response = requests.get(url, allow_redirects=True, timeout=30)
            status_code = response.status_code
            body = response.text
        else:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=30) as response:
                status_code = response.getcode()
                body = response.read().decode('utf-8', errors='ignore')
        
        end_time = time.time()
        duration = end_time - start_time
        
        if status_code != 200:
            print(f"FAILED (status {status_code}, {duration:.3f}s)")
            return False, duration
        
        if expected_text and expected_text not in body:
            print(f"FAILED (text not found, {duration:.3f}s)")
            return False, duration
        
        print(f"SUCCESS ({duration:.3f}s)")
        return True, duration
        
    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        print(f"ERROR ({type(e).__name__}, {duration:.3f}s)")
        return False, duration


def main():
    sites = [
        "https://example.com/",
        "https://www.google.com/",
        "https://www.modular.com/",
        "https://www.github.com/",
        "https://www.wikipedia.org/",
        "https://www.cloudflare.com/",
        "https://letsencrypt.org/",
        "https://www.digitalocean.com/",
        "https://www.microsoft.com/",
        "https://www.apple.com/",
    ]
    
    print("=" * 60)
    print("HTTPS GET Benchmark (Python)")
    print("=" * 60)
    print()
    
    results: List[Tuple[str, bool, float]] = []
    
    # Run tests
    for site in sites:
        success, duration = test_https_get_site(site, "")
        results.append((site, success, duration))
    
    print()
    print("=" * 60)
    print("Benchmark Results")
    print("=" * 60)
    
    # Calculate statistics
    successful_results = [r[2] for r in results if r[1]]
    failed_results = [r for r in results if not r[1]]
    
    if successful_results:
        print(f"\nSuccessful requests: {len(successful_results)}/{len(results)}")
        print(f"Total time (successful): {sum(successful_results):.3f}s")
        print(f"Average time: {statistics.mean(successful_results):.3f}s")
        print(f"Median time: {statistics.median(successful_results):.3f}s")
        if len(successful_results) > 1:
            print(f"Min time: {min(successful_results):.3f}s")
            print(f"Max time: {max(successful_results):.3f}s")
            if len(successful_results) > 2:
                print(f"Std deviation: {statistics.stdev(successful_results):.3f}s")
    
    if failed_results:
        print(f"\nFailed requests: {len(failed_results)}")
        for site, _, duration in failed_results:
            print(f"  - {site} ({duration:.3f}s)")
    
    print()
    print("Per-site timings:")
    for site, success, duration in results:
        status = "✓" if success else "✗"
        print(f"  {status} {site:40s} {duration:7.3f}s")
    
    print()
    if successful_results:
        print(f"Requests/sec (successful): {len(successful_results) / sum(successful_results):.2f}")


if __name__ == "__main__":
    main()

