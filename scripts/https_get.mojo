"""
Usage:
    pixi run mojo -I src scripts/https_get.mojo
"""
from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient


fn main() raises:
    var sites = List[String]()
    sites.append("https://example.com/")
    sites.append("https://www.google.com/")
    sites.append("https://www.modular.com/")
    sites.append("https://www.github.com/")
    sites.append("https://www.wikipedia.org/")
    sites.append("https://www.cloudflare.com/")
    sites.append("https://letsencrypt.org/")
    sites.append("https://www.microsoft.com/")

    var client = HTTPSClient(allow_redirects=True)

    for i in range(len(sites)):
        var url = sites[i]
        print("\n--- Requesting " + url + " ---")
        try:
            var uri = URI.parse(url)
            var req = HTTPRequest(uri)
            var res = client.do(req^)
            print("Status code: " + String(res.status_code))
            var body = to_string(res.body_raw.copy())
            print("Response body (first 200 chars):")
            print(body[:200] + "...")
        except e:
            print("Failed to fetch " + url + ": " + String(e))
