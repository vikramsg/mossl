"""
Usage:
    pixi run mojo run scripts/lightbug_https_get.mojo
"""
from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient


fn main() raises:
    var client = HTTPSClient()
    var uri = URI.parse("https://example.com/")
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    print("Status code: " + String(res.status_code))
    print("Response body: " + to_string(res.body_raw.copy()))
