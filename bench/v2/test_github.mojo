from lightbug_http import HTTPRequest, URI
from tls.https_client import HTTPSClient

fn main() raises:
    print("Testing https://www.github.com/...")
    var client = HTTPSClient(allow_redirects=True)
    var uri = URI.parse("https://www.github.com/")
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    print("Status code:", res.status_code)
