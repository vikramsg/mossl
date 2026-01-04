from lightbug_http import HTTPRequest, URI, to_string
from lightbug_http.client import Client

fn main() raises:
    var client = Client()
    var uri = URI.parse("http://httpbin.org/get")
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    print("Status code: " + String(res.status_code))
    print("Response body: " + to_string(res.body_raw.copy()))
