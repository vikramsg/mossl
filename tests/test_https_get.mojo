from testing import assert_equal

from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_https_get() raises:
    var client = HTTPSClient()
    var uri = URI.parse("https://example.com/")
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    assert_equal(res.status_code, 200)
    var body = to_string(res.body_raw.copy())
    assert_equal("Example Domain" in body, True)


fn main() raises:
    test_https_get()
