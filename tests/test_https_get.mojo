from testing import assert_equal

from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_https_get_example_com() raises:
    var client = HTTPSClient()
    var uri = URI.parse("https://example.com/")
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    assert_equal(res.status_code, 200)
    var body = to_string(res.body_raw.copy())
    assert_equal("Example Domain" in body, True)


fn test_https_get_example_net() raises:
    var client = HTTPSClient()
    var uri = URI.parse("https://example.net/")
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    assert_equal(res.status_code, 200)
    var body = to_string(res.body_raw.copy())
    assert_equal("Example Domain" in body, True)


fn test_https_get_example_org() raises:
    var client = HTTPSClient()
    var uri = URI.parse("https://example.org/")
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    assert_equal(res.status_code, 200)
    var body = to_string(res.body_raw.copy())
    assert_equal("Example Domain" in body, True)


fn test_expected_failure(url: String) raises:
    var client = HTTPSClient()
    var uri = URI.parse(url)
    var req = HTTPRequest(uri)
    try:
        var res = client.do(req^)
        print("SUCCESS (Unexpected): " + url)
        assert_equal(res.status_code, 200)
    except e:
        print("EXPECTED FAILURE: " + url + " - " + String(e))


fn main() raises:
    test_https_get_example_com()
    test_https_get_example_net()
    test_https_get_example_org()
    
    test_expected_failure("https://www.google.com/")
    test_expected_failure("https://www.modular.com/")
    test_expected_failure("https://www.cloudflare.com/")
    test_expected_failure("https://www.github.com/")
    test_expected_failure("https://www.wikipedia.org/")
    test_expected_failure("https://letsencrypt.org/")
    test_expected_failure("https://www.digitalocean.com/")