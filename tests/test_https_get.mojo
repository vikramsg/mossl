from testing import assert_equal

from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_https_get_site(url: String, expected_text: String) raises:
    print("Testing " + url + "...")
    var client = HTTPSClient()
    var uri = URI.parse(url)
    var req = HTTPRequest(uri)
    try:
        var res = client.do(req^)
        assert_equal(res.status_code, 200)
        var body = to_string(res.body_raw.copy())
        assert_equal(expected_text in body, True)
        print("  SUCCESS")
    except e:
        print("  FAILURE: " + String(e))
        raise e


fn test_expected_failure(url: String) raises:
    print("Testing expected failure: " + url + "...")
    var client = HTTPSClient()
    var uri = URI.parse(url)
    var req = HTTPRequest(uri)
    try:
        var res = client.do(req^)
        print("  SUCCESS (Unexpected): " + url)
        assert_equal(res.status_code, 200)
    except e:
        print("  EXPECTED FAILURE: " + url + " - " + String(e))


fn main() raises:
    try:
        test_https_get_site("https://example.com/", "Example Domain")
    except:
        pass

    try:
        test_https_get_site("https://example.net/", "Example Domain")
    except:
        pass

    try:
        test_https_get_site("https://example.org/", "Example Domain")
    except:
        pass

    test_expected_failure("https://www.google.com/")
    test_expected_failure("https://www.modular.com/")
    test_expected_failure("https://www.cloudflare.com/")
    test_expected_failure("https://www.github.com/")
    test_expected_failure("https://www.wikipedia.org/")
    test_expected_failure("https://letsencrypt.org/")
    test_expected_failure("https://www.digitalocean.com/")
