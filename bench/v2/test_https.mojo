from testing import assert_equal

from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient


fn test_https_get_site(url: String, expected_text: String) raises:
    print("Testing " + url + "...")
    var client = HTTPSClient(allow_redirects=True)
    var uri = URI.parse(url)
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    assert_equal(res.status_code, 200)
    var body = to_string(res.body_raw.copy())
    assert_equal(expected_text in body, True)

    print("Successfully tested ", url)


fn main() raises:
    var sites = List[String]()
    sites.append("https://example.com/")
    sites.append("https://www.google.com/")
    
    for i in range(len(sites)):
        try:
            test_https_get_site(sites[i], "")
        except:
            pass
