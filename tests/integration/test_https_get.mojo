from logger import Level, Logger
from testing import assert_equal

from lightbug_http import HTTPRequest, URI, to_string

from tls.https_client import HTTPSClient


fn test_https_get_site(url: String) raises:
    var log = Logger[Level.INFO]()
    log.info("Testing ", url, "...")
    var client = HTTPSClient(allow_redirects=True)
    var uri = URI.parse(url)
    var req = HTTPRequest(uri)
    var res = client.do(req^)
    assert_equal(res.status_code, 200)
    _ = to_string(res.body_raw.copy())

    log.info("Successfully tested ", url)


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

    for i in range(len(sites)):
        test_https_get_site(sites[i])
