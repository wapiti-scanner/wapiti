"""Make respx mock httpx2.

respx only patches httpx and httpcore. The mocker below patches the same classes of
httpcore2 instead and becomes the default one, so `@respx.mock` and `respx.get(...)` keep
working unchanged. respx itself still depends on httpx: a mocked response is an
`httpx.Response`, which respx converts before handing it to httpx2.
"""
import respx.mocks
from respx.mocks import HTTPCoreMocker


class HTTPCore2Mocker(HTTPCoreMocker):
    name = "httpcore2"
    targets = [
        "httpcore2._sync.connection.HTTPConnection",
        "httpcore2._sync.connection_pool.ConnectionPool",
        "httpcore2._sync.http_proxy.HTTPProxy",
        "httpcore2._async.connection.AsyncHTTPConnection",
        "httpcore2._async.connection_pool.AsyncConnectionPool",
        "httpcore2._async.http_proxy.AsyncHTTPProxy",
    ]


respx.mocks.DEFAULT_MOCKER = HTTPCore2Mocker.name
