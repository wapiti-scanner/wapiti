from wapitiCore.net.sqlite_persister import SqlitePersister
from wapitiCore.net.web import Request


def test_persister():
    persister = SqlitePersister("/tmp/crawl.db")
    persister.set_root_url("http://perdu.com")

    simple_get = Request("http://perdu.com")
    persister.set_to_browse([simple_get])

    request = next(persister.get_to_browse())
    assert request == simple_get
