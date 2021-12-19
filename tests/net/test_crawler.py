import httpx
import respx
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.page import Page


@respx.mock
def test_extract_disconnect_urls_one_url():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a></body></html>"
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    page = Page(resp)

    crawler = AsyncCrawler(target_url, timeout=1)

    disconnect_urls = crawler._extract_disconnect_urls(page)

    assert len(disconnect_urls) == 1


@respx.mock
def test_extract_disconnect_urls_no_url():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/foobar'></a></body></html>"
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    page = Page(resp)

    crawler = AsyncCrawler(target_url, timeout=1)

    disconnect_urls = crawler._extract_disconnect_urls(page)

    assert len(disconnect_urls) == 0


@respx.mock
def test_extract_disconnect_urls_multiple_urls():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
                <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    page = Page(resp)

    crawler = AsyncCrawler(target_url, timeout=1)

    disconnect_urls = crawler._extract_disconnect_urls(page)

    assert len(disconnect_urls) == 2
