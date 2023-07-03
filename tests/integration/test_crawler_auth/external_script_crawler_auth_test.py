from http.cookiejar import Cookie
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration


async def run(crawler_configuration: CrawlerConfiguration, auth_url: str, headless: str = "no"):
    # Instantiate an AsyncCrawler
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        token = "0123456789abcdefghijklmnopqrstuvwxyz"
        print(f"token is {token}")

        try:
            # Create a cookie with the token found in JSON data
            cookie = Cookie(
                version=0,
                name="token",
                value=token,
                port=None,
                domain="",
                domain_specified=False,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=False,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={'HttpOnly': None},
                rfc2109=False,
                port_specified=False
            )
        except:
            print("cookie init failed")
        try:
            # Set it on the current crawler
            crawler.cookie_jar.set_cookie(cookie)
        except:
            print("set_cookies for cookiejar has failed")

        try:
            # Overwrite cookies on crawler configuration so Wapiti can use them for scanning and attacks
            crawler_configuration.cookies = crawler.cookie_jar
        except:
            print("cookiejar assignement has failed")
