# Authentication with cookies
Wapiti allow different authentications systems but the ones with cookies deserve to be explained in order to avoid any unexpected behavior or crash from Wapiti. 

## Cookies
As you may have seen, you can pass a file to Wapiti using ``-c`` or ``--cookie`` following the path of a file. If you don't want to use wapiti-getcookie as explained in the documentation but write your own, the ``COOKIE_FILE`` should be structured that way:
```JSON
{
    ".a-domain.com": {
        "/a/specific/valid/path": {
            "the_cookie_name": {
                "value": "0123456789abcdefghijklmnopqrstuvwxyz",
                "version": 0,
                "secure": false,
                "expires": null,
                "port": null
            }
        }
    },
    ".another-domain.xyz": {
        "/":{
            "another_cookie":{
                "value": "468546584",
                "version": 0,
                "secure": false,
                "expires": null,
                "port": null
            }
        }    
    }
}
```
Every fields above is mandatory and allow to set each cookie for each domains (or subdomains) for each paths Wapiti may come across.  

## Python plugin script 

Another option given by Wapiti is to provide a python script file that will generate an authentication cookie and pass it to the crawler. The working principle is well explained [here](https://github.com/wapiti-scanner/wapiti/pull/325) by @devl00p, however, it is hard to find and isn't up to date as some changes have been made in Wapiti's files; Its place definitively belong to the documentation. So here is the updated version:

---

Some web authentication mechanisms rely on using tokens received from xml/json responses or set using javascript.

Some websites also may ask for human validation (solving a captcha, giving the answer to a simple question, etc)

Even if a focus is made to improve authentication, Wapiti will never be able to support all auth mechanisms hence the need of providing a way for users to bring their own auth scripts to Wapiti.

The way it works is:
- specify a Python script using ``--auth-script`` option
- the script must have an async function called run with the following prototype:

```Python
async def run(crawler_configuration: CrawlerConfiguration, auth_url: str, headless: str = "no")
```

It is up to the script to do whatever it needs to solve the authentication.

At the end, the script should overwrite some values on the CrawlerConfiguration object so Wapiti can use the data (tokens, custom headers, cookies, etc) that were obtained.

Here is an example of an auth script to login on juice-shop (do not reuse the script as is because credentials may expire) :
```Python
import json
from http.cookiejar import Cookie
                                                                                                                       
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration

async def run(crawler_configuration: CrawlerConfiguration, auth_url: str,headless: str = "no"):
    # Instantiate an AsyncCrawler
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        # Forge the login request
        request = Request(                                                                                   
                "https://juice-shop.herokuapp.com/rest/user/login",
                post_params='{"email":"toto@toto.com","password":"123456"}',
                enctype="application/json"
        )
        # Send it
        response = await crawler.async_send(request)
        data = response.json
        if not data:
            print("authentication failed")
            exit()
                                                                                                                       
        # Extract the token from the JSON response
        token = data["authentication"]["token"]
        print(f"token is {token}")

        # Create a cookie with the token found in JSON data
        cookie = Cookie(
            version=0,
            name="token",
            value=token,
            port=None,
            port_specified=False,
            domain="juice-shop.herokuapp.com",
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={'HttpOnly': None},
            rfc2109=False
        )                                                                                                              
        # Set it on the current crawler
        crawler.cookie_jar.set_cookie(cookie)
        # Try it
        request = Request(
                "https://juice-shop.herokuapp.com/rest/user/whoami",
        )                                                                                                              
        response = await crawler.async_get(
                request,
        )
        try:
            print(f'Login successful with user ID {response.json["user"]["id"]}')
        except KeyError:
            print("Authentication failed")
            exit()
                                                                                                                       
        # Overwrite cookies on crawler configuration so Wapiti can use them for scanning and attacks
        crawler_configuration.cookies = crawler.cookie_jar
```
---