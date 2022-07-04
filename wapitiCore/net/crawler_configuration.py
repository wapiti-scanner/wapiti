from typing import Union, Dict
from dataclasses import dataclass
from http.cookiejar import CookieJar

from wapitiCore.net import Request

DEFAULT_UA = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0"


@dataclass
class CrawlerConfiguration:
    base_request: Request
    timeout: float = 10.0
    secure: bool = False
    compression: bool = True
    user_agent: str = DEFAULT_UA
    proxy: str = None
    auth_credentials: tuple = tuple()
    auth_method: str = "basic"
    cookies: Union[Dict, CookieJar] = None
    stream: bool = False
    headers: dict = None
    drop_cookies: bool = False
