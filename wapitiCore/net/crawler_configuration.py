from typing import Optional
from dataclasses import dataclass
from http.cookiejar import CookieJar

from wapitiCore.net import Request

DEFAULT_UA = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0"


@dataclass
class HttpCredential:
    username: str
    password: str
    method: str = "basic"


@dataclass
class FormCredential:
    username: str
    password: str
    url: str
    enctype: Optional[str] = None
    data: Optional[str] = None


@dataclass
class CrawlerConfiguration:
    base_request: Request
    timeout: float = 10.0
    secure: bool = False
    compression: bool = True
    user_agent: str = DEFAULT_UA
    proxy: Optional[str] = None
    http_credential: Optional[HttpCredential] = None
    form_credential: Optional[FormCredential] = None
    cookies: Optional[CookieJar] = None
    stream: bool = False
    headers: Optional[dict] = None
    drop_cookies: bool = False
