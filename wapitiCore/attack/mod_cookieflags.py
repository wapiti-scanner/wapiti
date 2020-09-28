from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import Additional, _


class mod_cookieflags(Attack):
    name = "cookieflags"

    @staticmethod
    def check_secure_flag(cookie: object):
        return cookie.secure

    @staticmethod
    def check_httponly_flag(cookie: object):
        return "HttpOnly" in cookie._rest

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        cookies = self.crawler.session_cookies
        for cookie in cookies:
            self.log_blue(_("Checking cookie : {}").format(cookie.name))
            if not self.check_httponly_flag(cookie):
                self.log_red(Additional.INFO_COOKIE_HTTPONLY.format(cookie.name))
                self.add_addition(
                    category=Additional.COOKIE_HTTPONLY_DISABLED,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=Additional.INFO_COOKIE_HTTPONLY.format(cookie.name)
                )

            if not self.check_secure_flag(cookie):
                self.log_red(Additional.INFO_COOKIE_SECURE.format(cookie.name))
                self.add_addition(
                    category=Additional.COOKIE_SECURE_DISABLED,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=Additional.INFO_COOKIE_SECURE.format(cookie.name)
                )

        yield
