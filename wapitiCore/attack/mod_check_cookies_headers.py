import requests
from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import Information

class mod_check_cookies_headers(Attack):

    name = "check_cookies_headers"

    def check_secure_flag(self, cookie: object):

        return cookie.secure

    def check_httponly_flag(self, cookie: object):

        return bool('HttpOnly' in cookie._rest)

    def attack(self):
        url = self.persister.get_root_url()
        session = requests.session()
        _req = session.get(url)
        request = Request(url)
        for cook in session.cookies:
            self.log_blue('Check HttpOnly flag :')
            if not self.check_httponly_flag(cook):
                self.log_red('HTTPONLY FLAG IS NOT SET')
                self.log_red(cook)
                self.add_addition(
                    category=Information.COOKIE_HTTPONLY_DISABLED,
                    level=Information.LOW_LEVEL,
                    request=request,
                    info="HttpOnly flag is not set in the cookie : {}".format(cook.name)
                )
            if not self.check_secure_flag(cook):
                self.log_red('SECURE FLAG IS NOT SET')
                self.add_addition(
                    category=Information.COOKIE_SECURE_DISABLED,
                    level=Information.LOW_LEVEL,
                    request=request,
                    info="Secure flag is not set in the cookie : {}".format(cook.name)
                )

        yield
