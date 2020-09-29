from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import Additional, _


class mod_http_headers(Attack):
    """This class check the recommendations of security parameters in HTTP headers"""
    name = "http_headers"
    check_list_xframe = ['deny', 'sameorigin', 'allow-from']
    check_list_xss = ['1']
    check_list_xcontent = ['nosniff']
    check_list_hsts = ['max-age=']

    def is_set(self, response: object, header_name, check_list):
        if header_name not in response.headers:
            return False
        else:
            return any(element in response.headers[header_name].lower() for element in check_list)

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        response = self.crawler.get(request, follow_redirects=True)

        self.log_blue(_("Checking X-Frame-Options :"))
        if not self.is_set(response, "X-Frame-Options", self.check_list_xframe):
            self.log_red(Additional.INFO_XFRAME_OPTIONS)
            self.add_addition(
                category=Additional.MSG_HTTP_HEADERS,
                level=Additional.LOW_LEVEL,
                request=request,
                info=Additional.INFO_XFRAME_OPTIONS
            )
        else:
            self.log_green("OK")

        self.log_blue(_("Checking X-XSS-Protection :"))
        if not self.is_set(response, "X-XSS-Protection", self.check_list_xss):
            self.log_red(Additional.INFO_XSS_PROTECTION)
            self.add_addition(
                category=Additional.MSG_HTTP_HEADERS,
                level=Additional.LOW_LEVEL,
                request=request,
                info=Additional.INFO_XSS_PROTECTION
            )
        else:
            self.log_green("OK")

        self.log_blue(_("Checking X-Content-Type-Options :"))
        if not self.is_set(response, "X-Content-Type-Options", self.check_list_xcontent):
            self.log_red(Additional.INFO_XCONTENT_TYPE)
            self.add_addition(
                category=Additional.MSG_HTTP_HEADERS,
                level=Additional.LOW_LEVEL,
                request=request,
                info=Additional.INFO_XCONTENT_TYPE
            )
        else:
            self.log_green("OK")

        self.log_blue(_("Checking Strict-Transport-Security :"))
        if not self.is_set(response, "Strict-Transport-Security", self.check_list_hsts):
            self.log_red(Additional.INFO_HSTS)
            self.add_addition(
                category=Additional.MSG_HTTP_HEADERS,
                level=Additional.LOW_LEVEL,
                request=request,
                info=Additional.INFO_HSTS
            )
        else:
            self.log_green("OK")

        yield
