import requests, re
from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import Additional, _


# This module check the basics recommendations of CSP
class mod_csp(Attack):
    name = "csp"

    checks = ["default-src", "script-src", "object-src", "base-uri"]

    check_default = ["default-src *", "default-src 'unsafe-eval'"]
    check_script_src = ["script-src 'unsafe-inline'", "script-src 'data:'", "script-src 'http:'", "script-src 'https:'"]
    check_object_src = ["object-src 'none'"]
    check_base_uri = ["base-uri 'none'", "base-uri 'self'"]

    all_check = [check_default, check_script_src, check_object_src, check_base_uri]

    def is_set(self, request: object, csp_attribute):
        if 'Content-Security-Policy' not in request.headers:
            return False
        else:
            return re.search(csp_attribute, request.headers['Content-Security-Policy'])

    def check_default_src(self, request, element, check_list):
        '''
        This function return a number who tell us the status of the tested element in the CSP
        if the function return -1 : the element is missing in the CSP
        if the function return 1  : the element is set, but his value is not secure
        if the function return 2  : the element is set and his value is secure
        '''

        if not self.is_set(request, element):
            return -1
        # If the tested element is default-src or script-src, we must ensure that none of this unsafe values are present in the CSP
        elif element in ["default-src", "script-src"]:
            if any(el in request.headers['Content-Security-Policy'] for el in check_list):
                return 1
        # If the tested element is none of the previous list, we must ensure that one of this safe values is present in the CSP
        else:
            if any(elm in request.headers['Content-Security-Policy'] for elm in check_list):
                return 2
            else:
                return 1

        return 2

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        response = self.crawler.get(request, follow_redirects=True)

        self.log_blue(_("Checking CSP :"))
        print("CSP : ", response.headers['Content-Security-Policy'])
        i = 0
        for def_src in self.checks:
            result = self.check_default_src(response, def_src, self.all_check[i])
            if result == -1:
                self.log_red(Additional.MSG_CSP_MISSIING.format(def_src))
                self.add_addition(
                    category=Additional.INFO_CSP,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=Additional.MSG_CSP_MISSIING.format(def_src)
                )
            elif result == 1:
                self.log_red(Additional.MSG_CSP_UNSAFE.format(def_src))
                self.add_addition(
                    category=Additional.INFO_CSP,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=Additional.MSG_CSP_UNSAFE.format(def_src)
                )
            i += 1

        yield
