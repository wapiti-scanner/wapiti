import requests, re
from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.net import crawler
from wapitiCore.language.vulnerability import Additional, _


# This module check the basics recommendations of CSP
class mod_csp(Attack):
    name = "csp"

    checks = ["default-src", "script-src", "object-src", "base-uri"]

    check_default = ["*", "unsafe-eval"]
    check_script_src = ["unsafe-inline", "data:", "http", "https"]
    check_object_src = ["none"]
    check_base_uri = ["none", "self"]

    all_check = [check_default, check_script_src, check_object_src, check_base_uri]

    def is_set(self, request: object):
        if 'Content-Security-Policy' in request.headers:
            return True
        else:
            return False

    def check_default_src(self, request, element, check_list, dict):
        '''
        This function return a number who tell us the status of the tested element in the CSP
        if the function return -1 : the element is missing in the CSP
        if the function return 0  : the element is set, but his value is not secure
        if the function return 1  : the element is set and his value is secure
        '''

        if not element in dict:
            return -1
        # If the tested element is default-src or script-src, we must ensure that none of this unsafe values are present in the CSP
        elif element in ["default-src", "script-src"]:
            if any(el in dict[element] for el in check_list):
                return 0
        # If the tested element is none of the previous list, we must ensure that one of this safe values is present in the CSP
        else:
            if any(elm in dict[element] for elm in check_list):
                return 1
            else:
                return 0

        return 1

    def attack(self):
        head = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        url = self.persister.get_root_url()
        request = Request(url)
        response = self.crawler.get(request, follow_redirects=True, headers=head)
        if not self.is_set(response):
            self.log_red(Additional.MSG_NO_CSP)
            self.add_addition(
                category=Additional.INFO_CSP,
                level=Additional.LOW_LEVEL,
                request=request,
                info=Additional.MSG_NO_CSP
            )
        else:
            csp = response.headers['Content-Security-Policy']
            dict_csp = {}
            regex = re.compile(r"\s*((?:'[^']*')|(?:[^'\s]+))\s*")
            for policy_string in csp.split(";"):
                policy_name, policy_values = policy_string.strip().split(" ", 1)
                dict_csp[policy_name] = policy_values

            self.log_blue(_("Checking CSP :"))
            i = 0
            for element in self.checks:

                result = self.check_default_src(response, element, self.all_check[i], dict_csp)
                if result == -1:
                    self.log_red(Additional.MSG_CSP_MISSIING.format(element))
                    self.add_addition(
                        category=Additional.INFO_CSP,
                        level=Additional.LOW_LEVEL,
                        request=request,
                        info=Additional.MSG_CSP_MISSIING.format(element)
                    )
                elif result == 0:
                    self.log_red(Additional.MSG_CSP_UNSAFE.format(element))
                    self.add_addition(
                        category=Additional.INFO_CSP,
                        level=Additional.LOW_LEVEL,
                        request=request,
                        info=Additional.MSG_CSP_UNSAFE.format(element)
                    )
                i += 1

        yield
