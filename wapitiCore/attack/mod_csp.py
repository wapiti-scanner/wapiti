import re

from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import Additional, _


# This module check the basics recommendations of CSP
class mod_csp(Attack):
    name = "csp"

    check_list = ["default-src", "script-src", "object-src", "base-uri"]

    check_default = ["*", "unsafe-eval"]
    check_script_src = ["unsafe-inline", "data:", "http", "https"]
    check_object_src = ["none"]
    check_base_uri = ["none", "self"]

    all_check = [check_default, check_script_src, check_object_src, check_base_uri]

    def check_policy_values(self, policy_name, check_list, csp_dict):
        """
        This function return the status of the tested element in the CSP as an int. Possible values:
        -1 : the element is missing in the CSP
        0  : the element is set, but his value is not secure
        1  : the element is set and his value is secure
        """

        if policy_name not in csp_dict:
            return -1

        # If the tested element is default-src or script-src, we must ensure that none of this unsafe values are present
        if policy_name in ["default-src", "script-src"]:
            if any(policy_value in csp_dict[policy_name] for policy_value in check_list):
                return 0
        # If the tested element is none of the previous list, we must ensure that one of this safe values is present
        else:
            if any(policy_value in csp_dict[policy_name] for policy_value in check_list):
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

        if "Content-Security-Policy" not in response.headers:
            self.log_red(Additional.MSG_NO_CSP)
            self.add_addition(
                category=Additional.INFO_CSP,
                level=Additional.LOW_LEVEL,
                request=request,
                info=Additional.MSG_NO_CSP
            )
        else:
            csp = response.headers["Content-Security-Policy"]
            csp_dict = {}
            regex = re.compile(r"\s*((?:'[^']*')|(?:[^'\s]+))\s*")
            for policy_string in csp.split(";"):
                try:
                    policy_name, policy_values = policy_string.strip().split(" ", 1)
                except ValueError:
                    # Either it is malformed or we reach the end
                    continue
                csp_dict[policy_name] = [value.strip("'") for value in regex.findall(policy_values)]

            self.log_blue(_("Checking CSP :"))
            i = 0
            for policy_name in self.check_list:

                result = self.check_policy_values(policy_name, self.all_check[i], csp_dict)
                if result == -1:
                    self.log_red(Additional.MSG_CSP_MISSING.format(policy_name))
                    self.add_addition(
                        category=Additional.INFO_CSP,
                        level=Additional.LOW_LEVEL,
                        request=request,
                        info=Additional.MSG_CSP_MISSING.format(policy_name)
                    )
                elif result == 0:
                    self.log_red(Additional.MSG_CSP_UNSAFE.format(policy_name))
                    self.add_addition(
                        category=Additional.INFO_CSP,
                        level=Additional.LOW_LEVEL,
                        request=request,
                        info=Additional.MSG_CSP_UNSAFE.format(policy_name)
                    )
                i += 1

        yield
