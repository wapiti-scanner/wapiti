from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import Additional, _
from wapitiCore.net.csp_utils import csp_header_to_dict, CSP_CHECK_LISTS, check_policy_values


# This module check the basics recommendations of CSP
class mod_csp(Attack):
    name = "csp"

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        response = self.crawler.get(request, follow_redirects=True)

        if "Content-Security-Policy" not in response.headers:
            self.log_red(Additional.MSG_NO_CSP)
            self.add_addition(
                category=Additional.INFO_CSP,
                level=Additional.LOW_LEVEL,
                request=request,
                info=Additional.MSG_NO_CSP
            )
        else:
            csp_dict = csp_header_to_dict(response.headers["Content-Security-Policy"])

            for policy_name in CSP_CHECK_LISTS:
                result = check_policy_values(policy_name, csp_dict)

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

        yield
