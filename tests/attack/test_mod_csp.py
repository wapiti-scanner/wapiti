from wapitiCore.attack.mod_csp import mod_csp


def test_bad_csp():
    csp_dict = mod_csp.csp_header_to_dict("script-src 'self' 'unsafe-inline'; object-src 'none';")
    assert mod_csp.check_policy_values("script-src", csp_dict) == 0
