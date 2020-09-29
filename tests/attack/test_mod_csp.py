from wapitiCore.attack.mod_csp import mod_csp


def test_csp_parsing():
    csp_dict = mod_csp.csp_header_to_dict("script-src 'self' 'unsafe-inline' data: http://*.fr ; object-src 'none' '';")
    assert csp_dict.keys() == {"script-src", "object-src"}
    assert set(csp_dict["script-src"]) == {"self", "unsafe-inline", "data:", "http://*.fr"}
    assert set(csp_dict["object-src"]) == {"none", ""}


def test_bad_csp_examples():
    # Some examples from https://www.slideshare.net/LukasWeichselbaum/breaking-bad-csp
    # May be useful too: https://www.netsparker.com/blog/web-security/negative-impact-incorrect-csp-implementations/

    # unsafe-inline script
    csp_dict = mod_csp.csp_header_to_dict("script-src 'self' 'unsafe-inline'; object-src 'none';")
    assert mod_csp.check_policy_values("script-src", csp_dict) == 0

    # URL schemes
    csp_dict = mod_csp.csp_header_to_dict("script-src 'self' https:; object-src 'none' ;")
    assert mod_csp.check_policy_values("script-src", csp_dict) == 0

    # wildcard
    csp_dict = mod_csp.csp_header_to_dict("script-src 'self' *; object-src 'none' ;")
    assert mod_csp.check_policy_values("script-src", csp_dict) == 0


def test_missing_csp_directive():
    csp_dict = mod_csp.csp_header_to_dict("script-src 'self'")
    assert mod_csp.check_policy_values("default-src", csp_dict) == -1
