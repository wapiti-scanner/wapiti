from operator import attrgetter

from wapitiCore.net.cookies import headless_cookies_to_cookiejar, mitm_jar_to_cookiejar


def test_headless_cookies_to_cookiejar():
    headless_cookie = [
        {
            "name": "prov",
            "value": "0dcb6677-d4f8-b45d-3097-74490011b9f5",
            "path": "/",
            "domain": ".stackoverflow.com",
            "secure": False,
            "httpOnly": True,
            "expiry": 2682374400
        }
    ]

    jar = headless_cookies_to_cookiejar(headless_cookie)
    assert jar
    cookie = [_ for _ in jar][0]
    assert cookie.comment is None
    assert cookie.comment_url is None
    assert cookie.discard is True
    assert cookie.domain == ".stackoverflow.com"
    assert cookie.domain_initial_dot is False
    assert cookie.domain_specified is True
    assert cookie.expires is None
    assert cookie.name == "prov"
    assert cookie.path == "/"
    assert cookie.path_specified is True
    assert cookie.port is None
    assert cookie.port_specified is False
    assert cookie.rfc2109 is False
    assert cookie.secure is False
    assert cookie.value == "0dcb6677-d4f8-b45d-3097-74490011b9f5"
    assert cookie.version == 0


def test_mitm_jar_to_cookiejar():
    mitm_jar = {
        ("ovh.commander1.com", 443, "/"): {
            "tc_cj_v2": "cafebabe",
            "tc_cj_v2_cmp": "deadbeef"
        },
        (".commander1.com", 443, "/"): {"TCID": "2022102611252110711550640"},
        (".stackoverflow.com", 443, "/"): {"prov": "ef1e0ec9-7cd8-51c5-1c04-2c84a9a6481c"}
    }
    cookiejar = mitm_jar_to_cookiejar(mitm_jar)
    cookies = sorted(cookiejar, key=attrgetter("name"))
    assert len(cookies) == 4
    assert cookies[0].name == "TCID"
    assert cookies[0].value == "2022102611252110711550640"
    assert cookies[0].port == "443"
    assert cookies[0].port_specified is False
    assert cookies[0].domain == ".commander1.com"
    assert cookies[0].domain_specified is True

    assert cookies[1].name == "prov"
    assert cookies[1].value == "ef1e0ec9-7cd8-51c5-1c04-2c84a9a6481c"
    assert cookies[1].domain == ".stackoverflow.com"

    assert cookies[2].name == "tc_cj_v2"
    assert cookies[2].value == "cafebabe"
    assert cookies[2].domain == ".ovh.commander1.com"

    assert cookies[3].name == "tc_cj_v2_cmp"
    assert cookies[3].value == "deadbeef"
    assert cookies[3].domain == ".ovh.commander1.com"
