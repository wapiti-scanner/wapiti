from wapitiCore.attack.attack import Mutator
from wapitiCore.net import Request
from wapitiCore.model import str_to_payloadinfo


def test_mutations():
    req = Request(
        "http://perdu.com/page.php",
        method="POST",
        get_params=[["p", "login.php"]],
        post_params=[["user", "admin"], ["password", "letmein"]],
        file_params=[["file", ("pix.gif", b"GIF89a", "image/gif")]]
    )
    mutator = Mutator()

    count = 0
    for __ in mutator.mutate(req, str_to_payloadinfo(["INJECT"])):
        count += 1
    assert count == 4

    mutator = Mutator()
    count = 0
    for __ in mutator.mutate(req, str_to_payloadinfo(["PAYLOAD_1", "PAYLOAD_2", "PAYLOAD_3"])):
        count += 1
    assert count == 12

    mutator = Mutator(methods="G")
    count = 0
    for __ in mutator.mutate(req, str_to_payloadinfo(["PAYLOAD_1", "PAYLOAD_2", "PAYLOAD_3"])):
        count += 1
    assert count == 3

    mutator = Mutator(methods="P")
    count = 0
    for __ in mutator.mutate(req, str_to_payloadinfo(["PAYLOAD_1", "PAYLOAD_2", "PAYLOAD_3"])):
        count += 1
    assert count == 6

    mutator = Mutator(methods="PF")
    count = 0
    for __ in mutator.mutate(req, str_to_payloadinfo(["PAYLOAD_1", "PAYLOAD_2", "PAYLOAD_3"])):
        count += 1
    assert count == 9

    mutator = Mutator(parameters=["user", "file"])
    count = 0
    for __ in mutator.mutate(req, str_to_payloadinfo(["PAYLOAD_1", "PAYLOAD_2", "PAYLOAD_3"])):
        count += 1
    assert count == 6

    mutator = Mutator(skip={"p"})
    count = 0
    for __ in mutator.mutate(req, str_to_payloadinfo(["PAYLOAD_1", "PAYLOAD_2", "PAYLOAD_3"])):
        count += 1
    assert count == 9

    # JSESSIONID is marked as annoying parameter
    req2 = Request(
        "http://perdu.com/page.php",
        method="POST",
        get_params=[["JSESSIONID", "deadbeef"]],
        post_params=[["user", "admin"], ["password", "letmein"]],
        file_params=[["file", ("pix.gif", b"GIF89a", "image/gif")]]
    )
    mutator = Mutator()
    count = 0
    for __ in mutator.mutate(req2, str_to_payloadinfo(["INJECT"])):
        count += 1
    assert count == 3

    # Inject into query string. Will only work if method is GET without any parameter
    req3 = Request("http://perdu.com/page.php")
    mutator = Mutator(qs_inject=True)
    count = 0
    for __ in mutator.mutate(req3, str_to_payloadinfo(["PAYLOAD_1", "PAYLOAD_2"])):
        count += 1
    assert count == 2


def test_missing_value():
    req2 = Request(
        "http://perdu.com/directory/?high=tone",
    )
    # Filename of the target URL should be injected, but it is missing here, we should not raise a mutation
    mutator = Mutator()
    count = 0
    for __ in mutator.mutate(req2, str_to_payloadinfo(["[FILE_NAME]::$DATA"])):
        count += 1
    assert count == 0
