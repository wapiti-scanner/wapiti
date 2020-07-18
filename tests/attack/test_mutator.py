from wapitiCore.attack.attack import Mutator, Flags
from wapitiCore.net.web import Request


def test_mutations():
    req = Request(
        "http://perdu.com/page.php",
        method="POST",
        get_params=[["p", "login.php"]],
        post_params=[["user", "admin"], ["password", "letmein"]],
        file_params=[["file", ["pix.gif", "GIF89a", "image/gif"]]]
    )
    mutator = Mutator(payloads=[("INJECT", Flags())])
    count = 0
    for __ in mutator.mutate(req):
        count += 1
    assert count == 4

    mutator = Mutator(payloads=[("PAYLOAD_1", Flags()), ("PAYLOAD_2", Flags()), ("PAYLOAD_3", Flags())])
    count = 0
    for __ in mutator.mutate(req):
        count += 1
    assert count == 12

    mutator = Mutator(methods="G", payloads=[("PAYLOAD_1", Flags()), ("PAYLOAD_2", Flags()), ("PAYLOAD_3", Flags())])
    count = 0
    for __ in mutator.mutate(req):
        count += 1
    assert count == 3

    mutator = Mutator(methods="P", payloads=[("PAYLOAD_1", Flags()), ("PAYLOAD_2", Flags()), ("PAYLOAD_3", Flags())])
    count = 0
    for __ in mutator.mutate(req):
        count += 1
    assert count == 6

    mutator = Mutator(methods="PF", payloads=[("PAYLOAD_1", Flags()), ("PAYLOAD_2", Flags()), ("PAYLOAD_3", Flags())])
    count = 0
    for __ in mutator.mutate(req):
        count += 1
    assert count == 9

    mutator = Mutator(
        payloads=[("PAYLOAD_1", Flags()), ("PAYLOAD_2", Flags()), ("PAYLOAD_3", Flags())],
        parameters=["user", "file"]
    )
    count = 0
    for __ in mutator.mutate(req):
        count += 1
    assert count == 6

    mutator = Mutator(
        payloads=[("PAYLOAD_1", Flags()), ("PAYLOAD_2", Flags()), ("PAYLOAD_3", Flags())],
        skip={"p"}
    )
    count = 0
    for __, __, __, __ in mutator.mutate(req):
        count += 1
    assert count == 9

    # JSESSIONID is marked as annoying parameter
    req2 = Request(
        "http://perdu.com/page.php",
        method="POST",
        get_params=[["JSESSIONID", "deadbeef"]],
        post_params=[["user", "admin"], ["password", "letmein"]],
        file_params=[["file", ["pix.gif", "GIF89a", "image/gif"]]]
    )
    mutator = Mutator(payloads=[("INJECT", Flags())])
    count = 0
    for __ in mutator.mutate(req2):
        count += 1
    assert count == 3

    # Inject into query string. Will only work if method is GET without any parameter
    req3 = Request("http://perdu.com/page.php")
    mutator = Mutator(payloads=[("PAYLOAD_1", Flags()), ("PAYLOAD_2", Flags())], qs_inject=True)
    count = 0
    for __, __, __, __ in mutator.mutate(req3):
        count += 1
    assert count == 2


def test_missing_value():
    req2 = Request(
        "http://perdu.com/directory/?high=tone",
    )
    # Filename of the target URL should be injected but it is missing here, we should not raise a mutation
    mutator = Mutator(payloads=[("[FILE_NAME]::$DATA", Flags())])
    count = 0
    for __ in mutator.mutate(req2):
        count += 1
    assert count == 0
