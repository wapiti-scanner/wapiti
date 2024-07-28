from unittest import mock

from tests import get_mock_open
from wapitiCore.parsers.txt_payload_parser import TxtPayloadReader
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader


def test_txt_payload_reader():
    files = {
        "payloads.txt": "[TAB][NULL][EXTERNAL_ENDPOINT][LF][TIME] \nThis is dope\n",
    }

    with mock.patch("builtins.open", get_mock_open(files)):
        reader = TxtPayloadReader("payloads.txt")
        reader.add_handler(lambda x: x.replace("[EXTERNAL_ENDPOINT]", "http://perdu.com/"))
        reader.add_handler(lambda x: x.replace("[TIME]", "6"))
        reader.add_handler(lambda x: x.replace("dope", "success"))
        payloads = [line.payload for line in reader]
        assert payloads == ["\t[NULL]http://perdu.com/\n6", "This is success"]


def test_ini_payload_reader():
    files = {
        "payloads.ini": (
            "[DEFAULT]\n"
            "payload = None\n"
            "rules = None\n"
            "algorithm = simple\n"
            "\n"
            "[first]\n"
            "payload = 1st\n"
            "rules = root\n"
            "\tsysadmin\n"
            "\n"
            "[second]\n"
            "payload = 2nd\n"
            "rules = pwned\n"
            "algorithm = advanced\n"
        )
    }

    with mock.patch("builtins.open", get_mock_open(files)):
        reader = IniPayloadReader("payloads.ini")
        reader.add_key_handler("payload", lambda x: x.upper())
        reader.add_key_handler("rules", lambda x: x.split())
        payloads = [payload for payload in reader]
        assert payloads[0].payload == "1ST"
        assert payloads[0].rules == ["root", "sysadmin"]
        assert payloads[0].algorithm == "simple"
        assert payloads[1].algorithm == "advanced"

