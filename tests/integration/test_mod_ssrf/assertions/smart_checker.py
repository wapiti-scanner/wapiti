#!/bin/python3
import re
import sys
import json

# This python script will check reports with different dates, IP and random numbers in it 
# It takes 2 arguments: the assertion file and the produced report in their respective order
# It was tailored for the SSRF test, you may need to modify it for other tests if you have 
# similar needs

ALL_KEYS = {"method", "path", "info", "level", "parameter", "wstg", "http_request"}
KEY_NOT_FOUND_STR = "Key {key} doesn't exist in the report"
CONTENT_MISTMATCH_STR = "Content {content_report} mismatch with the assertion {content_assertion}"
DATE_REG = re.compile(r"[0-9]{4}(-[0-9]{2}){2}T([0-9]{2}:){2}[0-9]{2}\+[0-9]{2}:[0-9]{2}")
IP_REG = re.compile(r"([0-9]{1,3}\.){3}[0-9]{1,3}")
RAND_URL_PART = re.compile(r"(/[0-9a-z]+){4}-")


def match_trim(string_1: str, string_2: str, reg: str) -> tuple[str, str]:
    # Find the first match of the regex in both string, ensure that they 
    # are at the same positions, and remove them, regexes MUST exist in the string 
    # and MUST be at the same position
    assert (match_1 := reg.search(string_1)) and (match_2 := reg.search(string_2)), \
        "Regex: no match found"
    return string_1[:match_1.start()] + string_1[match_1.end():], \
           string_2[:match_2.start()] + string_2[match_2.end():]


def static_structure_checking(report: dict):
    assert "vulnerabilities" in report, KEY_NOT_FOUND_STR.format(key='vulnerabilities')
    assert "Server Side Request Forgery" in report["vulnerabilities"], \
        KEY_NOT_FOUND_STR.format(key='Server Side Request Forgery')
    for key in ALL_KEYS:
        assert key in report["vulnerabilities"]["Server Side Request Forgery"][0], KEY_NOT_FOUND_STR.format(key=key)


def static_content_checking(report, assertions):
    for key in ALL_KEYS - {"info"}:
        content_report = report["vulnerabilities"]["Server Side Request Forgery"][0][key]
        content_assertion = assertions["vulnerabilities"]["Server Side Request Forgery"][0][key]
        assert content_report == \
               content_assertion, \
            CONTENT_MISTMATCH_STR.format(content_report=content_report, content_assertion=content_assertion)


def main():
    assert len(sys.argv) == 3, "wrong number of arguments"

    with open(sys.argv[1], "r") as assertion_file:
        json_assertion = json.load(assertion_file)

    with open(sys.argv[2], "r") as report_file:
        json_report = json.load(report_file)

    static_structure_checking(json_report)
    static_content_checking(json_report, json_assertion)

    # "info" contain some non-static data
    infos = {
        "assertion": json_assertion["vulnerabilities"]["Server Side Request Forgery"][0]["info"],
        "report": json_report["vulnerabilities"]["Server Side Request Forgery"][0]["info"]
    }

    # there are 2 times the IP address
    seq = [DATE_REG, IP_REG, IP_REG, RAND_URL_PART]
    for reg in seq:
        infos["assertion"], infos["report"] = match_trim(infos["assertion"],
                                                         infos["report"],
                                                         reg)
    assert infos["assertion"] == infos["report"]

    return 0


if __name__ == "__main__":
    sys.exit(main())
