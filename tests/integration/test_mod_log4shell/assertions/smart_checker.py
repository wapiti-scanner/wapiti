#!/bin/python3
import re
import sys
import json

# This python script will check reports with urls in it 
# It takes 2 arguments: the assertion file and the produced report in their respective order
# It was tailored for the log4shell test, you may need to modify it for other tests if you have 
# similar needs

KEY_NOT_FOUND_STR = "Key {key} doesn't exist in the report"
CONTENT_MISTMATCH_STR = "Content {content_report} mismatch with the assertion {content_assertion}"
RAND_URL_PART = re.compile(r"(/[0-9a-z]+){4}-")
JSESSIONID_REG = re.compile(r"JSESSIONID=[0-9A-z]{32}")
PAYLOAD_REG = re.compile(r"jndi.*\.l")


def match_trim(string_1: str, string_2: str, reg: str) -> tuple[str, str]:
    # Find the first match of the regex in both string, ensure that they 
    # are at the same positions, and remove them, regexes MUST exist in the string 
    # and MUST be at the same position
    assert (match_1 := reg.search(string_1)) and (match_2 := reg.search(string_2)), \
        "Regex: no match found"
    return string_1[:match_1.start()] + string_1[match_1.end():], \
           string_2[:match_2.start()] + string_2[match_2.end():]


def static_checking(report, assertion):
    if isinstance(report, dict) and isinstance(assertion, dict):
        for key, value in report.items():
            assert key in assertion, KEY_NOT_FOUND_STR.format(key=key)
            if key != "http_request":
                static_checking(value, assertion[key])
    elif isinstance(report, list) and isinstance(assertion, list):
        for item_report, item_assertion in zip(report, assertion):
            static_checking(item_report, item_assertion)
    else:
        assert report == assertion, \
            CONTENT_MISTMATCH_STR.format(content_report=report, content_assertion=assertion)


def main():
    assert len(sys.argv) == 3, "wrong number of arguments"

    with open(sys.argv[1], "r") as assertion_file:
        json_assertion = json.load(assertion_file)

    with open(sys.argv[2], "r") as report_file:
        json_report = json.load(report_file)

    static_checking(json_report, json_assertion)

    # "http_requrest" contain some non-static data
    infos = {
        "assertion": json_assertion["vulnerabilities"]["Log4Shell"][0]["http_request"],
        "report": json_report["vulnerabilities"]["Log4Shell"][0]["http_request"]
    }

    if JSESSIONID_REG.search(infos["report"]) is not None:
        infos["assertion"], infos["report"] = match_trim(infos["assertion"],
                                                         infos["report"],
                                                         JSESSIONID_REG)
    infos["assertion"], infos["report"] = match_trim(infos["assertion"],
                                                     infos["report"],
                                                     PAYLOAD_REG)

    return 0


if __name__ == "__main__":
    sys.exit(main())
