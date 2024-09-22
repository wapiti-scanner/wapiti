#!/bin/python3
import re
import sys
import json

# This python script will check reports with urls in it 
# It takes 2 arguments: the assertion file and the produced report in their respective order
# It was tailored for the log4shell test, you may need to modify it for other tests if you have 
# similar needs

KEY_NOT_FOUND_STR = "Key {key} doesn't exist in the report"
CONTENT_MISTMATCH_STR = "CONTENT:\n\n{content_report} \n\nMISMATCH WITH THE ASSERTION:\n\n {content_assertion}"
RAND_PAYLOAD_PART = re.compile(r"%28.*%29")


def match_trim(string_1: str, string_2: str, reg: str) -> tuple[str, str]:
    # Find the first match of the regex in both string, ensure that they 
    # are at the same positions, and remove them, regexes MUST exist in the string 
    # and MUST be at the same position
    assert (match_1 := reg.search(string_1)) and (match_2 := reg.search(string_2)), \
        "Regex: no match found"
    return string_1[:match_1.start()] + string_1[match_1.end():], \
           string_2[:match_2.start()] + string_2[match_2.end():]


def static_checking(report, assertion, regex):
    if isinstance(report, dict) and isinstance(assertion, dict):
        for key, _ in report.items():
            assert key in assertion, KEY_NOT_FOUND_STR.format(key=key)
            if key == "http_request":
                report[key], assertion[key] = match_trim(report[key], assertion[key], regex)
            static_checking(report[key], assertion[key], regex)
    elif isinstance(report, list) and isinstance(assertion, list):
        for item_report, item_assertion in zip(report, assertion):
            static_checking(item_report, item_assertion, regex)
    else:
        assert report == assertion, \
            CONTENT_MISTMATCH_STR.format(content_report=report, content_assertion=assertion)


def main():
    assert len(sys.argv) == 3, "wrong number of arguments"

    with open(sys.argv[1], "r") as assertion_file:
        json_assertion = json.load(assertion_file)

    with open(sys.argv[2], "r") as report_file:
        json_report = json.load(report_file)

    static_checking(json_report, json_assertion, RAND_PAYLOAD_PART)

    return 0


if __name__ == "__main__":
    sys.exit(main())
