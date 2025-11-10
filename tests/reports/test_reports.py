import json
import os
import os.path
import shutil
from time import gmtime
import tempfile

import httpx
import pytest

from wapitiCore.report import GENERATORS
from wapitiCore.report.htmlreportgenerator import level_to_css_class
from wapitiCore.net import Request
from wapitiCore.definitions import additionals, anomalies, vulnerabilities, flatten_references
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL
from wapitiCore.net.sql_persister import Response

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Set this to True to regenerate fixture files
REGENERATE_FIXTURES = False


@pytest.mark.parametrize("report_format", GENERATORS.keys())
def test_reports(report_format):
    report_gen = GENERATORS[report_format]()

    report_gen.set_report_info(
        "http://perdu.com",
        "folder",
        gmtime(0),
        "WAPITI_VERSION",
        None,
        None,
        123456,
        0
    )

    for vul in vulnerabilities:
        report_gen.add_vulnerability_type(
            vul.name(),
            vul.description(),
            vul.solution(),
            flatten_references(vul.references())
        )

    for anomaly in anomalies:
        report_gen.add_anomaly_type(
            anomaly.name(),
            anomaly.description(),
            anomaly.solution(),
            flatten_references(anomaly.references())
        )

    for additional in additionals:
        report_gen.add_additional_type(
            additional.name(),
            additional.description(),
            additional.solution(),
            flatten_references(additional.references())
        )

    request = Request("http://perdu.com/riri?foo=bar")
    report_gen.add_vulnerability(
        category="Reflected Cross Site Scripting",
        level=1,
        request=request,
        parameter="foo",
        info="This is dope",
        module="xss"
    )

    request = Request("http://perdu.com/fifi")
    report_gen.add_anomaly(
        category="Internal Server Error",
        level=2,
        request=request,
        parameter=None,
        info="This is the way",
        module="xss"
    )

    request = Request("http://perdu.com/?foo=bar")
    report_gen.add_additional(
        category="Fingerprint web technology",
        level=3,
        request=request,
        parameter="foo",
        info="loulou",
        module="wapp"
    )

    if REGENERATE_FIXTURES:
        fixture_path = os.path.join(DATA_DIR, f"report.{report_format}")
        if report_format == "html":
            with tempfile.TemporaryDirectory() as temp_dir:
                report_gen.generate_report(temp_dir)
                shutil.copy(report_gen.final_path, fixture_path)
        else:
            report_gen.generate_report(fixture_path)
        pytest.skip(f"Generated fixture for {report_format}")

    if report_format == "html":
        temp_obj = tempfile.TemporaryDirectory()
        output = temp_obj.name
    else:
        # Use a temporary file not deleted on close
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8')
        output = temp_file.name
        temp_file.close()

    report_gen.generate_report(output)

    if report_format == "html":
        generated_path = report_gen.final_path
    else:
        generated_path = output

    fixture_path = os.path.join(DATA_DIR, f"report.{report_format}")
    with (
        open(fixture_path, "r", encoding="utf-8") as expected_fd,
        open(generated_path, "r", encoding="utf-8") as generated_fd
    ):
        if report_format == "json":
            expected = json.load(expected_fd)
            generated = json.load(generated_fd)
            assert expected == generated
        else:
            assert expected_fd.read() == generated_fd.read()

    if report_format != "html":
        os.remove(output)


@pytest.mark.parametrize("level", [1, 2])
@pytest.mark.parametrize("report_format", GENERATORS.keys())
def test_detailed_reports(report_format, level):
    report_gen = GENERATORS[report_format]()

    crawled_pages = [
        {
            "request": {
                "url": "http://perdu.com/",
                "method": "GET",
                "headers": [],
                "referer": None,
                "enctype": "application/x-www-form-urlencoded",
                "encoding": "utf-8",
                "depth": 0,
            },
            "response": {
                "status_code": 200,
                "body": "Hello from crawled page",
                "headers": [["Content-Type", "text/html"]],
            },
        }
    ]

    report_gen.set_report_info(
        "http://perdu.com",
        "folder",
        gmtime(0),
        "WAPITI_VERSION",
        None,
        crawled_pages,
        1,
        level
    )

    for vul in vulnerabilities:
        report_gen.add_vulnerability_type(
            vul.name(),
            vul.description(),
            vul.solution(),
            flatten_references(vul.references())
        )

    request = Request("http://perdu.com/riri?foo=bar")
    response = Response(
        httpx.Response(
            status_code=200,
            headers=httpx.Headers([["Content-Type", "text/html"]]),
            text="<html><body>riri</body></html>"
        ),
        url="http://perdu.com/riri?foo=bar"
    )
    report_gen.add_vulnerability(
        category="Reflected Cross Site Scripting",
        level=1,
        request=request,
        response=response,
        parameter="foo",
        info="This is dope",
        module="xss"
    )

    if REGENERATE_FIXTURES:
        fixture_path = os.path.join(DATA_DIR, f"report_level{level}.{report_format}")
        if report_format == "html":
            with tempfile.TemporaryDirectory() as temp_dir:
                report_gen.generate_report(temp_dir)
                shutil.copy(report_gen.final_path, fixture_path)
        else:
            report_gen.generate_report(fixture_path)
        pytest.skip(f"Generated fixture for {report_format} level {level}")

    if report_format == "html":
        temp_obj = tempfile.TemporaryDirectory()
        output = temp_obj.name
    else:
        # Use a temporary file not deleted on close
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8')
        output = temp_file.name
        temp_file.close()

    report_gen.generate_report(output)

    if report_format == "html":
        generated_path = report_gen.final_path
    else:
        generated_path = output

    fixture_path = os.path.join(DATA_DIR, f"report_level{level}.{report_format}")
    with (
        open(fixture_path, "r", encoding="utf-8") as expected_fd,
        open(generated_path, "r", encoding="utf-8") as generated_fd
    ):
        if report_format == "json":
            expected = json.load(expected_fd)
            generated = json.load(generated_fd)
            assert expected == generated
        else:
            assert expected_fd.read() == generated_fd.read()

    if report_format != "html":
        os.remove(output)


def test_level_to_css_class():
    assert level_to_css_class(CRITICAL_LEVEL) == "severity-critical"
    assert level_to_css_class(HIGH_LEVEL) == "severity-high"
    assert level_to_css_class(MEDIUM_LEVEL) == "severity-medium"
    assert level_to_css_class(LOW_LEVEL) == "severity-low"
    assert level_to_css_class(INFO_LEVEL) == "severity-info"
    assert level_to_css_class(999) == ""
