from time import gmtime
import tempfile

import httpx
import json

from wapitiCore.report import GENERATORS
from wapitiCore.net.sql_persister import Response
from wapitiCore.net import Request
from wapitiCore.definitions import additionals, anomalies, vulnerabilities, flatten_references
from wapitiCore.report.jsonreportgenerator import JSONReportGenerator


def test_reports():
    for report_format, report_class in GENERATORS.items():
        report_gen = report_class()

        report_gen.set_report_info(
            "http://perdu.com",
            "folder",
            gmtime(),
            "WAPITI_VERSION",
            {
                "method": "post",
                "url": "http://testphp.vulnweb.com/login.php",
                "logged_in": True,
                "form": {
                    "login_field": "uname",
                    "password_field": "pass"
                }
            },
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

        if report_format == "html":
            temp_obj = tempfile.TemporaryDirectory()

        else:
            temp_obj = tempfile.NamedTemporaryFile(delete=False)

        output = temp_obj.name

        print("Using report type '{}'".format(report_format))
        request = Request("http://perdu.com/riri?foo=bar")
        report_gen.add_vulnerability(
            category="Reflected Cross Site Scripting",
            level=1,
            request=request,
            parameter="foo",
            info="This is dope",
            module="xss"
        )

        request = Request("http://perdu.com/fifi?foo=bar")
        report_gen.add_anomaly(
            category="Internal Server Error",
            level=2,
            request=request,
            parameter="foo",
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

        report_gen.generate_report(output)

        if report_format == "html":
            output = report_gen.final_path

        with open(output) as fd:
            report = fd.read()
            assert "riri" in report
            assert "fifi" in report
            assert "loulou" in report
            assert "http://testphp.vulnweb.com/login.php" in report
            assert "uname" in report
            assert "pass" in report

            # the csv report only contains vulnerabilities without the info section
            if report_format != "csv":
                assert "123456" in report


def test_json_detail_report_full():
    report_gen = JSONReportGenerator()

    report_gen.set_report_info(
        "http://perdu.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {
            "method": "post",
            "url": "http://testphp.vulnweb.com/login.php",
            "logged_in": True,
            "form": {
                "login_field": "uname",
                "password_field": "pass"
            }
        },
        [
            "foo",
            "bar"
        ],
        1,
        2
    )

    request = Request("http://perdu.com/", "GET", [["foo", "bar"]])
    response = Response(
        httpx.Response(
            status_code=200,
            headers=httpx.Headers([["abc", "123"]]),
            content=b"OK"
        ),
        url="http://perdu.com/"
    )

    report_gen.add_vulnerability("foobar", "category", request=request, response=response)

    temp_obj = tempfile.NamedTemporaryFile(delete=False)

    output = temp_obj.name

    report_gen.generate_report(output)

    with open(output) as fd:
        report_obj = json.loads(fd.read())
        assert report_obj

        assert report_obj["infos"]["detailed_report_level"] == 2
        assert report_obj["infos"]["crawled_pages"] == ["foo", "bar"]
        assert report_obj["infos"]["crawled_pages_nbr"] == 1

        assert len(report_obj["vulnerabilities"]["category"]) == 1
        assert report_obj["vulnerabilities"]["category"][0]
        vuln = report_obj["vulnerabilities"]["category"][0]

        assert vuln["method"] == "GET"
        assert vuln["module"] == "foobar"
        assert vuln["detail"]["response"]["status_code"] == 200
        assert ["abc", "123"] in vuln["detail"]["response"]["headers"]


def test_json_detail_report_light():
    report_gen = JSONReportGenerator()

    report_gen.set_report_info(
        "http://perdu.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {
            "method": "post",
            "url": "http://testphp.vulnweb.com/login.php",
            "logged_in": True,
            "form": {
                "login_field": "uname",
                "password_field": "pass"
            }
        },
        [
            "foo",
            "bar"
        ],
        1,
        1
    )

    request = Request("http://perdu.com/", "GET", [["foo", "bar"]])
    response = Response(
        httpx.Response(
            status_code=200,
            headers=httpx.Headers([["abc", "123"]]),
            content=b"OK"
        ),
        url="http://perdu.com/"
    )

    report_gen.add_vulnerability("foobar", "category", request=request, response=response)

    temp_obj = tempfile.NamedTemporaryFile(delete=False)

    output = temp_obj.name

    report_gen.generate_report(output)

    with open(output) as fd:
        report_obj = json.loads(fd.read())
        assert report_obj

        assert report_obj["infos"]["detailed_report_level"] == 1
        assert report_obj["infos"]["crawled_pages"] == ["foo", "bar"]
        assert report_obj["infos"]["crawled_pages_nbr"] == 1
        for page in report_obj["infos"]["crawled_pages"]:
            assert "response" not in page

        assert len(report_obj["vulnerabilities"]["category"]) == 1
        assert report_obj["vulnerabilities"]["category"][0]
        vuln = report_obj["vulnerabilities"]["category"][0]

        assert vuln["method"] == "GET"
        assert vuln["module"] == "foobar"


def test_json_detail_report_none():
    report_gen = JSONReportGenerator()

    report_gen.set_report_info(
        "http://perdu.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {
            "method": "post",
            "url": "http://testphp.vulnweb.com/login.php",
            "logged_in": True,
            "form": {
                "login_field": "uname",
                "password_field": "pass"
            }
        },
        [
            "foo",
            "bar"
        ],
        1,
        0
    )

    request = Request("http://perdu.com/", "GET", [["foo", "bar"]])
    response = Response(
        httpx.Response(
            status_code=200,
            headers=httpx.Headers([["abc", "123"]]),
            content=b"OK"
        ),
        url="http://perdu.com/"
    )

    report_gen.add_vulnerability("foobar", "category", request=request, response=response)

    temp_obj = tempfile.NamedTemporaryFile(delete=False)

    output = temp_obj.name

    report_gen.generate_report(output)

    with open(output) as fd:
        report_obj = json.loads(fd.read())
        assert report_obj

        assert report_obj["infos"]["detailed_report_level"] == 0
        assert report_obj["infos"]["crawled_pages_nbr"] == 1
        assert "crawled_pages" not in report_obj["infos"]

        assert len(report_obj["vulnerabilities"]["category"]) == 1
        assert report_obj["vulnerabilities"]["category"][0]
        vuln = report_obj["vulnerabilities"]["category"][0]

        assert vuln["method"] == "GET"
        assert vuln["module"] == "foobar"
