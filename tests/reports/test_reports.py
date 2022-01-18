from time import gmtime
import tempfile

import httpx
import json

from wapitiCore.report import GENERATORS
from wapitiCore.language.language import _
from wapitiCore.net.sql_persister import Response
from wapitiCore.net.web import Request
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
            False
        )

        for vul in vulnerabilities:
            report_gen.add_vulnerability_type(
                vul.NAME,
                vul.DESCRIPTION,
                vul.SOLUTION,
                flatten_references(vul.REFERENCES)
            )

        for anomaly in anomalies:
            report_gen.add_anomaly_type(
                anomaly.NAME,
                anomaly.DESCRIPTION,
                anomaly.SOLUTION,
                flatten_references(anomaly.REFERENCES)
            )

        for additional in additionals:
            report_gen.add_additional_type(
                additional.NAME,
                additional.DESCRIPTION,
                additional.SOLUTION,
                flatten_references(additional.REFERENCES)
            )

        if report_format == "html":
            temp_obj = tempfile.TemporaryDirectory()

        else:
            temp_obj = tempfile.NamedTemporaryFile(delete=False)

        output = temp_obj.name

        print("Using report type '{}'".format(report_format))
        request = Request("http://perdu.com/riri?foo=bar")
        report_gen.add_vulnerability(
            category=_("Reflected Cross Site Scripting"),
            level=1,
            request=request,
            parameter="foo",
            info="This is dope",
            module="xss"
        )

        request = Request("http://perdu.com/fifi?foo=bar")
        report_gen.add_anomaly(
            category=_("Internal Server Error"),
            level=2,
            request=request,
            parameter="foo",
            info="This is the way",
            module="xss"
        )

        request = Request("http://perdu.com/?foo=bar")
        report_gen.add_additional(
            category=_("Fingerprint web technology"),
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

def test_json_detail_report():
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
            True
        )

        request = Request("http://perdu.com/", "GET", [["foo", "bar"]])
        response = Response(status_code=200, headers=httpx.Headers([["abc", "123"]]), body="OK")

        report_gen.add_vulnerability("foobar", "category", request=request, response=response)

        temp_obj = tempfile.NamedTemporaryFile(delete=False)

        output = temp_obj.name

        report_gen.generate_report(output)

        with open(output) as fd:
            report = fd.read()

            report_obj = None
            try:
                report_obj = json.loads(report)
            except:
                assert False

            assert report_obj

            assert report_obj["infos"]["detailed_report"] is True
            assert report_obj["infos"]["crawled_pages"] == ["foo", "bar"]
            assert report_obj["infos"]["crawled_pages_nbr"] == 1

            assert len(report_obj["vulnerabilities"]["category"]) == 1
            assert report_obj["vulnerabilities"]["category"][0]
            vuln = report_obj["vulnerabilities"]["category"][0]

            assert vuln["method"] == "GET"
            assert vuln["module"] == "foobar"
            assert vuln["detail"]["request"]["url"] == "http://perdu.com/?foo=bar"
            assert vuln["detail"]["request"]["method"] == "GET"
            assert vuln["detail"]["request"]["query"] == [["foo", "bar"]]
            assert vuln["detail"]["response"]["status_code"] == 200
            assert vuln["detail"]["response"]["headers"] == [["abc", "123"]]
