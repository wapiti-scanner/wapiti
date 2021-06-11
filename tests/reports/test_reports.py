from time import gmtime
import tempfile

from wapitiCore.report import GENERATORS
from wapitiCore.language.language import _
from wapitiCore.net.web import Request
from wapitiCore.definitions import additionals, anomalies, vulnerabilities, flatten_references


def test_reports():
    for report_format, report_class in GENERATORS.items():
        report_gen = report_class()

        report_gen.set_report_info(
            "http://perdu.com",
            "folder",
            gmtime(),
            "WAPITI_VERSION"
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
            category=_("Cross Site Scripting"),
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
