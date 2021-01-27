import os
import sys
from time import gmtime
import tempfile

from wapitiCore.file.reportgeneratorsxmlparser import ReportGeneratorsXMLParser
from wapitiCore.file.vulnerabilityxmlparser import VulnerabilityXMLParser
from wapitiCore.file.anomalyxmlparser import AnomalyXMLParser
from wapitiCore.file.additionalxmlparser import AdditionalXMLParser
from wapitiCore.language.language import _
from wapitiCore.net.web import Request


def test_reports():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    xml_rep_gen_parser = ReportGeneratorsXMLParser()
    xml_rep_gen_parser.parse(os.path.join(base_dir, "config", "reports", "generators.xml"))

    for rep_gen_info in xml_rep_gen_parser.get_report_generators():
        report_gen = rep_gen_info.create_instance()

        report_gen.set_report_info(
            "http://perdu.com",
            "folder",
            gmtime(),
            "WAPITI_VERSION"
        )

        vuln_xml_parser = VulnerabilityXMLParser()
        vuln_xml_parser.parse(os.path.join(base_dir, "config", "vulnerabilities", "vulnerabilities.xml"))
        for vul in vuln_xml_parser.get_vulnerabilities():
            report_gen.add_vulnerability_type(
                _(vul.get_name()),
                _(vul.get_description()),
                _(vul.get_solution()),
                vul.get_references())

        anom_xml_parser = AnomalyXMLParser()
        anom_xml_parser.parse(os.path.join(base_dir, "config", "vulnerabilities", "anomalies.xml"))
        for anomaly in anom_xml_parser.get_anomalies():
            report_gen.add_anomaly_type(
                _(anomaly.get_name()),
                (anomaly.get_description()),
                _(anomaly.get_solution()),
                anomaly.get_references()
            )

        addition_xml_parser = AdditionalXMLParser()
        addition_xml_parser.parse(os.path.join(base_dir, "config", "vulnerabilities", "additionals.xml"))
        for additional in addition_xml_parser.get_additionals():
            report_gen.add_additional_type(
                _(additional.get_name()),
                (additional.get_description()),
                _(additional.get_solution()),
                additional.get_references()
            )

        if rep_gen_info.name == "html":
            temp_obj = tempfile.TemporaryDirectory()

        else:
            temp_obj = tempfile.NamedTemporaryFile(delete=False)

        output = temp_obj.name

        print("Using report type '{}'".format(rep_gen_info.name))
        request = Request("http://perdu.com/riri?foo=bar")
        report_gen.add_vulnerability(
            category=_("Cross Site Scripting"),
            level=1,
            request=request,
            parameter="foo",
            info="This is dope"
        )

        request = Request("http://perdu.com/fifi?foo=bar")
        report_gen.add_anomaly(
            category=_("Internal Server Error"),
            level=2,
            request=request,
            parameter="foo",
            info="This is the way"
        )

        request = Request("http://perdu.com/?foo=bar")
        report_gen.add_additional(
            category=_("Fingerprint web technology"),
            level=3,
            request=request,
            parameter="foo",
            info="loulou"
        )

        report_gen.generate_report(output)

        if rep_gen_info.name == "html":
            output = report_gen.final_path
        elif rep_gen_info.name == "openvas":
            # Fix it later
            continue

        with open(output) as fd:
            report = fd.read()
            assert "riri" in report
            assert "fifi" in report
            assert "loulou" in report
