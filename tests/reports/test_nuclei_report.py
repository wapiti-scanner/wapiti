#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for Nuclei report generator"""
import os
import tempfile
from time import gmtime
import yaml

import httpx

from wapitiCore.report.nucleireportgenerator import NucleiReportGenerator
from wapitiCore.net import Request
from wapitiCore.net.sql_persister import Response


def test_nuclei_basic_vulnerability():
    """Test basic vulnerability template generation"""
    report_gen = NucleiReportGenerator()

    report_gen.set_report_info(
        "http://target.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {},
        None,
        10,
        0
    )

    request = Request("http://target.com/page?param=value", "GET")
    report_gen.add_vulnerability(
        category="Cross Site Scripting",
        level=2,
        request=request,
        parameter="param",
        info="XSS vulnerability found",
        module="xss"
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        report_gen.generate_report(temp_dir)

        # Check that a YAML file was created (exclude summary file)
        files = [f for f in os.listdir(temp_dir) if f.endswith('.yaml')]
        assert len(files) == 1
        assert files[0].endswith('.yaml')

        # Load and validate the template
        with open(os.path.join(temp_dir, files[0]), 'r') as f:
            template = yaml.safe_load(f)

        assert template['id'].startswith('wapiti-')
        assert 'info' in template
        assert template['info']['name'] == 'Cross Site Scripting'
        assert template['info']['severity'] == 'medium'
        assert template['info']['author'] == 'wapiti-scanner'
        assert 'http' in template
        assert template['http'][0]['method'] == 'GET'
        assert '{{BaseURL}}/page' in template['http'][0]['path'][0]


def test_nuclei_get_request():
    """Test GET request template generation"""
    report_gen = NucleiReportGenerator()

    report_gen.set_report_info(
        "http://target.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {},
        None,
        10,
        0
    )

    request = Request("http://target.com/test?foo=bar&baz=qux", "GET")
    report_gen.add_vulnerability(
        category="SQL Injection",
        level=3,
        request=request,
        parameter="foo",
        info="SQL injection in foo parameter",
        module="sql"
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        report_gen.generate_report(temp_dir)

        files = [f for f in os.listdir(temp_dir) if f.endswith(".yaml")]
        assert len(files) == 1

        with open(os.path.join(temp_dir, files[0]), 'r') as f:
            template = yaml.safe_load(f)

        assert template['info']['severity'] == 'high'
        assert 'foo=' in template['http'][0]['path'][0]
        assert 'baz=' in template['http'][0]['path'][0]


def test_nuclei_post_request():
    """Test POST request template with body"""
    report_gen = NucleiReportGenerator()

    report_gen.set_report_info(
        "http://target.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {},
        None,
        10,
        0
    )

    request = Request(
        "http://target.com/submit",
        "POST",
        post_params=[["username", "admin"], ["password", "pass123"]]
    )
    report_gen.add_vulnerability(
        category="Command Injection",
        level=4,
        request=request,
        parameter="username",
        info="Command injection vulnerability",
        module="exec"
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        report_gen.generate_report(temp_dir)

        files = [f for f in os.listdir(temp_dir) if f.endswith(".yaml")]
        assert len(files) == 1

        with open(os.path.join(temp_dir, files[0]), 'r') as f:
            template = yaml.safe_load(f)

        assert template['http'][0]['method'] == 'POST'
        assert template['info']['severity'] == 'critical'
        assert 'body' in template['http'][0]
        assert 'username=' in template['http'][0]['body']
        assert 'password=' in template['http'][0]['body']


def test_nuclei_multiple_vulnerabilities():
    """Test generation of multiple templates for multiple vulnerabilities"""
    report_gen = NucleiReportGenerator()

    report_gen.set_report_info(
        "http://target.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {},
        None,
        10,
        0
    )

    request1 = Request("http://target.com/page1?id=1", "GET")
    report_gen.add_vulnerability(
        category="XSS",
        level=1,
        request=request1,
        parameter="id",
        info="XSS in page1",
        module="xss"
    )

    request2 = Request("http://target.com/page2?name=test", "GET")
    report_gen.add_vulnerability(
        category="SQLi",
        level=2,
        request=request2,
        parameter="name",
        info="SQLi in page2",
        module="sql"
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        report_gen.generate_report(temp_dir)

        files = [f for f in os.listdir(temp_dir) if f.endswith(".yaml")]
        assert len(files) == 2
        assert all(f.endswith('.yaml') for f in files)


def test_nuclei_severity_mapping():
    """Test that Wapiti levels are correctly mapped to Nuclei severities"""
    report_gen = NucleiReportGenerator()

    report_gen.set_report_info(
        "http://target.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {},
        None,
        10,
        0
    )

    severity_tests = [
        (0, 'info'),
        (1, 'low'),
        (2, 'medium'),
        (3, 'high'),
        (4, 'critical')
    ]

    for level, expected_severity in severity_tests:
        request = Request(f"http://target.com/test{level}", "GET")
        report_gen.add_vulnerability(
            category=f"Test{level}",
            level=level,
            request=request,
            parameter="test",
            info=f"Test severity {level}",
            module="test"
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        report_gen.generate_report(temp_dir)

        files = sorted([f for f in os.listdir(temp_dir) if f.endswith('.yaml')])
        assert len(files) == 5

        for idx, (level, expected_severity) in enumerate(severity_tests):
            with open(os.path.join(temp_dir, files[idx]), 'r') as f:
                template = yaml.safe_load(f)
            assert template['info']['severity'] == expected_severity


def test_nuclei_anomaly():
    """Test anomaly template generation"""
    report_gen = NucleiReportGenerator()

    report_gen.set_report_info(
        "http://target.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {},
        None,
        10,
        0
    )

    request = Request("http://target.com/error", "GET")
    report_gen.add_anomaly(
        category="Internal Server Error",
        level=1,
        request=request,
        parameter="",
        info="500 error encountered",
        module="error"
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        report_gen.generate_report(temp_dir)

        files = [f for f in os.listdir(temp_dir) if f.endswith(".yaml")]
        assert len(files) == 1

        with open(os.path.join(temp_dir, files[0]), 'r') as f:
            template = yaml.safe_load(f)

        assert template['info']['name'] == 'Internal Server Error'
        assert 'matchers' in template['http'][0]


def test_nuclei_template_id_uniqueness():
    """Test that template IDs are unique even for same vulnerability type"""
    report_gen = NucleiReportGenerator()

    report_gen.set_report_info(
        "http://target.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        {},
        None,
        10,
        0
    )

    # Add two XSS vulnerabilities at different locations
    request1 = Request("http://target.com/page1?id=1", "GET")
    report_gen.add_vulnerability(
        category="XSS",
        level=1,
        request=request1,
        parameter="id",
        info="XSS in page1",
        module="xss"
    )

    request2 = Request("http://target.com/page2?name=test", "GET")
    report_gen.add_vulnerability(
        category="XSS",
        level=1,
        request=request2,
        parameter="name",
        info="XSS in page2",
        module="xss"
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        report_gen.generate_report(temp_dir)

        files = [f for f in os.listdir(temp_dir) if f.endswith(".yaml")]
        assert len(files) == 2

        template_ids = set()
        for filename in files:
            with open(os.path.join(temp_dir, filename), 'r') as f:
                template = yaml.safe_load(f)
                template_ids.add(template['id'])

        # Ensure IDs are unique
        assert len(template_ids) == 2
