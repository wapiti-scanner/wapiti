#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for abstract Vulnerability and Anomaly classes
"""
from wapitiCore.definitions.base import FindingBase, Vulnerability, Anomaly, Additional
from wapitiCore.definitions.reflected_xss import XssFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding


class TestAbstractClasses:
    """Test the abstract Vulnerability, Anomaly, and Additional classes"""

    def test_vulnerability_type(self):
        """Test that Vulnerability abstract class returns correct type"""
        assert Vulnerability.type() == "vulnerability"

    def test_anomaly_type(self):
        """Test that Anomaly abstract class returns correct type"""
        assert Anomaly.type() == "anomaly"

    def test_additional_type(self):
        """Test that Additional abstract class returns correct type"""
        assert Additional.type() == "additional"

    def test_xss_is_vulnerability(self):
        """Test that XssFinding inherits from Vulnerability"""
        assert issubclass(XssFinding, Vulnerability)
        assert issubclass(XssFinding, FindingBase)
        assert XssFinding.type() == "vulnerability"

    def test_internal_error_is_anomaly(self):
        """Test that InternalErrorFinding inherits from Anomaly"""
        assert issubclass(InternalErrorFinding, Anomaly)
        assert issubclass(InternalErrorFinding, FindingBase)
        assert InternalErrorFinding.type() == "anomaly"

    def test_fingerprint_is_additional(self):
        """Test that SoftwareNameDisclosureFinding inherits from Additional"""
        assert issubclass(SoftwareNameDisclosureFinding, Additional)
        assert issubclass(SoftwareNameDisclosureFinding, FindingBase)
        assert SoftwareNameDisclosureFinding.type() == "additional"

    def test_xss_finding_attributes(self):
        """Test that XssFinding still has all required attributes"""
        assert XssFinding.name() == "Reflected Cross Site Scripting"
        assert XssFinding.short_name() == "XSS"
        assert isinstance(XssFinding.description(), str)
        assert isinstance(XssFinding.solution(), str)
        assert isinstance(XssFinding.references(), list)
        assert isinstance(XssFinding.wstg_code(), list)

    def test_internal_error_finding_attributes(self):
        """Test that InternalErrorFinding still has all required attributes"""
        assert InternalErrorFinding.name() == "Internal Server Error"
        assert isinstance(InternalErrorFinding.description(), str)
        assert isinstance(InternalErrorFinding.solution(), str)
        assert isinstance(InternalErrorFinding.references(), list)
        assert isinstance(InternalErrorFinding.wstg_code(), list)

    def test_backward_compatibility_definitions_module(self):
        """Test that definitions module categorization still works"""
        from wapitiCore.definitions import vulnerabilities, anomalies, additionals

        # Check that categorization still works
        assert len(vulnerabilities) > 0
        assert len(anomalies) > 0
        assert len(additionals) > 0

        # Check specific findings are in correct categories
        assert XssFinding in vulnerabilities
        assert InternalErrorFinding in anomalies
        assert SoftwareNameDisclosureFinding in additionals
