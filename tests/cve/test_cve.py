import json
import lzma
import os
import tempfile

import pytest

from wapitiCore.attack.cve.checker import (
    is_version_in_list,
    cvss_score_to_wapiti_level,
    is_cve_supported_software,
    CVEChecker,
)
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL


def test_is_cve_supported_software():
    assert is_cve_supported_software("Next.JS") is True
    assert is_cve_supported_software("angular.js") is True
    assert is_cve_supported_software("tomahawkjs") is False
    assert is_cve_supported_software("Apache") is True
    assert is_cve_supported_software("underscore-js") is True


def test_cvss_score_to_wapiti_level():
    assert cvss_score_to_wapiti_level(0) == LOW_LEVEL
    assert cvss_score_to_wapiti_level(4) == MEDIUM_LEVEL
    assert cvss_score_to_wapiti_level(8) == HIGH_LEVEL
    assert cvss_score_to_wapiti_level(9) == CRITICAL_LEVEL


def test_is_version_in_list():
    version_list = [
        [None, "<=1.6.2"],
        "1.6",
        "1.6.1",
        [">2.5", "<3.0"],
        [">=3.0.1", "<=3.1.4"]
    ]

    # Test exact matches
    assert is_version_in_list("1.6", version_list) is True  # Exact match
    assert is_version_in_list("1.6.1", version_list) is True  # Exact match

    # Test versions within range
    assert is_version_in_list("1.5", version_list) is True  # True, <= 1.6.2
    assert is_version_in_list("1.6.2", version_list) is True  # True, <= 1.6.2
    assert is_version_in_list("2.6", version_list) is True  # True, > 2.5 and < 3.0
    assert is_version_in_list("3.0.1", version_list) is True  # True, >= 3.0.1
    assert is_version_in_list("3.0a", version_list) is True  # True, alpha version is before the stable one
    assert is_version_in_list("3.0-rc1", version_list) is True  # True, RC version is before the stable one
    assert is_version_in_list("3.1.4", version_list) is True  # True, <= 3.1.4

    # Test versions outside of range
    assert is_version_in_list("1.6.3", version_list) is False  # False
    assert is_version_in_list("2.5", version_list) is False  # False, exactly 2.5
    assert is_version_in_list("3.0", version_list) is False  # False, < 3.0.1
    assert is_version_in_list("3.2", version_list) is False  # False, > 3.1.4

    # Test edge cases and invalid inputs
    assert is_version_in_list("invalid.version", version_list) is False  # False, invalid version
    assert is_version_in_list("", version_list) is False  # False, empty string


def test_get_cves():
    with tempfile.TemporaryDirectory() as temp_dir:
        os.mkdir(os.path.join(temp_dir, "cves"))
        checker = CVEChecker(temp_dir)
        # Software not in supported list
        assert list(checker.get_cves("nosuchsoftware", "93.6")) == []
        # Missing CVE file
        assert list(checker.get_cves("apache", "93.6")) == []
        # Corrupted file
        with lzma.open(os.path.join(temp_dir, "cves", "apache.json.xz"), "wb") as fd:
            fd.write(b"Ceci n'est pas du JSON")
        assert list(checker.get_cves("apache", "1337")) == []
        # Valid CVE data
        cve_data = [
            {
                "id": "CVE-2043-31337",
                "description": "Back to the future",
                "cvss3.1": 8.6,
                "versions": [
                    [
                        ">=93.6",
                        None
                    ]
                ]
            },
            {
                "id": "CVE-2023-43622",
                "description": "This is bad",
                "cvss3.1": 7.5,
                "versions": [
                    [
                        ">=2.4.55",
                        "<2.4.58"
                    ]
                ]
            },
            {
                "id": "CVE-2023-45802",
                "description": "This is bad too",
                "cvss3.1": 5.9,
                "versions": [
                    [
                        None,
                        "<2.4.58"
                    ]
                ]
            },
        ]
        with lzma.open(os.path.join(temp_dir, "cves", "apache.json.xz"), "wb") as fd:
            fd.write(json.dumps(cve_data).encode())
        assert list(checker.get_cves("apache", "2.4.57")) == cve_data[1:]
