import json
import lzma
from pathlib import Path
from typing import Dict, Any, Iterable
from packaging.version import Version, InvalidVersion
import re

from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL

SUPPORTED_SOFTWARES = [
    "angularjs",
    "apache",
    "drupal",
    "jetty",
    "joomla",
    "jquery",
    "nextjs",
    "nginx",
    "nodejs",
    "openssl",
    "php",
    "prestashop",
    "spip",
    "tomcat",
    "underscorejs",
    "wordpress",
]

CVE_DIRECTORY = "cves"


def is_cve_supported_software(software_name: str) -> bool:
    software_name = software_name.lower().replace(".", "").replace("-", "")
    return software_name in SUPPORTED_SOFTWARES


def compare_versions(ver_str: str, version: Version) -> bool:
    """Helper function to compare a version string with a Version object."""
    match = re.match(r"([<>]=?)([\d.]+)", ver_str)
    if not match:
        return False
    op, ver = match.groups()
    ver = Version(ver)
    if op == '<':
        return version < ver
    elif op == '<=':
        return version <= ver
    elif op == '>':
        return version > ver
    elif op == '>=':
        return version >= ver
    return False


def is_version_in_list(version: str, version_list: list) -> bool:
    try:
        version = Version(version)
    except InvalidVersion:
        return False

    for item in version_list:
        if isinstance(item, str):
            try:
                if version == Version(item):
                    return True
            except InvalidVersion:
                continue
        elif isinstance(item, list) and len(item) == 2:
            start, end = item
            start_ok = end_ok = True
            if start is not None:
                start_ok = compare_versions(start, version)
            if end is not None:
                end_ok = compare_versions(end, version)
            if start_ok and end_ok:
                return True
    return False


def cvss_score_to_wapiti_level(cvss_score: float):
    """Returns the Wapiti alert level for a CVSS score. It is based on CVSS v3 Ratings."""
    if cvss_score < 3.9:
        return LOW_LEVEL
    if cvss_score < 6.9:
        return MEDIUM_LEVEL
    if cvss_score < 8.9:
        return HIGH_LEVEL
    return CRITICAL_LEVEL


class CVEChecker:
    def __init__(self, data_dir: str):
        self._data_dir = Path(data_dir)

    def get_cves(self, software_name: str, version: str) -> Iterable[Dict[str, Any]]:
        if not is_cve_supported_software(software_name):
            return

        software_name = software_name.replace(".", "").replace("-", "")
        filepath = (self._data_dir / CVE_DIRECTORY / software_name).with_suffix(".json.xz")
        if not filepath.is_file():
            return

        # Extract the contents of the .xz file
        with lzma.open(str(filepath)) as fd:
            try:
                cve_list = json.load(fd)
                for cve in cve_list:
                    if is_version_in_list(version, cve.get("versions", [])):
                        yield cve
            except json.JSONDecodeError:
                print("malformed JSON file")


if __name__ == "__main__":
    print(is_version_in_list("13.4.19", [[None, '<13.4.20'], '13.4.20']))
