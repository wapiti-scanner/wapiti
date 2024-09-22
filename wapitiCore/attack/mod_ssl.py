# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2023 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# https://badssl.com/ can help to test the module
import fnmatch
import os
import socket
import ssl
import subprocess
from datetime import datetime, timezone
import json
import asyncio
from os.path import join as path_join, exists
from typing import List, Tuple, Optional, AsyncIterator
from collections import defaultdict
import xml.etree.ElementTree as ET
import re
import tempfile
import shutil

from httpx import RequestError
import humanize
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request, Response
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, INFO_LEVEL
from wapitiCore.main.log import log_red, log_blue, log_green, log_orange, logging
from wapitiCore.definitions.ssl import SslInformationFinding, SslVulnerabilityFinding


def sslscan_level_to_color(security_level: str) -> str:
    if security_level == "weak":
        return "RED"
    if security_level == "acceptable":
        return "ORANGE"
    # Secure / Recommended / Unknown
    return "GREEN"


def sslscan_level_to_wapiti_level(security_level: str) -> str:
    if security_level == "weak":
        return CRITICAL_LEVEL
    if security_level == "acceptable":
        return MEDIUM_LEVEL
    # Secure / Recommended / Unknown
    return INFO_LEVEL


def check_ev_certificate(cert: x509.Certificate) -> bool:
    """
    Checks if the certificate is an EV (Extended Validation) certificate.
    """
    for attribute in cert.subject:
        if attribute.oid == NameOID.ORGANIZATION_NAME:
            return True
    return False


def get_certificate(hostname: str, port: int = 443) -> x509.Certificate:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.connect((hostname, port))
    cert_bin = conn.getpeercert(True)
    return x509.load_der_x509_certificate(cert_bin, default_backend())


def check_ocsp_must_staple(cert: x509.Certificate) -> bool:
    try:
        extension = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24"))
        return extension is not None
    except x509.ExtensionNotFound:
        return False


def extract_altnames(altnames: str) -> List[str]:
    return [name.split(":", 1)[1] for name in re.split(r',\s*', altnames) if ":" in name]


def match_address(target: str, subject: str, alt_names: List[str]) -> bool:
    # Check against subject
    if fnmatch.fnmatch(target, subject):
        return True

    # Check against each alternative name
    for alt_name in alt_names:
        if fnmatch.fnmatch(target, alt_name):
            return True

    return False


def sslscan_date_to_utc(date_str: str) -> datetime:
    dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
    return dt.replace(tzinfo=timezone.utc)


async def process_cert_info(xml_file: str) -> AsyncIterator[Tuple[int, str]]:
    tree = ET.parse(xml_file)
    root = tree.getroot()

    target = root.find(".//ssltest").get("sniname")

    # Extract certificate information
    for cert in root.findall(".//certificate"):
        subject = cert.find("subject").text
        message = f"Certificate subject: {subject}"
        log_blue(message)
        yield INFO_LEVEL, message

        alt_names_tag = cert.find("altnames")
        if alt_names_tag is not None and alt_names_tag.text.strip():
            alt_names = extract_altnames(alt_names_tag.text)
            message = f"Alt. names: {', '.join(alt_names)}"
            log_blue(message)
            yield INFO_LEVEL, message
        else:
            alt_names = []

        message = f"Issuer: {cert.find('issuer').text}"
        log_blue(message)
        yield INFO_LEVEL, message

        if not match_address(target, subject, alt_names):
            message = "Requested hostname doesn't match those in the certificate"
            log_red(message)
            yield CRITICAL_LEVEL, message

        key = cert.find("pk")
        message = f"Key: {key.get('type')} {key.get('bits')} bits"
        log_blue(message)
        yield INFO_LEVEL, message

        message = f"Signature Algorithm: {cert.find('signature-algorithm').text}"
        log_blue(message)
        yield INFO_LEVEL, message

        if cert.find("self-signed").text == "true":
            message = (
                "Self-signed certificate detected: The certificate is not signed by a trusted Certificate Authority"
            )
            log_orange(message)
            yield MEDIUM_LEVEL, message

        not_valid_after = sslscan_date_to_utc(cert.find("not-valid-after").text)
        utcnow = datetime.utcnow().replace(tzinfo=timezone.utc)
        if not_valid_after > utcnow:
            message = "Certificate expires in " + humanize.precisedelta(not_valid_after - utcnow)
            log_green(message)
            yield INFO_LEVEL, message
        else:
            message = f"Certificate has expired at {not_valid_after}"
            log_red(message)
            yield CRITICAL_LEVEL, message


async def process_cipher_suites2(xml_file: str) -> AsyncIterator[Tuple[int, str]]:
    tree = ET.parse(xml_file)
    root = tree.getroot()

    protocol_versions = set()
    # Enumerate supported protocols first
    for cipher in root.findall(".//cipher"):
        protocol_versions.add(cipher.get("sslversion"))

    # For each protocol, group ciphers by severity then raise a warning per severity
    for protocol in protocol_versions:
        log_blue(f"\nAccepted cipher suites for {protocol}:")
        group_by_severity = defaultdict(list)
        for cipher in root.findall(f".//cipher[@sslversion='{protocol}']"):
            name = cipher.get("cipher")
            group_by_severity[cipher.get("strength")].append(name)

            logging.log(
                sslscan_level_to_color(cipher.get("strength")),
                f"* {name} {cipher.get('strength')}"
            )

        for security_level, ciphers in group_by_severity.items():
            # We are using sslscan level in the report to be consistent with output from the tool
            message = f"The following ciphers are {security_level.lower()} for {protocol}: {', '.join(sorted(ciphers))}"
            yield sslscan_level_to_wapiti_level(security_level), message


async def process_bad_protocols(xml_file: str) -> AsyncIterator[Tuple[int, str]]:
    # https://blog.mozilla.org/security/2014/10/14/the-poodle-attack-and-the-end-of-ssl-3-0/
    # https://blog.qualys.com/product-tech/2018/11/19/grade-change-for-tls-1-0-and-tls-1-1-protocols
    known_bad_protocols = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

    tree = ET.parse(xml_file)
    root = tree.getroot()
    bad_protocols = set()
    for protocol in root.findall(".//protocol[@enabled='1']"):
        name = f"{protocol.get('type').upper()}v{protocol.get('version')}"
        if name in known_bad_protocols:
            bad_protocols.add(name)

    if bad_protocols:
        message = "The following protocols are deprecated and/or insecure and should be deactivated: " + \
                  ", ".join(sorted(bad_protocols))
        log_red(message)
        yield CRITICAL_LEVEL, message


def process_error(xml_file: str) -> str:
    if not exists(xml_file):
        return "sslscan did not generate the expected XML file"

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        error = root.find(".//error")
        if error:
            return error.text
        return ""
    except (ET.ParseError, FileNotFoundError, OSError, IOError) as exception:
        return "Error parsing sslscan XML output:" + str(exception)


async def process_vulnerabilities(xml_file: str) -> AsyncIterator[Tuple[int, str]]:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    vulnerable_protocols = set()
    for protocol in root.findall(".//heartbleed[@vulnerable='1']"):
        vulnerable_protocols.add(protocol.get("sslversion"))

    if vulnerable_protocols:
        message = f"Server is vulnerable to Heartbleed attack via {', '.join(vulnerable_protocols)}"
        log_red(message)
        yield CRITICAL_LEVEL, message

    if root.find(".//compression[@supported='1']"):
        message = "Server is vulnerable to CRIME attack (compression is supported)"
        log_red(message)
        yield CRITICAL_LEVEL, message

    if root.find(".//fallback[@supported='1']"):
        message = "Server is vulnerable to OpenSSL CCS (CVE-2014-0224)"
        log_red(message)
        yield CRITICAL_LEVEL, message

    renegotiation = root.find(".//renegotiation")
    if int(renegotiation.get("supported")) == 0:
        message = "Server doesn't support secure renegotiations"
        log_orange(message)
        yield MEDIUM_LEVEL, message
    elif int(renegotiation.get("secure")) == 0:
        message = "Server honors client-initiated renegotiations (vulnerable to DoS attacks)"
        log_red(message)
        yield HIGH_LEVEL, message


def process_cipher_suites(results, version: str):
    accepted_ciphers = results.accepted_cipher_suites
    if not accepted_ciphers:
        return

    with open(path_join(Attack.DATA_DIR, "cipher_suites.json"), encoding="utf-8") as fd:
        ciphers = json.load(fd)

    group_by_severity = defaultdict(list)
    log_blue(f"\nAccepted cipher suites for {version}:")
    for accepted_cipher_suite in accepted_ciphers:
        try:
            security_level = ciphers[accepted_cipher_suite.cipher_suite.name]["security"].title()
        except KeyError:
            # Cipher that isn't in our database... certainly fresh and secure but let's ignore it
            continue

        logging.log(
            sslscan_level_to_color(security_level),
            f"* {accepted_cipher_suite.cipher_suite.name} "
            f"{accepted_cipher_suite.cipher_suite.openssl_name} "
            # f"{accepted_cipher_suite.cipher_suite.key_size} "
            f"{security_level}"
        )
        # Group ciphers using severity to reduce entries in the report
        group_by_severity[security_level].append(accepted_cipher_suite.cipher_suite.openssl_name)

    for security_level, ciphers in group_by_severity.items():
        message = f"The following ciphers are {security_level.lower()} for {version}: {', '.join(sorted(ciphers))}"
        yield sslscan_level_to_wapiti_level(security_level), message


class ModuleSsl(Attack):
    """Evaluate the security of SSL/TLS certificate configuration."""
    name = "ssl"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)
        # list to ensure only one occurrence per (vulnerable url/post_keys) tuple
        self.tested_targets = set()
        self.has_sslcan = None

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.has_sslcan is None:
            if shutil.which("sslscan"):
                self.has_sslcan = True
            else:
                log_red("sslscan is not installed or not found in PATH, module will be skipped")
                self.has_sslcan = False

        if not self.has_sslcan:
            return False

        if request.scheme != "https":
            return False

        if response.is_directory_redirection:
            return False

        if request.hostname in self.tested_targets:
            return False

        self.tested_targets.add(request.hostname)
        return True

    async def attack(self, request: Request, response: Optional[Response] = None):
        loop = asyncio.get_running_loop()
        scan_results = await loop.run_in_executor(None, self.process_sslscan, request.hostname, request.port)

        async for level, message in scan_results:
            finding = SslInformationFinding if level == INFO_LEVEL else SslVulnerabilityFinding
            await self.add_payload(
                level=level,
                finding_class=finding,
                request=request,
                info=message
            )

    async def check_hsts(self, hostname: str, port: int) -> int:
        """
        Checks if the given hostname supports HSTS.
        """
        try:
            response = await self.crawler.async_send(Request(f'https://{hostname}:{port}'))
        except RequestError:
            return -1
        return int('strict-transport-security' in response.headers)

    async def check_certificate_transparency(self, cert: x509.Certificate) -> int:
        """
        Returns 1 if at least one CST exists, 0 otherwise. -1 if an error occurs.
        """
        serial_number = cert.serial_number
        try:
            # crt.sh should be able to provide JSON output, but currently it doesn't work
            # moved to that simple check instead
            response = await self.crawler.async_send(Request(f'https://crt.sh/?q={serial_number}'))
            if response.status != 200:
                return -1
            if "None found" in response.content:
                return 0
            return 1
        except RequestError:
            return -1

    async def process_cert_features(self, target: str, port: int) -> AsyncIterator[Tuple[int, str]]:
        cert = get_certificate(target, port)

        if not check_ev_certificate(cert):
            message = "Certificate doesn't use Extended Validation"
            log_orange(message)
            yield MEDIUM_LEVEL, message

        # https://en.wikipedia.org/wiki/OCSP_stapling
        if not check_ocsp_must_staple(cert):
            message = "OCSP Must-Staple extension is missing"
            log_orange(message)
            yield MEDIUM_LEVEL, message

        has_sct = await self.check_certificate_transparency(cert)
        if has_sct > 0:
            message = "Certificate transparency: Yes"
            log_green(message)
            yield INFO_LEVEL, message
        elif has_sct == 0:
            message = "Certificate transparency: No"
            log_red(message)
            yield HIGH_LEVEL, message

        if await self.check_hsts(target, port) == 0:
            message = "Strict Transport Security (HSTS) is not set"
            log_red(message)
            yield HIGH_LEVEL, message

    async def process_sslscan(self, hostname: str, port: int) -> AsyncIterator[Tuple[int, str]]:
        with tempfile.NamedTemporaryFile("r", suffix=".xml", delete=False) as temp_file:
            sslscan_command = ["sslscan", "--iana-names", "--ocsp", f"--xml={temp_file.name}", f"{hostname}:{port}"]
            try:
                subprocess.run(sslscan_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError as exception:
                log_red("Error running sslscan: " + str(exception))
                return

            error = process_error(temp_file.name)
            if error:
                log_red(error)
            else:
                async for info in process_cert_info(temp_file.name):
                    yield info
                try:
                    async for info in self.process_cert_features(hostname, port):
                        yield info
                except ssl.SSLError:
                    log_red("Could not get extra information about the certificate due to SSL errors")
                except (socket.timeout, socket.gaierror):
                    log_red("Could not get extra information about the certificate due to network errors")
                async for info in process_vulnerabilities(temp_file.name):
                    yield info
                async for info in process_cipher_suites2(temp_file.name):
                    yield info
                async for info in process_bad_protocols(temp_file.name):
                    yield info
                os.unlink(temp_file.name)
