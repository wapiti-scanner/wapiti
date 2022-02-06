# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2022 Nicolas Surribas
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
from datetime import datetime
import json
import asyncio
from os.path import join as path_join
from typing import List, Tuple
from collections import defaultdict

import humanize
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography import x509
from sslyze.plugins.certificate_info._certificate_utils import get_common_names, extract_dns_subject_alternative_names
from sslyze.plugins.robot.implementation import RobotScanResultEnum
from sslyze import ServerNetworkLocation, ServerNetworkConfiguration, ScanCommand, Scanner, ServerScanRequest, \
    ScanCommandAttemptStatusEnum
from sslyze.errors import ServerHostnameCouldNotBeResolved

from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import _, CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, INFO_LEVEL
from wapitiCore.main.log import log_red, log_blue, log_green, log_orange, logging
from wapitiCore.definitions.ssl import NAME, WSTG_CODE


def get_common_name(name_field: x509.Name) -> str:
    try:
        return get_common_names(name_field)[0]
    except IndexError:
        return name_field.rfc4514_string()


def cipher_level_to_color(security_level: str) -> str:
    if security_level == "Insecure":
        return "RED"
    if security_level == "Weak":
        return "ORANGE"
    # Secure / Recommanded / Unknown
    return "GREEN"


def cipher_level_to_wapiti_level(security_level: str) -> str:
    if security_level == "Insecure":
        return CRITICAL_LEVEL
    if security_level == "Weak":
        return HIGH_LEVEL
    # Secure / Recommended / Unknown
    return INFO_LEVEL


def process_certificate_info(certinfo_result):
    for cert_deployment in certinfo_result.certificate_deployments:

        leaf_certificate = cert_deployment.received_certificate_chain[0]
        message = _("Certificate subject: {0}").format(get_common_name(leaf_certificate.subject))
        log_blue(message)
        yield INFO_LEVEL, message

        message = _("Alt. names: {0}").format(extract_dns_subject_alternative_names(leaf_certificate))
        log_blue(message)
        yield INFO_LEVEL, message

        message = _("Issuer: {0}").format(get_common_name(leaf_certificate.issuer))
        log_blue(message)
        yield INFO_LEVEL, message

        if not cert_deployment.leaf_certificate_subject_matches_hostname:
            message = _("Requested hostname doesn't match those in the certificate")
            log_red(message)
            yield CRITICAL_LEVEL, message

        if not cert_deployment.received_chain_has_valid_order:
            message = _("Certificate chain is in invalid order")
            log_orange(message)
            yield MEDIUM_LEVEL, message

        public_key = leaf_certificate.public_key()

        if isinstance(public_key, EllipticCurvePublicKey):
            key_size = public_key.curve.key_size
        else:
            key_size = public_key.key_size

        if public_key.__class__.__name__ == "_RSAPublicKey":
            algorithm = "RSA"
        elif public_key.__class__.__name__ == "_EllipticCurvePublicKey":
            algorithm = "ECC"
        else:
            algorithm = public_key.__class__.__name__

        message = _("Key: {0} {1} bits").format(algorithm, key_size)
        log_blue(message)
        yield INFO_LEVEL, message

        message = _("Signature Algorithm: {0}").format(leaf_certificate.signature_hash_algorithm.name)
        log_blue(message)
        yield INFO_LEVEL, message

        # print(f"Valid from {leaf_certificate.not_valid_before} to {leaf_certificate.not_valid_after}")
        if leaf_certificate.not_valid_after > datetime.utcnow():
            # We should add a method for humanize inside our language package
            # _t = humanize.i18n.activate("fr_FR")
            message = _("Certificate expires in ") + \
                      humanize.precisedelta(leaf_certificate.not_valid_after - datetime.utcnow())
            log_green(message)
            yield INFO_LEVEL, message
        else:
            message = _("Certificate has expired at") + f" {leaf_certificate.not_valid_after}"
            log_red(message)
            yield CRITICAL_LEVEL, message

        if not cert_deployment.leaf_certificate_is_ev:
            message = _("Certificate doesn't use Extended Validation")
            log_orange(message)
            yield MEDIUM_LEVEL, message

        # https://en.wikipedia.org/wiki/OCSP_stapling
        if not cert_deployment.leaf_certificate_has_must_staple_extension:
            message = _("OCSP Must-Staple extension is missing")
            log_orange(message)
            yield MEDIUM_LEVEL, message

        if cert_deployment.leaf_certificate_signed_certificate_timestamps_count is None:
            message = _("Certificate transparency:") + " " + _("Unknown (Your OpenSSL version is not recent enough)")
            log_orange(message)
            yield MEDIUM_LEVEL, message
        elif cert_deployment.leaf_certificate_signed_certificate_timestamps_count:
            message = _("Certificate transparency:") + " " + _("Yes") + \
                      f" ({cert_deployment.leaf_certificate_signed_certificate_timestamps_count} SCT)"
            log_green(message)
            yield INFO_LEVEL, message
        else:
            message = _("Certificate transparency:") + " " + _("No")
            log_red(message)
            yield HIGH_LEVEL, message

        if cert_deployment.verified_chain_has_sha1_signature:
            message = _("One of the certificate in the chain is signed using SHA-1")
            log_red(message)
            yield HIGH_LEVEL, message

        for validation_result in cert_deployment.path_validation_results:
            if not validation_result.was_validation_successful:
                message = _("Certificate is invalid for {} trust store: {}").format(
                        validation_result.trust_store.name,
                        validation_result.openssl_error_string
                    )
                log_red(message)
                yield CRITICAL_LEVEL, message

        # Currently we stop at the first certificate of the server, maybe improve later
        # Right now several certificates generates too much confusion in report
        break


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
            cipher_level_to_color(security_level),
            f"* {accepted_cipher_suite.cipher_suite.name} "
            f"{accepted_cipher_suite.cipher_suite.openssl_name} "
            # f"{accepted_cipher_suite.cipher_suite.key_size} "
            f"{security_level}"
        )
        # Group ciphers using severity to reduce entries in the report
        group_by_severity[security_level].append(accepted_cipher_suite.cipher_suite.openssl_name)

    for security_level, ciphers in group_by_severity.items():
        message = _("The following ciphers are {0} for {1}: {2}").format(
            _(security_level).lower(),
            version,
            ", ".join(sorted(ciphers))
        )
        yield cipher_level_to_wapiti_level(security_level), message


def analyze(hostname: str, port: int) -> List[Tuple[int, str]]:
    results = []
    # Define the server that you want to scan
    try:
        server_location = ServerNetworkLocation(hostname, port)
    except ServerHostnameCouldNotBeResolved:
        log_red(_("Could not resolve {0}"), hostname)
        return results

    # Then queue some scan commands for the server
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        server_location=server_location,
        scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.ROBOT,
            ScanCommand.HEARTBLEED,
            ScanCommand.TLS_COMPRESSION,
            ScanCommand.TLS_FALLBACK_SCSV,
            ScanCommand.TLS_1_3_EARLY_DATA,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.SESSION_RENEGOTIATION,
            ScanCommand.HTTP_HEADERS
        },
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=server_location.hostname,
            network_timeout=5,
            network_max_retries=2
        )
    )
    scanner.queue_scans([server_scan_req])

    # TLS 1.2 / 1.3 results
    good_protocols = {
        ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS v1.2",
        ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS v1.3"
    }

    # https://blog.mozilla.org/security/2014/10/14/the-poodle-attack-and-the-end-of-ssl-3-0/
    # https://blog.qualys.com/product-tech/2018/11/19/grade-change-for-tls-1-0-and-tls-1-1-protocols
    bad_protocols = {
        ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL v2",
        ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL v3",
        ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS v1.0",
        ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS v1.1"
    }

    # Then retrieve the results
    for result in scanner.get_results():
        log_blue("\n" + _("Results for") + f" {result.server_location.hostname}:")
        deprecated_protocols = []

        if result.connectivity_error_trace:
            # Stuff like connection timeout
            log_red(result.connectivity_error_trace)
            continue

        for scan_command in result.scan_result.__annotations__:
            scan_results = getattr(result.scan_result, scan_command)

            if scan_results.error_reason:
                log_red(scan_results.error_reason)
                continue

            if scan_results.status != ScanCommandAttemptStatusEnum.COMPLETED:
                continue

            if scan_command == ScanCommand.CERTIFICATE_INFO:
                for level, message in process_certificate_info(scan_results.result):
                    results.append((level, message))
            elif scan_command in bad_protocols:
                if scan_results.result.accepted_cipher_suites:
                    deprecated_protocols.append(bad_protocols[scan_command])
            elif scan_command == ScanCommand.ROBOT:
                if scan_results.result.robot_result in (
                        RobotScanResultEnum.VULNERABLE_WEAK_ORACLE, RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
                ):
                    message = _("Server is vulnerable to ROBOT attack")
                    log_red(message)
                    results.append((CRITICAL_LEVEL, message))
            elif scan_command == ScanCommand.HEARTBLEED:
                if scan_results.result.is_vulnerable_to_heartbleed:
                    message = _("Server is vulnerable to Heartbleed attack")
                    log_red(message)
                    results.append((CRITICAL_LEVEL, message))
            elif scan_command == ScanCommand.TLS_COMPRESSION:
                if scan_results.result.supports_compression:
                    message = _("Server is vulnerable to CRIME attack (compression is supported)")
                    log_red(message)
                    results.append((CRITICAL_LEVEL, message))
            elif scan_command == ScanCommand.TLS_FALLBACK_SCSV:
                if not scan_results.result.supports_fallback_scsv:
                    message = _("Server is vulnerable to downgrade attacks (support for TLS_FALLBACK_SCSV is missing)")
                    log_red(message)
                    results.append((CRITICAL_LEVEL, message))
            elif scan_command == ScanCommand.TLS_1_3_EARLY_DATA:
                # https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/
                if scan_results.result.supports_early_data:
                    message = _("TLS 1.3 Early Data (0RTT) is vulnerable to replay attacks")
                    log_orange(message)
                    results.append((MEDIUM_LEVEL, message))
            elif scan_command == ScanCommand.OPENSSL_CCS_INJECTION:
                if scan_results.result.is_vulnerable_to_ccs_injection:
                    message = _("Server is vulnerable to OpenSSL CCS (CVE-2014-0224)")
                    log_red(message)
                    results.append((CRITICAL_LEVEL, message))
            elif scan_command == ScanCommand.SESSION_RENEGOTIATION:
                if scan_results.result.is_vulnerable_to_client_renegotiation_dos:
                    message = _("Server honors client-initiated renegotiations (vulnerable to DoS attacks)")
                    log_red(message)
                    results.append((HIGH_LEVEL, message))
                if not scan_results.result.supports_secure_renegotiation:
                    message = _("Server doesn't support secure renegotiations")
                    log_orange(message)
                    results.append((MEDIUM_LEVEL, message))
            elif scan_command == ScanCommand.HTTP_HEADERS:
                if scan_results.result.strict_transport_security_header is None:
                    message = _("Strict Transport Security (HSTS) is not set")
                    log_red(message)
                    results.append((HIGH_LEVEL, message))
            elif scan_command in good_protocols:
                for level, message in process_cipher_suites(scan_results.result, good_protocols[scan_command]):
                    results.append((level, message))

        if deprecated_protocols:
            message = _("The following protocols are deprecated and/or insecure and should be deactivated:") + \
                      " " + ", ".join(deprecated_protocols)
            log_red(message)
            results.append((CRITICAL_LEVEL, message))

    return results


class ModuleSsl(Attack):
    """Evaluate the security of SSL/TLS certificate configuration."""
    name = "ssl"

    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        # list to ensure only one occurrence per (vulnerable url/post_keys) tuple
        self.tested_targets = set()

    async def must_attack(self, request: Request):
        if request.scheme != "https":
            return False

        if request.hostname in self.tested_targets:
            return False

        self.tested_targets.add(request.hostname)
        return True

    async def attack(self, request: Request):
        loop = asyncio.get_running_loop()
        # sslyze use threads to launch scanners concurrently so we put those inside an asyncio executor
        scan_results = await loop.run_in_executor(None, analyze, request.hostname, request.port)

        for level, message in scan_results:
            if level == INFO_LEVEL:
                await self.add_addition(category=NAME, request=request, info=message, wstg=WSTG_CODE)
            else:
                await self.add_vuln(level=level, category=NAME, request=request, info=message, wstg=WSTG_CODE)
