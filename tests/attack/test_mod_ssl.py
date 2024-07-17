from multiprocessing import Process
import os
import sys
from time import sleep
from asyncio import Event
import http.server
import ssl
from unittest.mock import AsyncMock
from datetime import datetime, timedelta

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, INFO_LEVEL, MEDIUM_LEVEL
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_ssl import (
    ModuleSsl, extract_altnames,
    match_address, check_ocsp_must_staple, check_ev_certificate, process_vulnerabilities, process_bad_protocols
)


def https_server(cert_directory: str):
    server_address = ("127.0.0.1", 4443)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile=os.path.join(cert_directory, "cert.pem"),
        keyfile=os.path.join(cert_directory, "key.pem"),
        ssl_version=ssl.PROTOCOL_TLS
    )
    httpd.serve_forever()


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    pem_directory = os.path.join(base_dir, "..", "tests/data/ssl/")

    process = Process(target=https_server, args=(pem_directory,))
    process.start()

    sleep(.5)
    yield
    process.kill()


@pytest.mark.asyncio
async def test_ssl_scanner():
    persister = AsyncMock()
    request = Request("https://127.0.0.1:4443/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("https://127.0.0.1:4443/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsl(crawler, persister, options, Event(), crawler_configuration)
        await module.attack(request)

        persister.add_payload.assert_any_call(
            request_id=-1,
            payload_type="additional",
            module="ssl",
            category="TLS/SSL misconfigurations",
            level=INFO_LEVEL,
            request=request,
            parameter='',
            wstg=["WSTG-CRYP-01"],
            info="Certificate subject: yolo.com",
            response=None
        )

        persister.add_payload.assert_any_call(
            request_id=-1,
            payload_type="vulnerability",
            module="ssl",
            category="TLS/SSL misconfigurations",
            level=CRITICAL_LEVEL,
            request=request,
            parameter='',
            wstg=["WSTG-CRYP-01"],
            info="Requested hostname doesn't match those in the certificate",
            response=None
        )

        persister.add_payload.assert_any_call(
            request_id=-1,
            payload_type="vulnerability",
            module="ssl",
            category="TLS/SSL misconfigurations",
            level=HIGH_LEVEL,
            request=request,
            parameter='',
            wstg=["WSTG-CRYP-01"],
            info="Strict Transport Security (HSTS) is not set",
            response=None
        )

        persister.add_payload.assert_any_call(
            request_id=-1,
            payload_type="vulnerability",
            module="ssl",
            category="TLS/SSL misconfigurations",
            level=MEDIUM_LEVEL,
            request=request,
            parameter='',
            wstg=["WSTG-CRYP-01"],
            info="Self-signed certificate detected: The certificate is not signed by a trusted Certificate Authority",
            response=None
        )


def test_extract_alt_names():
    assert ["perdu.com", "test.fr"] == extract_altnames("DNS:perdu.com,  DNS:test.fr, whatever, ")


def test_match_address():
    assert match_address("sub.domain.com", "domain.com", ["*.domain.com", "yolo"])
    assert match_address("sub.domain.com", "*.domain.com", ["yolo"])
    assert not match_address("sub.domain.com", "google.com", ["*.truc.com"])


def generate_cert(include_organization_name: bool = True, include_ocsp_must_staple: bool = True):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Build the subject name
    subject_name = [
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"mysite.com"),
    ]

    if include_organization_name:
        subject_name.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Company"))

    # Generate a certificate
    subject = issuer = x509.Name(subject_name)

    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    )

    if include_ocsp_must_staple:
        cert_builder = cert_builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False
        )

    cert = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
    return cert


@pytest.mark.asyncio
@respx.mock
async def test_certificate_transparency():
    cert = generate_cert()
    respx.get(f'https://crt.sh/?q={cert.serial_number}').mock(
        # Method GET that serve as a reference
        return_value=httpx.Response(200, text="Success")
    )

    persister = AsyncMock()
    request = Request("https://127.0.0.1:4443/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("https://127.0.0.1:4443/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsl(crawler, persister, options, Event(), crawler_configuration)
        assert 1 == await module.check_certificate_transparency(cert)


def test_ocsp():
    assert 0 == check_ocsp_must_staple(generate_cert(include_ocsp_must_staple=False))
    assert 1 == check_ocsp_must_staple(generate_cert())


def test_extended_validation():
    assert 0 == check_ev_certificate(generate_cert(include_organization_name=False))
    assert 1 == check_ev_certificate(generate_cert())


@pytest.mark.asyncio
async def test_process_vulnerabilities():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    xml_file = os.path.join(base_dir, "..", "tests/data/ssl/broken_ssl.xml")
    results = [info async for info in process_vulnerabilities(xml_file)]
    assert [
        (4, 'Server is vulnerable to Heartbleed attack via TLSv1.0'),
        (3, 'Server honors client-initiated renegotiations (vulnerable to DoS attacks)')
    ] == results


@pytest.mark.asyncio
async def test_process_bad_protocols():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    xml_file = os.path.join(base_dir, "..", "tests/data/ssl/broken_ssl.xml")
    results = [info async for info in process_bad_protocols(xml_file)]
    assert [
       (4, 'The following protocols are deprecated and/or insecure and should be deactivated: SSLv2, TLSv1.0')
    ] == results
