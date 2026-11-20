import ipaddress
import os
import ssl
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from wapitiCore.net.proxy.ca import CertificateAuthority, CA_COMMON_NAME


def test_ca_files_are_created_with_safe_permissions(tmp_path):
    directory = tmp_path / "ca"
    authority = CertificateAuthority(str(directory))

    assert os.path.isfile(authority.certificate_path)
    assert os.path.isfile(authority.key_path)
    # Nobody but the owner can read the private key
    assert stat.S_IMODE(os.stat(authority.key_path).st_mode) == 0o600

    certificate = authority.certificate
    assert certificate.subject.rfc4514_string().startswith(f"O=Wapiti,CN={CA_COMMON_NAME}")
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True


def test_ca_is_reused_between_instances(tmp_path):
    first = CertificateAuthority(str(tmp_path))
    second = CertificateAuthority(str(tmp_path))

    assert first.certificate_pem == second.certificate_pem
    # A certificate issued by one instance is trusted through the certificate of the other
    second.issue_certificate("example.com").verify_directly_issued_by(first.certificate)


def test_mismatching_key_is_not_overwritten(tmp_path):
    authority = CertificateAuthority(str(tmp_path))
    with open(authority.certificate_path, "rb") as certificate_file:
        original_certificate = certificate_file.read()

    other = CertificateAuthority(str(tmp_path / "other"))
    with open(other.key_path, "rb") as source, open(authority.key_path, "wb") as destination:
        destination.write(source.read())

    with pytest.raises(ValueError):
        CertificateAuthority(str(tmp_path))

    with open(authority.certificate_path, "rb") as certificate_file:
        assert certificate_file.read() == original_certificate


def test_issue_certificate_for_hostname(tmp_path):
    authority = CertificateAuthority(str(tmp_path))
    certificate = authority.issue_certificate("WWW.Example.com.")

    certificate.verify_directly_issued_by(authority.certificate)
    alternative_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert alternative_names.get_values_for_type(x509.DNSName) == ["www.example.com"]
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert isinstance(certificate.public_key(), ec.EllipticCurvePublicKey)
    # Browsers refuse certificates valid for more than 398 days
    assert (certificate.not_valid_after_utc - certificate.not_valid_before_utc).days <= 398


def test_issue_certificate_for_ip_address(tmp_path):
    authority = CertificateAuthority(str(tmp_path))
    certificate = authority.issue_certificate("127.0.0.1")

    alternative_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert alternative_names.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("127.0.0.1")]
    assert alternative_names.get_values_for_type(x509.DNSName) == []


def test_issue_certificate_for_long_hostname(tmp_path):
    authority = CertificateAuthority(str(tmp_path))
    hostname = ".".join(["a" * 30] * 4) + ".example.com"
    certificate = authority.issue_certificate(hostname)

    # Too long for a common name: the hostname is only in the (then critical) subjectAltName
    assert not certificate.subject.rdns
    extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert extension.critical is True
    assert extension.value.get_values_for_type(x509.DNSName) == [hostname]


def test_ssl_contexts_are_cached_and_evicted(tmp_path):
    authority = CertificateAuthority(str(tmp_path), cache_size=2)
    first = authority.ssl_context_for("a.example.com")

    assert isinstance(first, ssl.SSLContext)
    assert authority.ssl_context_for("A.example.com.") is first

    authority.ssl_context_for("b.example.com")
    authority.ssl_context_for("c.example.com")
    # a.example.com was the least recently used entry, so it got evicted
    assert authority.ssl_context_for("a.example.com") is not first
