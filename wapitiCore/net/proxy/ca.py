#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2026 Nicolas SURRIBAS
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
"""Certificate authority used by the intercepting proxy to impersonate HTTPS servers."""
import datetime
import ipaddress
import os
import ssl
import tempfile
from collections import OrderedDict
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT_FILENAME = "wapiti-ca.pem"
CA_KEY_FILENAME = "wapiti-ca-key.pem"
CA_COMMON_NAME = "Wapiti intercepting proxy CA"

CA_VALIDITY = datetime.timedelta(days=3650)
# Browsers reject server certificates valid for more than 398 days
LEAF_VALIDITY = datetime.timedelta(days=365)
# Tolerate clients whose clock is slightly behind ours
CLOCK_SKEW = datetime.timedelta(days=1)
# X.509 limits the common name to 64 characters, longer hostnames only go in the subjectAltName
MAX_COMMON_NAME_LENGTH = 64


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _private_key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().rstrip(".").lower()


class CertificateAuthority:
    """
    A local certificate authority persisted in a directory.

    The CA key and certificate are created on first use and reused afterwards, so a user who imported
    the certificate in a browser does not have to do it again at each scan.
    Server certificates are generated on the fly, one per hostname, and only kept in memory.
    """

    def __init__(self, directory: str, cache_size: int = 1024):
        self._directory = directory
        self._cache_size = cache_size
        self._contexts: "OrderedDict[str, ssl.SSLContext]" = OrderedDict()
        self._ca_key, self._ca_certificate = self._load_or_create()
        # Every server certificate shares the same key: generating one key per host would bring nothing here
        self._leaf_key = ec.generate_private_key(ec.SECP256R1())
        self._leaf_key_pem = _private_key_to_pem(self._leaf_key)

    @property
    def certificate_path(self) -> str:
        """Path of the PEM file to import in a browser as a trusted authority."""
        return os.path.join(self._directory, CA_CERT_FILENAME)

    @property
    def key_path(self) -> str:
        return os.path.join(self._directory, CA_KEY_FILENAME)

    @property
    def certificate(self) -> x509.Certificate:
        return self._ca_certificate

    @property
    def certificate_pem(self) -> bytes:
        return self._ca_certificate.public_bytes(serialization.Encoding.PEM)

    def _load_or_create(self) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        if os.path.isfile(self.certificate_path) and os.path.isfile(self.key_path):
            with open(self.key_path, "rb") as key_file:
                key = serialization.load_pem_private_key(key_file.read(), password=None)

            with open(self.certificate_path, "rb") as certificate_file:
                certificate = x509.load_pem_x509_certificate(certificate_file.read())

            if certificate.public_key().public_numbers() != key.public_key().public_numbers():
                # Never overwrite files we don't understand, the user may have put its own CA here
                raise ValueError(
                    f"The certificate {self.certificate_path} does not match the private key {self.key_path}"
                )

            if certificate.not_valid_after_utc > _utcnow() + CLOCK_SKEW:
                return key, certificate

        return self._create()

    def _create(self) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wapiti"),
        ])
        now = _utcnow()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + CA_VALIDITY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )

        os.makedirs(self._directory, mode=0o700, exist_ok=True)
        # The private key must never be readable by other users: anyone holding it can impersonate
        # any website for a browser trusting our certificate
        descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(_private_key_to_pem(key))

        with open(self.certificate_path, "wb") as certificate_file:
            certificate_file.write(certificate.public_bytes(serialization.Encoding.PEM))

        return key, certificate

    def issue_certificate(self, hostname: str) -> x509.Certificate:
        """Returns a server certificate for the given hostname (or IP address), signed by the CA."""
        hostname = normalize_hostname(hostname)
        try:
            alternative_name = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            alternative_name = x509.DNSName(hostname)

        attributes = []
        if len(hostname) <= MAX_COMMON_NAME_LENGTH:
            attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, hostname))

        now = _utcnow()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name(attributes))
            .issuer_name(self._ca_certificate.subject)
            .public_key(self._leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + LEAF_VALIDITY)
            # The subjectAltName must be critical when the subject is empty
            .add_extension(x509.SubjectAlternativeName([alternative_name]), critical=not attributes)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._leaf_key.public_key()),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

    def ssl_context_for(self, hostname: str) -> ssl.SSLContext:
        """Returns a server-side SSL context presenting a certificate valid for the given hostname."""
        hostname = normalize_hostname(hostname)
        context = self._contexts.get(hostname)
        if context is not None:
            self._contexts.move_to_end(hostname)
            return context

        certificate = self.issue_certificate(hostname)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # The proxy only speaks HTTP/1.1 with its clients
        context.set_alpn_protocols(["http/1.1"])

        # The ssl module can only load a certificate chain from a file.
        # delete=False because Windows can't open a NamedTemporaryFile a second time while it is still open.
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as chain_file:
            try:
                chain_file.write(self._leaf_key_pem)
                chain_file.write(certificate.public_bytes(serialization.Encoding.PEM))
                chain_file.close()
                context.load_cert_chain(chain_file.name)
            finally:
                chain_file.close()
                os.unlink(chain_file.name)

        self._contexts[hostname] = context
        if len(self._contexts) > self._cache_size:
            self._contexts.popitem(last=False)

        return context
