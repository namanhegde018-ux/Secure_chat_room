"""Verified TLS client context; optional explicit SHA-256 certificate pin."""

import hashlib
import ssl


def create_client_context(cafile=None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def verify_certificate_pin(der_certificate: bytes, expected_sha256_hex: str) -> None:
    actual = hashlib.sha256(der_certificate).hexdigest()
    if not expected_sha256_hex or actual.lower() != expected_sha256_hex.replace(":", "").lower():
        raise ssl.SSLCertVerificationError("server certificate pin mismatch")
