import ssl
import hashlib
import pytest
from crypto.tls import create_client_context, verify_certificate_pin


def test_tls_context_requires_certificate_and_hostname_verification():
    context = create_client_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_certificate_pin_comparison():
    cert = b"demo certificate bytes"
    verify_certificate_pin(cert, hashlib.sha256(cert).hexdigest())
    with pytest.raises(ssl.SSLCertVerificationError):
        verify_certificate_pin(cert, "00" * 32)
