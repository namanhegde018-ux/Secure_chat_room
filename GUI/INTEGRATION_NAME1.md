# Name 1 integration handoff

Share `crypto/encryption.py` (and `crypto/__init__.py` only if importing via package root). Import `from crypto.encryption import encrypt, decrypt`.

- `encrypt(key: bytes, data: bytes) -> bytes`: key must be exactly 32 bytes. Output is nonce (12 bytes) followed by AESGCM ciphertext and 16-byte authentication tag.
- `decrypt(key: bytes, data: bytes) -> bytes`: rejects malformed data and authenticated tampering/wrong keys.
- Base64 encode bytes for JSON; never put raw bytes in JSON.
- Automated tests are in `tests/test_encryption.py` and passed in the project's Python 3.13 virtual environment.
- Create the client TLS context with `crypto.tls.create_client_context(cafile=trusted_ca_or_explicit_server_cert)`, wrap with `server_hostname=expected_host`, and retain normal hostname/certificate validation. If using a pin as an additional check, compare `tls_socket.getpeercert(binary_form=True)` with `crypto.tls.verify_certificate_pin(...)` after the verified handshake; never turn off certificate verification.

Use a unique session key per conversation and do not reuse keys across sessions. A random nonce per message makes reuse extraordinarily unlikely, but session key rotation and replay protection are still required. AES-GCM does not by itself authenticate the peer or prevent replay.
