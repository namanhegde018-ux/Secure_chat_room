# Database-Free Secure Messaging — Name 2 module

Cryptography, security helpers, secure file transfer, and a Tkinter demonstration GUI. No database or conversation history is created. The GUI runs against `FakeCore` until Name 1's actual backend is supplied.

## Environment

- Python 3.10 or newer
- Dependencies: `cryptography` (AES-GCM, X25519, Ed25519, HKDF, Scrypt), `PyMuPDF` and `Pillow` (watermarked PDF display); `pytest` for tests
- Tkinter is included with most standard Windows Python distributions.

Install with `python -m venv .venv`, then `.venv\\Scripts\\python -m pip install -r requirements.txt` on Windows. Run the GUI with `.venv\\Scripts\\python main.py` and tests with `.venv\\Scripts\\python -m pytest`.

## Crypto API for Name 1

```python
from crypto.encryption import encrypt, decrypt
encrypted: bytes = encrypt(key_32_bytes, plaintext_bytes)
plaintext: bytes = decrypt(key_32_bytes, encrypted)
```

Encrypted bytes are `12-byte random nonce || AES-GCM ciphertext || 16-byte tag`. Encode the result as Base64 before placing it in JSON. AES-GCM authentication errors propagate as `cryptography.exceptions.InvalidTag`; malformed/short values raise `ValueError`. A fresh random nonce is generated for each call. The caller must use a fresh session key and must not reuse a key/nonce pair.

Other agreed functions are `crypto.key_exchange.derive_session_key(my_priv, their_pub, context=...)` and `crypto.fingerprint.fingerprint(pubkey_bytes)`. For session derivation, context must bind a unique session and both parties' authenticated handshake transcript. `crypto.session.EphemeralHandshake` creates signed ephemeral X25519 keys; `SessionSecurityContext` scopes sequence tracking and drops key references at session close. Callers must compare verified identity fingerprints and provide the same transcript/context on both ends. Python does not guarantee native memory zeroization.

## Message and UI contract

Networking contract to be implemented by Name 1: 4-byte big-endian length header followed by UTF-8 JSON; message types `register`, `invite`, `accept`, `reject`, `msg`, `file`, `export_request`, `export_decision`, `end`. UI-to-core methods: `connect`, `invite`, `accept`, `reject`, `send_message`, `send_file`, `request_export`, `decide_export`, `end_session`. Core events: `on_invite_received`, `on_session_started`, `on_message`, `on_file_received`, `on_export_request`, `on_export_decision`, `on_peer_disconnected`, `on_session_ended`.

The GUI queues incoming callbacks onto Tk's event loop. Demo: Connect, Simulate invite, confirm identity comparison, then chat. FakeCore is not a network implementation.

## Identity and security notes

`crypto.identity` stores a password-encrypted Ed25519 raw private key in `%USERPROFILE%\\.secure-messaging\\identity.key`, using Scrypt and AES-GCM, and applies a current-user-only Windows ACL attempt. The GUI asks for the password and displays the computed fingerprint. The password is never embedded. Filesystem ACLs do not protect against malware or compromise of the same user account. Do not commit identity files.

TLS helper `crypto.tls.create_client_context(cafile=...)` requires certificate validation and hostname verification. Configure the server name when wrapping the socket; use a trusted CA or explicit pinning. There is no live server integration yet.

File encryption uses 64 KiB chunks, random per-chunk nonces, and AES-GCM AAD binding the session, transfer, chunk index, and total count. It writes to a temporary destination and atomically replaces only after full length and SHA-256 validation. Normal failure cleans the temp file; stale send/receive files older than 24 hours are scavenged when another transfer begins in the same folder. Forced termination can leave recent temp files behind. Python does not guarantee native secret zeroization.

## Status

Automated crypto/security, Tk fake-flow, and PDF-rendering tests pass in the local Python 3.13 virtual environment (21 tests). The login screen was also opened and visually inspected. No password was entered; the GUI flow test uses FakeCore and a temporary peer-trust file. Name 1 networking integration remains pending. See `SECURITY_TEST_CHECKLIST.md` and `DEPENDENCIES.md`.
