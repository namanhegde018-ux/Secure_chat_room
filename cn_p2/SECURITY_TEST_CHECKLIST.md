# Security test checklist

| Check | Status | Notes |
|---|---|---|
| AES-GCM round trip, wrong key, tampering, malformed input, nonce uniqueness | Automated test passed | `pytest` covers authenticated encryption failures and unique random nonces. |
| X25519/HKDF agreement and signed ephemeral handshake | Automated test passed | Transcript and peer identity context must match at integration. |
| Session key and ephemeral reference cleanup on normal end | Automated test passed | Session context drops the key and ephemeral private-key references; native zeroization cannot be guaranteed. |
| Replay, duplicate, out-of-order, invalid/ended session | Automated test passed | `ReplayGuard` enforces in-order sequences scoped to a session. |
| Chunk tampering, ordering, missing/duplicate chunks, integrity | Automated test passed | File stream authenticates index/context and verifies final size/digest. |
| Private-key encryption, wrong password, Windows ACL | Automated test passed | On Windows, test inspects `icacls` for the current account grant and absence of Everyone; ACL is defense in depth, not protection from same-account malware. |
| Peer fingerprint pinning and changed-key rejection | Automated test passed | Trust persists in a small local JSON file after explicit out-of-band comparison; corrupted trust data fails closed. |
| TLS certificate/hostname validation configuration and pin comparison | Automated test passed | Live server certificate validation remains pending Name 1's server details. |
| No database or persistent message-history files | Automated static test passed; manual review pending | Static scan checks project files for database/history storage artifacts; trust metadata is kept separately in a JSON file. |
| FakeCore contract/events | Automated test passed | UI actions and event data are exercised without a live server. |
| Tkinter login/chat/invite/export/disconnect/end fake flow and watermarked PDF page rendering | Automated test passed; login screen visually inspected | FakeCore flow uses temporary trust data and does not enter an identity password or contact a server. |
| Wireshark application payload inspection | Pending teammate integration | Base64 AES-GCM payload should look high-entropy; TLS also encrypts transport. IPs, timing, sizes and endpoints remain observable absent additional protections. |
| Temp-file cleanup on transfer completion/failure and stale recovery | Automated test passed; forced-termination test pending | Transfer staging files are removed on completion/failure; stale `sm-recv-*`/`sm-send-*` files older than 24 hours are removed when another transfer starts in that folder. Forced termination may leave recent files. |
| Forced termination / Windows process kill; Linux `kill -9` | Pending manual test | Forced termination can bypass cleanup; kill -9 is Linux/WSL-only and must not be claimed passed on Windows. |
| Unauthenticated peer / invalid signature rejection | Crypto helper automated tests passed; pending teammate integration | Handshake helpers verify signatures; real network rejection depends on Name 1 wiring the handshake. |
| Screenshot/export bypass | Known limitation | OS screenshots, cameras, clipboard and external capture cannot be reliably prevented. |
