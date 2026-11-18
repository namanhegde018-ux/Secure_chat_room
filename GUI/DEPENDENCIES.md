# Team dependencies

## Pending — Name 1

- Provide the actual networking/core package and its event payload definitions to connect `gui.app.SecureMessagingApp` to the real signaling server.
- Provide the TLS server hostname and trusted CA/certificate pin configuration.
- Confirm how the handshake public keys/signatures and session transcript are represented in the existing JSON messages.
- Provide the actual server/core and event schemas to test Wireshark payload visibility, authenticated-peer rejection, and live crypto/file integration.
- Until then, the GUI uses `gui.fake_core.FakeCore`; networking and TLS integration are not complete.

## Implemented independently

- Peer fingerprints that the user explicitly confirms are pinned in `trusted-peers.json` (a small metadata file, not a message database). A changed fingerprint fails closed and requires deliberate local trust reset after out-of-band verification.
- The GUI has a PDF viewer that renders each page with a recipient name and timestamp watermark. Screenshot/capture bypass remains a known limitation.
