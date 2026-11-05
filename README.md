# 🔐 Database-Free Secure Messaging

**A Session-Based, Peer-to-Peer Communication System Using TCP and Software-Defined Networking (SDN)**

A privacy-focused messaging application designed to minimize persistent data storage, provide secure communication, and give users greater control over shared information.

Unlike conventional messaging systems that commonly support persistent conversation histories, this project follows a **database-free architecture** in which active communication sessions and temporary content are managed without maintaining a persistent message database.

---

## 📌 Project Overview

Digital communication increasingly involves exchanging sensitive information, including confidential documents, private discussions, business information, and personal data.

End-to-end encryption protects message contents against many forms of interception. However, encryption alone does not eliminate risks associated with persistent storage, compromised devices, recipient-controlled disclosure, or communication metadata.

This project explores an alternative approach: **communication that exists primarily within an authorized session rather than as a permanently stored conversation.**

The application combines:

- Peer-to-Peer (P2P) communication.
- TCP-based data transmission.
- End-to-End Encryption (E2EE).
- Database-free architecture.
- Temporary document sharing.
- Sender-authorized document export.
- Software-Defined Networking (SDN) for network-flow management.

## 🎯 Objectives

- Eliminate persistent message-history databases.
- Minimize the retention of sensitive communication data.
- Establish secure, session-based communication.
- Enable direct peer-to-peer communication wherever network conditions permit.
- Restrict ordinary unauthorized copying and exporting of shared documents.
- Implement network-level access policies using SDN.
- Reduce unnecessary exposure of communication metadata.

---

## ⚙️ Key Features

### 1. Database-Free Architecture

The application is designed without a database on either the client or server side.

- Contacts are maintained locally using files.
- Active session information is maintained in memory.
- Message history is not persistently stored.
- Temporary session data is removed after termination.
- No offline message history is maintained.

The objective is to minimize the amount of sensitive information retained by the application.

### 2. Peer-to-Peer Communication

The application aims to establish direct communication between users.

- Users can initiate individual or group conversations.
- Recipients must accept incoming communication requests.
- TCP is used for reliable data transmission.
- A signaling mechanism assists with peer discovery and session establishment.
- A relay may be used when direct connectivity is unavailable.

### 3. Session-Based Messaging

Communication takes place within authorized sessions.

- Users initiate a communication request.
- Recipients accept or reject the request.
- Messages and shared content are available during the session.
- Session termination triggers cleanup of temporary application data.
- Concurrent communication sessions can be detected and notified to relevant participants.

### 4. Temporary Document Sharing

Users can exchange documents and other files without automatically creating permanent copies through the application.

Proposed workflow:

1. Sender shares a document.
2. Recipient views it inside the application.
3. Recipient requests permission to save it.
4. Sender approves or rejects the request.
5. If approved, the application authorizes document export.

The application aims to restrict ordinary copying, forwarding, and exporting wherever technically possible.

**Note:** These restrictions cannot prevent external photography, modified clients, or privileged operating-system-level capture.

### 5. Software-Defined Networking (SDN)

SDN is integrated to provide programmable network access control.

Potential capabilities include:

- Managing authorized communication flows.
- Restricting unauthorized network connections.
- Applying network segmentation.
- Dynamically managing forwarding rules.
- Revoking session-related network permissions.

SDN provides network control, not automatic anonymity. Its policies apply to infrastructure under the system's administrative control.

### 6. Session Cleanup

When a session terminates, the application aims to:

- Discard ephemeral session private keys and derived session keys.
- Clear application-managed message buffers.
- Remove temporary files.
- Discard temporary session metadata.
- Revoke associated network-flow permissions where applicable.

Cleanup is best-effort. In a garbage-collected language such as Python, overwriting every copy of secret material in memory cannot be guaranteed. The application must avoid logging secrets and should keep sensitive data in memory only as long as necessary.

### 7. Dynamic Document Watermarking (Planned)

The document viewer may display a recipient-specific visible watermark, such as the recipient identifier and a session reference. This can discourage casual redistribution and help investigate a leaked screenshot or export.

Watermarking is a deterrent and attribution aid, not copy protection. It cannot prevent screenshots, photography, screen recording, or deliberate removal by a modified client.

---

## 🏗️ System Architecture

The proposed architecture consists of the following components:

```
                 USER A
          ┌──────────────────┐
          │   Desktop Client │
          │                  │
          │  Local Contacts  │
          │  Session Manager │
          │  Encryption      │
          │  File Handling   │
          └────────┬─────────┘
                   │
                   │
             Signaling Layer
          (Temporary RAM State)
                   │
                   │
          ┌────────▼─────────┐
          │  Peer Discovery  │
          │ Session Setup    │
          │ Authentication  │
          └────────┬─────────┘
                   │
                   │
             TCP Connection
                   │
          ┌────────▼─────────┐
          │   USER B CLIENT  │
          │                  │
          │  Local Contacts  │
          │  Session Manager │
          │  Encryption      │
          │  File Handling   │
          └──────────────────┘

              SDN Controller
                    │
                    ▼
             Network Devices

```

### Communication Workflow

1. Users register or authenticate with the signaling mechanism.
2. Online peer information is maintained temporarily in memory.
3. A user initiates a communication request.
4. The signaling mechanism locates the intended recipient.
5. The recipient accepts the request.
6. The clients establish an authenticated, encrypted communication session.
7. Data is exchanged directly over TCP whenever network conditions permit.
8. The session terminates and temporary application state is cleaned up.

---

## 🔒 Security and Privacy Approach

The project follows these security principles:

| **Principle**          | **Implementation Goal**                                |
| ---------------------- | ------------------------------------------------------ |
| Data minimization      | Avoid unnecessary persistent storage                   |
| Confidentiality        | End-to-end encryption                                  |
| Authentication         | Verify communicating identities                        |
| Forward secrecy        | Use an established protocol supporting forward secrecy |
| Temporary access       | Session-based communication                            |
| Controlled sharing     | Sender-authorized document export                      |
| Network access control | SDN-based flow management                              |
| Data cleanup           | Remove temporary application-managed data              |

### Threat Model

The application aims to reduce risks associated with:

- Network interception.
- Unauthorized network connections.
- Persistent server-side message storage.
- Unnecessary message-history retention.
- Unauthorized ordinary document export.

It does not claim to eliminate:

- Malware or spyware on participant devices.
- External screen photography or recording.
- Deliberate disclosure by authorized recipients.
- All forms of network traffic analysis.
- Metadata exposure to network infrastructure.

---

## 🛠️ Technology Stack

The proposed desktop client will use **Python 3.11 or later** and **Tkinter**. Tkinter is included with standard Python distributions and is generally straightforward to package and run on Windows. It is selected instead of GTK to reduce cross-platform setup friction.

| **Component** | **Technology / Library** |
|---|---|
| Desktop interface | Tkinter (`tkinter`, `ttk`) |
| Language | Python 3.11+ |
| TCP networking | Python standard library (`socket`, `ssl`) |
| Message framing and models | `struct`, `json`, `dataclasses`, `enum`, `typing` |
| Concurrency | `threading`, `queue` |
| Cryptographic primitives | `cryptography` |
| Key agreement | X25519 |
| Identity signatures | Ed25519 |
| Key derivation | HKDF-SHA256 |
| Authenticated encryption | ChaCha20-Poly1305 (or AES-GCM) |
| File handling | `pathlib`, `tempfile`, `hashlib` |
| Peer-to-peer networking | TCP sockets; signaling and optional relay |
| SDN emulator | Mininet |
| Virtual switching | Open vSwitch |
| SDN controller | Ryu or a compatible controller |

**Alternative GUI:** PySide6 (Qt for Python) is also suitable if the project needs a richer interface, more advanced widgets, or a more polished desktop experience. It is an additional dependency and should be selected deliberately. The current proposed baseline is Tkinter; do not mix Tkinter and PySide6 in the same UI.

The SDN controller and Mininet environment may run separately from the Windows desktop client, typically in a Linux VM. Pin and test compatible versions for the chosen controller environment.

*These are proposed implementation choices. Pin exact dependency versions in a requirements file after the team validates them on its target environment.*

---

## 📜 Interface and Protocol Contracts

This section defines the initial contracts between the desktop UI, application core, peers, and cryptographic layer. These are proposed interfaces; implementation names and payload fields should remain consistent across team members.

### 1. Message Types

Messages use a common envelope. Control messages can be encoded as UTF-8 JSON; encrypted message/file payloads should be carried as binary data rather than being forced into JSON strings.

| **Message type** | **Direction** | **Purpose** |
|---|---|---|
| `HELLO` | Client ↔ signaling service | Announce or refresh temporary online presence |
| `SESSION_REQUEST` | Initiator → recipient | Request a communication session |
| `SESSION_ACCEPT` | Recipient → initiator | Accept a session request |
| `SESSION_REJECT` | Recipient → initiator | Reject a session request |
| `KEY_EXCHANGE` | Peer ↔ peer | Exchange signed ephemeral X25519 public keys |
| `KEY_CONFIRM` | Peer ↔ peer | Confirm that both peers derived the same session context |
| `DATA` | Peer ↔ peer | Carry an encrypted chat message |
| `FILE_OFFER` | Sender → recipient | Announce a file and its metadata |
| `FILE_PERMISSION_REQUEST` | Recipient → sender | Request permission to export a shared file |
| `FILE_PERMISSION_RESPONSE` | Sender → recipient | Approve or reject an export request |
| `FILE_CHUNK` | Peer ↔ peer | Carry an encrypted file-data chunk |
| `SESSION_END` | Peer ↔ peer | End the active session |
| `HEARTBEAT` | Client ↔ signaling service / peer | Maintain temporary liveness state |
| `ERROR` | Any component → peer/component | Report a protocol or application error |

**Common control-message envelope (illustrative):**


The receiver must validate the protocol version, message type, field sizes, session state, sender identity, and authorization before processing a message. Use length-prefixed framing over TCP so the receiver can determine where each message ends; TCP itself is a byte stream and does not preserve application message boundaries. Do not put plaintext message bodies, private keys, or secret key material in signaling messages or logs.

### 2. Cryptographic Function Contracts

The crypto module will provide the following operations:

- `generate_identity_keypair()` — create or load the user's long-term Ed25519 identity keys.
- `generate_ephemeral_keypair()` — create a fresh X25519 keypair for each session.
- `sign_ephemeral_key()` — sign the session's ephemeral public key and session context using the identity key.
- `verify_ephemeral_signature()` — verify the peer's signature using a trusted identity public key.
- `derive_session_keys()` — derive separate send and receive keys using X25519 and HKDF-SHA256.
- `encrypt_message()` / `decrypt_message()` — protect and authenticate messages using an AEAD cipher such as ChaCha20-Poly1305 or AES-GCM.
- `discard_session_secrets()` — release session key references and clear application-managed session state.

**Forward-secrecy requirements:** Generate new ephemeral X25519 keys for every session; never reuse ephemeral private keys. Authenticate the key exchange by signing a canonical session transcript with the long-term Ed25519 identity key. Verify identity keys through a trusted enrollment or fingerprint-verification process. Derive separate directional keys and never reuse an AEAD nonce with the same key. Discard ephemeral and session secrets when the session ends. Python cannot guarantee physical zeroization of every in-memory copy.

This design is intended to provide forward secrecy against later compromise of the long-term identity signing key, assuming ephemeral secrets were not retained or compromised. Prefer a reviewed handshake protocol, such as Noise, over a custom handshake where practical.

### 3. UI-to-Core Methods

The UI must call the application core through a defined controller/service interface. Long-running network and file operations must not block the UI thread.

| **Method** | **Purpose** |
|---|---|
| `start()` | Initialize the core and required background services |
| `stop()` | Stop services and clean up active sessions |
| `get_contacts()` | Return locally stored contacts |
| `add_contact(contact)` | Add or update a local contact |
| `send_session_request(peer_id)` | Request a session with a peer |
| `accept_session(session_id)` | Accept an incoming session |
| `reject_session(session_id)` | Reject an incoming session |
| `send_text(session_id, text)` | Send a text message through the active secure session |
| `offer_file(session_id, file_path)` | Offer a file to the peer |
| `request_file_export(session_id, file_id)` | Ask the sender for export permission |
| `respond_to_export_request(session_id, request_id, approved)` | Approve or reject an export request |
| `end_session(session_id)` | End a session and trigger cleanup |

### 4. Core-to-UI Events

The core must publish events to the UI. In a Tkinter implementation, worker threads should place events on a `queue.Queue`; the UI thread should consume the queue and update widgets. Worker threads must not directly modify Tkinter widgets.

| **Event** | **When it is emitted** |
|---|---|
| `on_status_changed(status)` | Connection or application status changes |
| `on_peer_presence_changed(peer_id, online)` | A contact's temporary online status changes |
| `on_incoming_session_request(request)` | A peer requests a session |
| `on_session_established(session_id, peer)` | A secure session is ready |
| `on_message_received(session_id, message)` | An authenticated message is received |
| `on_file_offer_received(session_id, file_offer)` | A peer offers a file |
| `on_export_permission_requested(request)` | A recipient requests permission to export |
| `on_export_permission_result(request_id, approved)` | An export request receives a decision |
| `on_session_ended(session_id, reason)` | A session terminates |
| `on_error(error_code, message)` | A recoverable or fatal error occurs |

Events should contain only the information the UI needs. Do not expose private keys or raw session secrets to the UI layer.

### 5. Python Runtime and Libraries

**Proposed baseline:** Python 3.11+ for the desktop client and core.

**Python libraries:** `cryptography` is the main additional dependency. The client also uses standard-library modules such as `tkinter`, `socket`, `ssl`, `threading`, `queue`, `json`, `dataclasses`, and `pathlib`.

Mininet, Open vSwitch, and the SDN controller are installed separately in the Linux network-lab environment.

---
## ⚖️ Advantages and Trade-offs

### Advantages

- No persistent message-history database.
- Reduced server-side exposure of historical conversations.
- Temporary communication sessions.
- Greater control over document export.
- Programmable network access control.
- Reduced unnecessary data retention.

### Trade-offs

- No conventional offline message delivery.
- No persistent conversation history or recovery.
- P2P connections may be restricted by NAT and firewalls.
- Relay infrastructure may be required.
- Screenshot and external recording restrictions cannot be guaranteed.
- Database-free operation does not eliminate all metadata exposure.
- Secure identity and key management introduce additional complexity.

---

## 🚀 Development Status

**Project Status: Under Development**

Planned development stages:

- &#x20;TCP-based communication.
- &#x20;Peer discovery and signaling.
- &#x20;User authentication.
- &#x20;End-to-end encryption and authenticated ephemeral X25519 key exchange.
- &#x20;Message and application interface contracts.
- &#x20;Tkinter desktop UI and Python dependency setup.
- &#x20;Individual communication sessions.
- &#x20;Group communication.
- &#x20;Temporary document sharing.
- &#x20;Sender-authorized document export.
- &#x20;Session lifecycle and cleanup.
- &#x20;SDN integration.
- &#x20;Network-flow authorization and revocation.
- &#x20;Security and performance testing.

---

## 🎯 Intended Use Cases

The project explores applications in environments where confidentiality and reduced data retention are important:

- Confidential professional discussions.
- Corporate document exchange.
- Research collaboration.
- Legal and consulting communications.
- Sensitive internal organizational communication.
- Secure team discussions.

The system's suitability for regulated environments would require additional compliance, audit, and retention controls.

---

## 📚 Core Design Philosophy

> Communication should not necessarily create a permanent record.

The project explores a communication model in which sensitive information is exchanged through authenticated, encrypted sessions, with minimal persistent storage and controlled document sharing.

Rather than relying exclusively on encryption, it considers the entire communication lifecycle: identity, discovery, connection establishment, data exchange, network access, and session termination.

---

## ⚠️ Disclaimer

This project is developed for educational and research purposes.

It does not claim to provide absolute anonymity, prevent every form of information leakage, or guarantee complete physical erasure of data.

Security depends on the implementation, cryptographic protocols, endpoint integrity, network configuration, and operational environment.

---

## 🤝 Contributions

Contributions, suggestions, security reviews, and architectural discussions are welcome.

If you identify a security vulnerability, please report it responsibly rather than publicly disclosing exploitable details.

---

**Built with a focus on privacy, data minimization, and secure communication.**