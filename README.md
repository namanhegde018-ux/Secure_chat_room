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

- Destroy session cryptographic keys.
- Clear application-managed message buffers.
- Remove temporary files.
- Discard temporary session metadata.
- Revoke associated network-flow permissions where applicable.

Cleanup is best-effort and cannot guarantee the removal of every operating-system, storage, or recipient-side artifact.

---

## 🏗️ System Architecture

The proposed architecture consists of the following components:

```text
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

| Principle | Implementation Goal |
|---|---|
| Data minimization | Avoid unnecessary persistent storage |
| Confidentiality | End-to-end encryption |
| Authentication | Verify communicating identities |
| Forward secrecy | Use an established protocol supporting forward secrecy |
| Temporary access | Session-based communication |
| Controlled sharing | Sender-authorized document export |
| Network access control | SDN-based flow management |
| Data cleanup | Remove temporary application-managed data |

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

| Component | Technology |
|---|---|
| Desktop Interface | GTK |
| Programming Language | Python / C++ |
| Communication Protocol | TCP |
| Transport Security | TLS |
| Message Security | End-to-End Encryption |
| Network Architecture | Peer-to-Peer |
| Network Management | Software-Defined Networking |
| SDN Emulator | Mininet |
| Virtual Switching | Open vSwitch |
| SDN Controller | Ryu or compatible controller |

*The final technology stack may change during implementation.*

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

- [ ] TCP-based communication.
- [ ] Peer discovery and signaling.
- [ ] User authentication.
- [ ] End-to-end encryption.
- [ ] Individual communication sessions.
- [ ] Group communication.
- [ ] Temporary document sharing.
- [ ] Sender-authorized document export.
- [ ] Session lifecycle and cleanup.
- [ ] SDN integration.
- [ ] Network-flow authorization and revocation.
- [ ] Security and performance testing.

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
