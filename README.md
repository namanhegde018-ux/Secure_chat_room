*Secure Messenger*:
Secure Messenger is a command-line messaging system for two or more people, built to show how end-to-end encryption and network policy can work together. Users connect to a central relay server that forwards their messages, but the server cannot read the content. Each pair of users in a chat establishes its own encrypted channel, and they confirm each other's identity by comparing fingerprints through a separate channel. A software-defined network lab, built with Mininet and OS-Ken, accompanies the project and restricts the network so that clients can reach only the server. The project is a learning and demonstration system and has not been security audited.


*Aims*:
1.Provide group text messaging through a relay server that holds no accounts and no message content.
2.Protect message content from the server and from anyone observing the network, using authenticated key agreement and ChaCha20-Poly1305 encryption.
3.Prevent silent key substitution by requiring users to verify each other's fingerprints before messages are accepted.
4.Support one-to-one file transfer with SHA-256 integrity checks and sender-approved export.
5.Keep the server stateless with respect to storage, with all session state held in memory.
6.Demonstrate network-level enforcement that allows clients to reach only the server, using OpenFlow 1.3.
7.Keep the client core independent of the user interface, so the interface can change without touching the networking or cryptography.


*Project layout*:
1.main.py: the user program. It starts the server if needed and provides the menu and chat commands.
2.src/signaling_server/: the relay server, including connection handling, invitations, groups, and expiry.
3.src/client_core/: the client library, including networking, handshake, encryption, trust storage, file transfer, and temporary storage.
4.src/tests/: unit tests for the cryptography and session logic.
5.sdn/: the network lab, including the OpenFlow policy, the Mininet topology, and the controller launcher.
6.docs/SYSTEM_GUIDE.md: the detailed design document.


*Chat Commands*:
fp: show your fingerprint.
invite <name> [name ...]: invite one or more people to a group.
accept <id> or reject <id>: respond to an invitation.
verify <name> <fingerprint>: confirm a peer's fingerprint after comparing it out of band.
msg <text>: send a message to the group.
file <path>: send a file (one-to-one chats only).
files: list sent and received files with their transfer IDs.
reqexport <id>, approve <id>, deny <id>, export <id>: request, decide, and perform an export of a received file.
end: end the current chat.
disconnect: leave the chat and return to the menu.
help: list the commands.


*Next goals*:
1.Graphical user interface, built on the existing client core so the networking and cryptography remain unchanged.
2.File transfer in group chats, including a rule for how export approval applies to each recipient.


*Limitations*:
1.The server can see metadata: which names connect, who invites whom, when, and how much data is sent.
2.Export approval records permission but does not prevent copying. A received file sits in temporary storage until it is exported or deleted, and the recipient can copy it in other ways.
3.Deleting temporary files does not guarantee that the data is erased from disk.
4.Identity private keys are stored without a passphrase in data/<name>/identity.json, so anyone with access to that folder can impersonate the user.
5.Without fingerprint verification, a malicious server can impersonate any registered name.
6.Restarting the server clears all registrations, invitations, and sessions.
7.Groups are fixed once formed. Members cannot join later, and if any member leaves, the group ends for everyone.
8.Every member of a group can read messages sent by the others.
9.Group size is limited to 20, and each member must complete one handshake and verification per other member.
10.File transfer and export are not available in group chats.
11.The protocol is custom and has not been audited.
12.The network policy limits traffic paths only. It does not inspect or protect message content.
13.The lab runs on a single Linux machine with Mininet and Open vSwitch, and it has not been tested on other platforms.
