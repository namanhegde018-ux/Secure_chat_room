# SDN group-chat implementation and integration guide

## Architecture choice

This version supports **two group communication modes**. The default `mesh` mode allows direct member-to-member IPv4 paths and also allows member↔Server signaling. The optional `server-relay` mode allows members to communicate only through the Server (10.0.0.3), which must forward group messages. The SDN API accepts either mode in the `/session/start` request. The project design describes direct peer communication when connectivity permits, with relay fallback when needed.

This is a network access-control layer, not group encryption. Name 2's cryptographic layer must continue to provide end-to-end/application-level encryption and authenticate group members.

## Fixed Mininet host and switch-port map

The link creation order in `sdn/topology.py` is deliberate:

| Switch port | Host | IP | Role |
|---:|---|---|---|
| 1 | Alice | 10.0.0.1 | Group member |
| 2 | Bob | 10.0.0.2 | Group member |
| 3 | Server | 10.0.0.3 | Signaling endpoint / optional group relay |
| 4 | Mallory | 10.0.0.4 | Unauthorised test host |
| 5 | Charlie | 10.0.0.5 | Group member |
| 6 | David | 10.0.0.6 | Group member |

Do not reorder the `HOSTS` or link creation list without updating the controller's port constants and API's `GROUP_MEMBERS` map.

## Files

- `sdn/topology.py`: creates the six-host Mininet topology and remote OpenFlow controller connection.
- `sdn/sdn_controller.py`: installs base default-deny, Mallory-monitoring and trusted-host ARP rules; reports blocked attempts to Flask.
- `sdn/run_controller.py`: starts the OS-Ken OpenFlow handler and the project controller application.
- `sdn/sdn_api.py`: exposes session APIs and installs/removes cookie-tagged group flows using `ovs-ofctl`.
- `dashboard/templates/index.html`: dashboard for active group sessions and retained events.

## Install packages on Ubuntu

```bash
sudo apt update
sudo apt install mininet openvswitch-switch python3-os-ken python3-flask -y
```

## Start order (three terminals)

Terminal 1 — controller:

```bash
cd ~/Desktop/Secure_chat_room/sdn
python3 -u run_controller.py
```

Look for `[LOAD] SecureMessagingController instantiated`.

Terminal 2 — Mininet:

```bash
cd ~/Desktop/Secure_chat_room/sdn
sudo mn -c
sudo python3 topology.py
```

Inside `mininet>`:

```text
sh ovs-vsctl show
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected base rules: priority 600 Mallory-monitor rules, priority 300 trusted ARP rules, priority 0 table-miss/controller rule. The switch should show `is_connected: true`.

Terminal 3 — API:

```bash
cd ~/Desktop/Secure_chat_room/sdn
sudo python3 sdn_api.py
```

Start Flask only after bridge `s1` exists. The API binds to `127.0.0.1:5000` by default.

Open `http://127.0.0.1:5000/dashboard` in the Ubuntu browser.

## API contract

### Start a group session

```http
POST /session/start
Content-Type: application/json
```

```json
{
  "session_id": "group-001",
  "mode": "mesh",
  "participants": [
    {"name": "Alice", "ip": "10.0.0.1"},
    {"name": "Bob", "ip": "10.0.0.2"},
    {"name": "Charlie", "ip": "10.0.0.5"}
  ]
}
```

The default mode is `mesh`. For three members plus Server, it installs 12 directed IPv4 flow rules (each endpoint can send to each of the other three endpoints). To use a relay server instead, add `"mode":"server-relay"`; that mode installs 6 rules for three members (member→Server and Server→member).

For compatibility with the original team's two-person contract, this is also accepted:

```json
{"session_id":"session-legacy","alice_ip":"10.0.0.1","bob_ip":"10.0.0.2"}
```

### End a group session

```http
POST /session/end
Content-Type: application/json
```

```json
{"session_id":"group-001"}
```

### Other endpoints

- `GET /health`
- `GET /sessions`
- `GET /events`
- `POST /internal/event` (controller-to-Flask local event endpoint)

## Manual verification script

Use a fourth terminal (Ubuntu host shell, not the `mininet>` prompt) for curl commands.

```bash
curl http://127.0.0.1:5000/health

curl -X POST http://127.0.0.1:5000/session/start \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"group-001","participants":[{"name":"Alice","ip":"10.0.0.1"},{"name":"Bob","ip":"10.0.0.2"},{"name":"Charlie","ip":"10.0.0.5"}]}'

curl http://127.0.0.1:5000/sessions
```

While the session is active in `mesh` mode, test from the Mininet prompt:

```text
alice ping -c 3 10.0.0.2
alice ping -c 3 10.0.0.5
bob ping -c 3 10.0.0.3
charlie ping -c 3 10.0.0.1
mallory ping -c 3 10.0.0.3
```

Expected: authorised members can reach other session members and Server; Mallory does not. If you choose `server-relay`, participant-to-participant ping is intentionally not authorised; test member→Server and Server→member instead. These ping checks validate network flows, not the messaging application's actual group-delivery logic.

End the group:

```bash
curl -X POST http://127.0.0.1:5000/session/end \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"group-001"}'
```

After ending, repeat a member→Server ping; it should fail. Verify cookies and flow rules:

```text
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

The fixed base rules should remain, while the ended session's cookie-tagged rules should be gone.

## Integration with Name 1 (messaging core)

For the original one-to-one flow, Name 1 can continue calling:

```json
{"session_id":"...","alice_ip":"10.0.0.1","bob_ip":"10.0.0.2"}
```

This legacy form uses `mesh` mode by default. For group chat, call `/session/start` with a `participants` array and choose `mode: "mesh"` or `mode: "server-relay"`. On session termination, call `/session/end` with the same `session_id`. Coordinate the mode with Name 1: it must match whether their messaging core uses direct peer links or a relay Server.

The Flask API is bound to loopback (`127.0.0.1`) for lab safety. The client core must run in the Ubuntu host network namespace to use that address. If the client runs inside a Mininet host namespace or on another computer, `127.0.0.1` will refer to that client itself; a controlled management path, authenticated API endpoint, and firewall rule must be designed before changing the bind address. Do not expose this unauthenticated control API to a public or campus network.

## Integration with Name 2 (crypto/GUI)

The SDN layer authorises the network path only. It does not replace X25519, AEAD encryption, peer fingerprint verification, message authentication or replay protection. For `server-relay` mode, the Server should forward encrypted application payloads without decrypting them if the project architecture requires end-to-end confidentiality.

## Limitations to state in the report

- The topology is a controlled Mininet lab, not a public-Internet SDN deployment.
- The API uses a fixed allowlist and fixed port mapping for this demonstration.
- Session state and dashboard events are RAM-only; they disappear when Flask restarts.
- `atexit` cleanup runs on normal API shutdown, not after `kill -9` or power loss. On API startup, stale flows with this project's cookie prefix are removed, provided the bridge already exists.
- For `server-relay` mode, the Server must implement actual group message relay. In `mesh` mode, clients must implement direct group message delivery. SDN flows alone do not distribute messages.
- The controller reports traffic that matches the Mallory monitoring flows. It is not a general-purpose intrusion-detection system.
- The API is an unauthenticated local prototype; production integration requires authentication, authorization, TLS, input hardening and a restricted management network.
- The fixed IP/port rules are not cryptographic identity. IP/MAC spoofing and compromised endpoints require additional controls.
