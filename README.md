# Secure Messaging SDN — Group Chat Update

This bundle contains a group-capable SDN lab implementation using Mininet, Open vSwitch, OS-Ken, Flask and a small live dashboard.

**Group models:** `mesh` (default) and `server-relay`. Choose the mode that matches the messaging core; Mallory remains monitored and blocked in both.

See [`docs/GROUP_CHAT_INTEGRATION.md`](docs/GROUP_CHAT_INTEGRATION.md) for installation, launch order, API contracts, tests and team integration notes.

## Quick start

1. Install Ubuntu packages: `sudo apt install mininet openvswitch-switch python3-os-ken python3-flask -y`
2. Terminal 1: `cd sdn && python3 -u run_controller.py`
3. Terminal 2: `cd sdn && sudo mn -c && sudo python3 topology.py`
4. Terminal 3: `cd sdn && sudo python3 sdn_api.py`
5. Open `http://127.0.0.1:5000/dashboard`.

This is a controlled educational prototype. Keep the Flask control API on localhost and do not expose it to untrusted networks.
