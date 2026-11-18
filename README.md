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



PROJECT=/home/naman-hegde/Desktop/Programs/Computer_Networks/Secure_chat_room


cd $PROJECT
rm -f sdn/sdn_api.py src/client_core/demo_server.py
cd sdn
.venv-sdn/bin/pip install os-ken cryptography
.venv-sdn/bin/python -c "import os_ken, mininet, cryptography; print('ok')"
sudo mn -c

cd $PROJECT/sdn
.venv-sdn/bin/python run_controller.py

cd $PROJECT/sdn
sudo .venv-sdn/bin/python topology.py --clients 3

mininet> xterm server h1 h2 h3

export PY=/home/naman-hegde/Desktop/Programs/Computer_Networks/Secure_chat_room/sdn/.venv-sdn/bin/python
cd /home/naman-hegde/Desktop/Programs/Computer_Networks/Secure_chat_room
$PY main.py --server

export PY=/home/naman-hegde/Desktop/Programs/Computer_Networks/Secure_chat_room/sdn/.venv-sdn/bin/python
cd /home/naman-hegde/Desktop/Programs/Computer_Networks/Secure_chat_room
$PY main.py --host 10.0.0.1