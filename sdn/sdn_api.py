from flask import Flask, request, jsonify
import subprocess
import secrets
import ipaddress
import threading
import atexit
from datetime import datetime, timezone


app = Flask(__name__)

# ==========================================
# NETWORK CONFIGURATION
# ==========================================

BRIDGE = "s1"

SERVER_IP = "10.0.0.3"

# Fixed topology addresses
ALICE_IP = "10.0.0.1"
BOB_IP = "10.0.0.2"

# Session-specific cookie namespace
COOKIE_PREFIX = 0x534D000000000000
COOKIE_MASK = 0xFFFFFFFF00000000

# Store active sessions in RAM only
active_sessions = {}

lock = threading.RLock()


# ==========================================
# EVENT LOG
# ==========================================

events = []


def log_event(source, destination, status, message):

    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "destination": destination,
        "status": status,
        "message": message
    }

    events.append(event)

    # Keep only the latest 500 events
    if len(events) > 500:
        del events[:-500]


# ==========================================
# OPEN VSWITCH COMMAND FUNCTION
# ==========================================

def ovs_command(*args):

    result = subprocess.run(
        [
            "ovs-ofctl",
            "-O", "OpenFlow13",
            *args
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=10
    )

    return result.stdout


def check_bridge():

    subprocess.run(
        ["ovs-vsctl", "br-exists", BRIDGE],
        check=True,
        capture_output=True,
        text=True,
        timeout=5
    )


# ==========================================
# COOKIE MANAGEMENT
# ==========================================

def generate_cookie():

    return COOKIE_PREFIX | secrets.randbits(32)


def delete_session_flows(cookie):

    cookie_match = (
        f"cookie=0x{cookie:016x}/0xffffffffffffffff"
    )

    ovs_command(
        "del-flows",
        BRIDGE,
        cookie_match
    )


def cleanup_old_session_flows():

    cookie_match = (
        f"cookie=0x{COOKIE_PREFIX:016x}/"
        f"0x{COOKIE_MASK:016x}"
    )

    ovs_command(
        "del-flows",
        BRIDGE,
        cookie_match
    )


# ==========================================
# SESSION FLOW RULES
# ==========================================

def create_session_flows(cookie, alice_ip, bob_ip):

    # Port numbers:
    # Alice  = 1
    # Bob    = 2
    # Server = 3
    # Mallory = 4

    rules = [

        # Alice -> Bob
        (
            f"in_port=1,ip,nw_src={alice_ip},"
            f"nw_dst={bob_ip},actions=output:2"
        ),

        # Bob -> Alice
        (
            f"in_port=2,ip,nw_src={bob_ip},"
            f"nw_dst={alice_ip},actions=output:1"
        ),

        # Alice -> Server
        (
            f"in_port=1,ip,nw_src={alice_ip},"
            f"nw_dst={SERVER_IP},actions=output:3"
        ),

        # Server -> Alice
        (
            f"in_port=3,ip,nw_src={SERVER_IP},"
            f"nw_dst={alice_ip},actions=output:1"
        ),

        # Bob -> Server
        (
            f"in_port=2,ip,nw_src={bob_ip},"
            f"nw_dst={SERVER_IP},actions=output:3"
        ),

        # Server -> Bob
        (
            f"in_port=3,ip,nw_src={SERVER_IP},"
            f"nw_dst={bob_ip},actions=output:2"
        )
    ]

    installed = 0

    try:

        for rule in rules:

            flow = (
                f"cookie=0x{cookie:016x},"
                f"priority=200,{rule}"
            )

            ovs_command(
                "add-flow",
                BRIDGE,
                flow
            )

            installed += 1

    except Exception:

        # Roll back partially installed rules
        delete_session_flows(cookie)

        raise

    return installed


# ==========================================
# API 1: START SESSION
# ==========================================

@app.route("/session/start", methods=["POST"])
def start_session():

    data = request.get_json(silent=True) or {}

    session_id = data.get("session_id")
    alice_ip = data.get("alice_ip")
    bob_ip = data.get("bob_ip")

    # Validate session ID
    if (
        not isinstance(session_id, str)
        or not session_id.strip()
        or len(session_id) > 64
    ):

        return jsonify({
            "status": "error",
            "message": "Invalid session ID"
        }), 400

    # Only allow our configured participants
    try:

        alice_ip = str(ipaddress.ip_address(alice_ip))
        bob_ip = str(ipaddress.ip_address(bob_ip))

    except (ValueError, TypeError):

        return jsonify({
            "status": "error",
            "message": "Invalid IP address"
        }), 400

    if alice_ip != ALICE_IP or bob_ip != BOB_IP:

        return jsonify({
            "status": "error",
            "message": "Unauthorised participants"
        }), 403

    with lock:

        if session_id in active_sessions:

            return jsonify({
                "status": "error",
                "message": "Session already exists"
            }), 409

        cookie = generate_cookie()

        try:

            check_bridge()

            installed = create_session_flows(
                cookie,
                alice_ip,
                bob_ip
            )

            active_sessions[session_id] = {
                "cookie": cookie,
                "alice_ip": alice_ip,
                "bob_ip": bob_ip,
                "started_at": datetime.now(
                    timezone.utc
                ).isoformat()
            }

            log_event(
                "Alice",
                "Bob",
                "ALLOWED",
                "Session started"
            )

            return jsonify({

                "status": "success",
                "message": "Session started",
                "session_id": session_id,
                "rules_installed": installed

            }), 200

        except Exception as error:

            app.logger.exception("Session start failed")

            return jsonify({
                "status": "error",
                "message": str(error)
            }), 500


# ==========================================
# API 2: END SESSION
# ==========================================

@app.route("/session/end", methods=["POST"])
def end_session():

    data = request.get_json(silent=True) or {}

    session_id = data.get("session_id")

    if not isinstance(session_id, str) or not session_id.strip():

        return jsonify({
            "status": "error",
            "message": "Invalid session ID"
        }), 400

    with lock:

        session = active_sessions.get(session_id)

        if session is None:

            return jsonify({
                "status": "error",
                "message": "Session not found"
            }), 404

        try:

            delete_session_flows(session["cookie"])

            del active_sessions[session_id]

            log_event(
                "Alice",
                "Bob",
                "ENDED",
                "Session ended"
            )

            return jsonify({

                "status": "success",
                "message": "Session ended and rules removed",
                "session_id": session_id

            }), 200

        except Exception as error:

            app.logger.exception("Session end failed")

            return jsonify({
                "status": "error",
                "message": str(error)
            }), 500


# ==========================================
# API 3: HEALTH CHECK
# ==========================================

@app.route("/health", methods=["GET"])
def health():

    try:

        check_bridge()

        return jsonify({
            "status": "healthy",
            "bridge": BRIDGE,
            "active_sessions": len(active_sessions)
        })

    except Exception as error:

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 503


# ==========================================
# API 4: VIEW ACTIVE SESSIONS
# ==========================================

@app.route("/sessions", methods=["GET"])
def get_sessions():

    with lock:

        result = {}

        for session_id, details in active_sessions.items():

            result[session_id] = {
                "alice_ip": details["alice_ip"],
                "bob_ip": details["bob_ip"],
                "started_at": details["started_at"]
            }

        return jsonify(result)


# ==========================================
# API 5: VIEW EVENT LOG
# ==========================================

@app.route("/events", methods=["GET"])
def get_events():

    return jsonify(events)


# ==========================================
# CLEANUP ON NORMAL SHUTDOWN
# ==========================================

def shutdown_cleanup():

    for session_id, session in list(active_sessions.items()):

        try:

            delete_session_flows(session["cookie"])

            print("Cleaned session:", session_id)

        except Exception as error:

            print("Cleanup warning:", error)


atexit.register(shutdown_cleanup)


# ==========================================
# START FLASK SERVER
# ==========================================

if __name__ == "__main__":

    print("Starting Secure Messaging SDN API...")

    try:

        check_bridge()

        # Remove stale session rules from an earlier API run
        cleanup_old_session_flows()

    except Exception as error:

        print("Cannot initialise SDN API:", error)

        print("Start Mininet and its switch first.")

        raise SystemExit(1)

    print("Open vSwitch bridge:", BRIDGE)
    print("Flask API: http://127.0.0.1:5000")
    print("Session tracking: RAM only")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
