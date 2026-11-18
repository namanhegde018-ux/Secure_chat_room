"""Flask API for group-session SDN flow management.

Supports direct mesh group flows or an optional Server-relay mode. Select the
mode in POST /session/start; direct mesh is the default. API/session state is
kept in RAM and the control API binds to loopback for the lab VM.
"""

from __future__ import annotations

import atexit
import ipaddress
import itertools
import secrets
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
app = Flask(
    __name__,
    template_folder=str(PROJECT_DIR / "dashboard" / "templates"),
    static_folder=str(PROJECT_DIR / "dashboard" / "static"),
)

BRIDGE = "s1"
SERVER_NAME = "Server"
SERVER_IP = "10.0.0.3"
SERVER_PORT = 3

# The values must match topology.py and the fixed Mininet link/port order.
GROUP_MEMBERS = {
    "Alice": {"ip": "10.0.0.1", "port": 1},
    "Bob": {"ip": "10.0.0.2", "port": 2},
    "Charlie": {"ip": "10.0.0.5", "port": 5},
    "David": {"ip": "10.0.0.6", "port": 6},
}
NAME_BY_IP = {details["ip"]: name for name, details in GROUP_MEMBERS.items()}

# Project-specific cookie namespace. Upper 32 bits identify our session flows.
COOKIE_PREFIX = 0x534D000000000000
COOKIE_MASK = 0xFFFFFFFF00000000

# Session priorities are unique, allowing overlapping group sessions to share
# participant/server matches. The forwarding action is the same for each.
_priority_counter = itertools.count(1001)

# RAM-only state, as required by the project design.
active_sessions: dict[str, dict] = {}
events = deque(maxlen=500)
state_lock = threading.RLock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(source: str, destination: str, status: str, message: str) -> None:
    with state_lock:
        events.append({
            "time": utc_now(),
            "source": source[:80],
            "destination": destination[:80],
            "status": status,
            "message": message[:240],
        })


def ovs_command(*args: str) -> str:
    """Run ovs-ofctl and raise an informative exception on failure."""
    result = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", *args],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return result.stdout


def check_bridge() -> None:
    subprocess.run(
        ["ovs-vsctl", "br-exists", BRIDGE],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )


def generate_cookie() -> int:
    return COOKIE_PREFIX | secrets.randbits(32)


def delete_session_flows(cookie: int) -> None:
    # A full 64-bit mask deletes only flows with this exact session cookie.
    selector = f"cookie=0x{cookie:016x}/0xffffffffffffffff"
    ovs_command("del-flows", BRIDGE, selector)


def cleanup_old_session_flows() -> None:
    # Called once when the API starts, after Mininet has created bridge s1.
    selector = f"cookie=0x{COOKIE_PREFIX:016x}/0x{COOKIE_MASK:016x}"
    ovs_command("del-flows", BRIDGE, selector)


def resolve_participants(data: dict) -> list[dict]:
    """Accept group format and the original Alice/Bob API contract."""
    raw = data.get("participants")

    # Backward compatibility with the team's original API:
    # {session_id, alice_ip, bob_ip}
    if raw is None and "alice_ip" in data and "bob_ip" in data:
        raw = [
            {"name": "Alice", "ip": data.get("alice_ip")},
            {"name": "Bob", "ip": data.get("bob_ip")},
        ]

    if not isinstance(raw, list):
        raise ValueError("participants must be a list (at least two members)")
    if not 2 <= len(raw) <= len(GROUP_MEMBERS):
        raise ValueError(f"group must contain 2 to {len(GROUP_MEMBERS)} participants")

    resolved = []
    seen_names = set()
    seen_ips = set()

    for item in raw:
        if isinstance(item, str):
            name = item
            supplied_ip = None
        elif isinstance(item, dict):
            name = item.get("name")
            supplied_ip = item.get("ip")
        else:
            raise ValueError("each participant must be a name or an object with name and ip")

        if not isinstance(name, str) or name not in GROUP_MEMBERS:
            raise ValueError(f"unknown or unauthorised group member: {name!r}")

        member = GROUP_MEMBERS[name]
        if supplied_ip is not None:
            try:
                canonical_ip = str(ipaddress.ip_address(supplied_ip))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"invalid IP address for {name}") from exc
            if canonical_ip != member["ip"]:
                raise ValueError(f"IP address does not match configured host {name}")

        if name in seen_names or member["ip"] in seen_ips:
            raise ValueError(f"duplicate participant: {name}")

        seen_names.add(name)
        seen_ips.add(member["ip"])
        resolved.append({
            "name": name,
            "ip": member["ip"],
            "port": member["port"],
        })

    if data.get("server_ip") not in (None, SERVER_IP):
        raise ValueError("server_ip must match the configured messaging server")

    return resolved


def build_session_flow_specs(participants: list[dict], priority: int, mode: str) -> list[str]:
    """Build cookie-tagged IPv4 rules for a group session.

    mesh: every group member can reach every other member; Server is also
          reachable for signaling/control traffic.
    server-relay: members communicate only with Server; Server relays messages.
    """
    server = {"name": SERVER_NAME, "ip": SERVER_IP, "port": SERVER_PORT}
    endpoints = participants + [server]
    specs = []

    if mode == "server-relay":
        pairs = []
        for member in participants:
            pairs.append((member, server))
            pairs.append((server, member))
    else:  # mode == "mesh"
        pairs = [
            (source, destination)
            for source in endpoints
            for destination in endpoints
            if source["port"] != destination["port"]
        ]

    for source, destination in pairs:
        specs.append(
            f"priority={priority},in_port={source['port']},ip,"
            f"nw_src={source['ip']},nw_dst={destination['ip']},"
            f"actions=output:{destination['port']}"
        )
    return specs


def install_session_flows(cookie: int, priority: int, participants: list[dict], mode: str) -> int:
    installed = 0
    try:
        for spec in build_session_flow_specs(participants, priority, mode):
            flow = f"cookie=0x{cookie:016x},table=0,{spec}"
            ovs_command("add-flow", BRIDGE, flow)
            installed += 1
    except Exception:
        # Do not leave a partially installed group policy behind.
        try:
            delete_session_flows(cookie)
        except Exception:
            app.logger.exception("Rollback failed for cookie 0x%016x", cookie)
        raise
    return installed


@app.get("/health")
def health():
    try:
        check_bridge()
        return jsonify({
            "status": "healthy",
            "bridge": BRIDGE,
            "active_sessions": len(active_sessions),
        })
    except Exception as exc:
        app.logger.exception("Health check failed")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/")
@app.get("/dashboard")
def dashboard():
    return render_template("index.html")


@app.post("/session/start")
def start_session():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")

    if not isinstance(session_id, str) or not session_id.strip() or len(session_id) > 64:
        return jsonify({"status": "error", "message": "session_id must be 1-64 characters"}), 400

    try:
        participants = resolve_participants(data)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    mode = data.get("mode", "mesh")
    if mode not in ("mesh", "server-relay"):
        return jsonify({
            "status": "error",
            "message": "mode must be 'mesh' or 'server-relay'",
        }), 400

    names = [member["name"] for member in participants]
    with state_lock:
        if session_id in active_sessions:
            return jsonify({"status": "error", "message": "session already exists"}), 409

        cookie = generate_cookie()
        priority = next(_priority_counter)
        if priority > 60000:
            return jsonify({"status": "error", "message": "session priority capacity reached; restart API after ending sessions"}), 503

        try:
            check_bridge()
            installed = install_session_flows(cookie, priority, participants, mode)
        except Exception as exc:
            app.logger.exception("Could not install group session flows")
            return jsonify({"status": "error", "message": f"could not install session flows: {exc}"}), 500

        active_sessions[session_id] = {
            "cookie": cookie,
            "priority": priority,
            "participants": participants,
            "mode": mode,
            "started_at": utc_now(),
        }

        group_label = ", ".join(names)
        log_event("SDN API", group_label, "ALLOWED", f"Group session started; mode={mode}")

    return jsonify({
        "status": "success",
        "message": "Group session started",
        "session_id": session_id,
        "mode": mode,
        "participants": names,
        "rules_installed": installed,
        "server_ip": SERVER_IP,
    }), 200


@app.post("/session/end")
def end_session():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        return jsonify({"status": "error", "message": "invalid session_id"}), 400

    with state_lock:
        session = active_sessions.get(session_id)
        if session is None:
            return jsonify({"status": "error", "message": "session not found"}), 404

        try:
            delete_session_flows(session["cookie"])
        except Exception as exc:
            app.logger.exception("Could not delete group session flows")
            return jsonify({"status": "error", "message": f"could not remove session flows: {exc}"}), 500

        del active_sessions[session_id]
        group_label = ", ".join(member["name"] for member in session["participants"])
        log_event("SDN API", group_label, "ENDED", "Group session ended; session flows removed")

    return jsonify({
        "status": "success",
        "message": "Group session ended and session rules removed",
        "session_id": session_id,
    }), 200


@app.get("/sessions")
def get_sessions():
    with state_lock:
        safe_sessions = {}
        for session_id, session in active_sessions.items():
            safe_sessions[session_id] = {
                "participants": [member["name"] for member in session["participants"]],
                "participant_ips": [member["ip"] for member in session["participants"]],
                "server_ip": SERVER_IP,
                "mode": session["mode"],
                "started_at": session["started_at"],
            }
    return jsonify(safe_sessions)


@app.post("/internal/event")
def receive_controller_event():
    data = request.get_json(silent=True) or {}
    source = data.get("source", "Unknown")
    destination = data.get("destination", "Unknown")
    status = data.get("status")
    message = data.get("message", "")

    if status not in ("BLOCKED", "ALLOWED"):
        return jsonify({"status": "error", "message": "status must be BLOCKED or ALLOWED"}), 400
    if not all(isinstance(value, str) for value in (source, destination, message)):
        return jsonify({"status": "error", "message": "event fields must be strings"}), 400

    log_event(source, destination, status, message)
    return jsonify({"status": "success", "message": "event recorded"}), 200


@app.get("/events")
def get_events():
    with state_lock:
        return jsonify(list(events))


def shutdown_cleanup():
    # Best-effort cleanup on normal API shutdown. A hard kill/power loss cannot
    # execute atexit; the next API startup clears this project's cookie range.
    with state_lock:
        sessions = list(active_sessions.items())
    for session_id, session in sessions:
        try:
            delete_session_flows(session["cookie"])
            print(f"[CLEANUP] Removed SDN rules for {session_id}", flush=True)
        except Exception as exc:
            print(f"[CLEANUP WARNING] {session_id}: {exc}", flush=True)


atexit.register(shutdown_cleanup)


def main():
    print("Starting Secure Messaging Group SDN API...", flush=True)
    try:
        check_bridge()
        cleanup_old_session_flows()
    except Exception as exc:
        raise SystemExit(
            f"Cannot initialise SDN API: {exc}. Start OS-Ken and Mininet first."
        )

    host = "127.0.0.1"  # Keep control API local to the trusted VM by default.
    port = 5000
    print(f"Bridge: {BRIDGE}", flush=True)
    print(f"API: http://{host}:{port}", flush=True)
    print("Session state: RAM only", flush=True)
    print("Group modes: mesh (default) or server-relay", flush=True)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
