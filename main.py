#!/usr/bin/env python3
"""Secure messenger: starts the signaling server if needed, then a text menu.

Usage (from the project root):
  $PY main.py                  start the server if needed, then the menu
  $PY main.py --server         run the server in the foreground
  $PY main.py --host 10.0.0.1  connect to a server at another address
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"
DATA_DIR = ROOT / "data"
RUNTIME_DIR = ROOT / "runtime"
ACCOUNTS_FILE = DATA_DIR / "accounts.json"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
LOCAL_HOSTS = {"127.0.0.1", "localhost"}
DEFAULT_PORT = int(os.environ.get("SIGNAL_PORT", "9000"))
SERVER_COMMAND = [sys.executable, "-m", "signaling_server.server"]

sys.path.insert(0, str(SRC_DIR))
from client_core import ClientCore  # noqa: E402
from client_core.crypto import Identity  # noqa: E402

EVENTS = (
    "connected", "disconnected", "connection_error", "registered",
    "invitation", "invite_sent", "invitation_accepted", "invitation_rejected",
    "invitation_cancelled", "invitation_expired",
    "session_started", "session_ready", "session_ended", "session_expired",
    "secure_session_established", "handshake_failed", "peer_verified",
    "peer_key_changed", "message", "message_rejected", "error",
    "file_sent", "file_receive_started", "file_received",
    "file_transfer_error", "file_transfer_aborted",
    "export_request_sent", "export_requested", "export_decided",
    "export_approved", "export_rejected", "file_exported", "export_error",
)

HELP = """Commands:
  fp                           show your fingerprint
  invite <name> [name ...]     invite one or more people to a group
  accept <invitation_id>       accept an invitation
  reject <invitation_id>       reject an invitation
  verify <name> <fingerprint>  confirm a peer's fingerprint (compare out of band)
  msg <text>                   send a message to the group
  file <path>                  send a file (one-to-one chats only)
  files                        list sent and received files with their ids
  reqexport <id>               ask the sender to allow a copy of a received file
  approve <id> | deny <id>     (sender) allow or refuse a requested copy
  export <id>                  save an approved file to your downloads folder
  end                          end the chat
  disconnect                   leave and return to the menu
  help                         show this list"""


class UsageError(Exception):
    pass


def say(text=""):
    print(text, flush=True)


def ask(prompt):
    return input(prompt).strip()


def run(future, timeout=10):
    """Wait for a ClientCore command. Commands that return None are accepted."""
    return future.result(timeout=timeout) if future is not None else None


def track(future, label):
    """Report a background ClientCore command's failure without blocking the prompt."""
    def done(f):
        if f.cancelled():
            return
        exc = f.exception()
        if exc is not None:
            say(f"[{label} error] {exc}")
    if future is not None:
        future.add_done_callback(done)


def need(words, count, usage):
    if len(words) < count:
        raise UsageError(usage)


def _tid(p):
    return p.get("transfer_id") or p.get("tid") or "?"


def _fname(p):
    return p.get("name") or p.get("filename") or "file"


# ---------- accounts (local to this machine; the server keeps no accounts) ----------

def load_accounts():
    if not ACCOUNTS_FILE.exists():
        return {}
    return json.loads(ACCOUNTS_FILE.read_text(encoding="utf-8"))


def save_accounts(accounts):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = ACCOUNTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(accounts, indent=2), encoding="utf-8")
    tmp.replace(ACCOUNTS_FILE)


def user_paths(name):
    base = DATA_DIR / name
    return {
        "identity": base / "identity.json",
        "trust": base / "trust.json",
        "downloads": base / "downloads",
    }


def register_flow():
    name = ask("New name (letters, digits, _ . -): ")
    if not NAME_PATTERN.match(name):
        say("invalid name")
        return
    accounts = load_accounts()
    if name in accounts:
        say(f"'{name}' is already registered. Choose Connect.")
        return
    paths = user_paths(name)
    paths["downloads"].mkdir(parents=True, exist_ok=True)
    identity = Identity.load_or_create(str(paths["identity"]))
    accounts[name] = {"registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    save_accounts(accounts)
    say(f"registered '{name}'. Your fingerprint: {identity.fingerprint}")


def connect_flow(host, port):
    name = ask("Your name: ")
    if name not in load_accounts():
        say(f"'{name}' is not registered. Choose Register first.")
        return
    chat(name, host, port)


# ---------- chat session ----------

class Chat:
    def __init__(self, core, me):
        self.core = core
        self.me = me
        self.known_fp = {}   # peer -> fingerprint reported by the secure channel
        self.group_size = 0  # number of members in the current session

    def on_event(self, event, p):
        handler = getattr(self, f"_ev_{event}", None)
        if handler is None:
            say(f"[{event}] {p}")
        else:
            handler(p)

    def _reset_session(self):
        self.known_fp.clear()
        self.group_size = 0

    def _peer_name(self, p):
        return p.get("from") or p.get("peer") or "the other person"

    # connection and invitations

    def _ev_connected(self, p):
        say("[connected] server reachable")

    def _ev_disconnected(self, p):
        say("[disconnected]")

    def _ev_connection_error(self, p):
        say(f"[connection error] {p.get('message', p)}")

    def _ev_registered(self, p):
        say(f"[online] signed in as {p.get('client_id', self.me)}")

    def _ev_invitation(self, p):
        group = ", ".join(map(str, p.get("group", [])))
        say(f"[invitation] from {p.get('from')} to group: {group}")
        say(f"  accept {p.get('invitation_id')}   or   reject {p.get('invitation_id')}"
            f"   (expires in {p.get('ttl')}s)")

    def _ev_invite_sent(self, p):
        say(f"[invite sent] to {p.get('to')} (id {p.get('invitation_id')})")

    def _ev_invitation_accepted(self, p):
        say(f"[accepted] {p.get('by')} accepted invitation {p.get('invitation_id')}")

    def _ev_invitation_rejected(self, p):
        say(f"[rejected] {p.get('by')} declined. The whole group invitation is cancelled.")

    def _ev_invitation_cancelled(self, p):
        say(f"[invitation cancelled] reason: {p.get('reason')}")

    def _ev_invitation_expired(self, p):
        say("[invitation expired]")

    # session and verification

    def _ev_session_started(self, p):
        members = list(p.get("members", []))
        self.group_size = len(members)
        say(f"[group formed] members: {', '.join(map(str, members))}")
        say("[info] setting up a secure channel with each member...")

    def _ev_secure_session_established(self, p):
        peer = p.get("peer")
        fp = p.get("peer_fingerprint")
        self.known_fp[peer] = fp
        if p.get("verified"):
            say(f"[secure] channel with {peer} is verified")
        else:
            say(f"[secure] channel with {peer} established.")
            say(f"  {peer}'s fingerprint: {fp}")
            say(f"  Compare it with {peer}'s own 'fp' output, then type: verify {peer} <fingerprint>")

    def _ev_session_ready(self, p):
        say("[ready] all channels are up. Messages are sent once every peer is verified.")

    def _ev_session_ended(self, p):
        say(f"[session ended] reason: {p.get('reason')}")
        self._reset_session()

    def _ev_session_expired(self, p):
        say(f"[session expired] reason: {p.get('reason')}")
        self._reset_session()

    def _ev_handshake_failed(self, p):
        say(f"[handshake failed] with {p.get('peer')}: {p.get('reason', '')}")

    def _ev_peer_verified(self, p):
        say(f"[verified] {p.get('peer')}")

    def _ev_peer_key_changed(self, p):
        say(f"[WARNING] the key for {p.get('peer')} changed. Do not continue until you "
            "confirm with that person out of band.")

    # messages

    def _ev_message(self, p):
        body = p.get("body") or {}
        text = body.get("text", body) if isinstance(body, dict) else body
        say(f"[{p.get('from')}] {text}")

    def _ev_message_rejected(self, p):
        say(f"[message from {p.get('from')} rejected] {p.get('reason')}")

    def _ev_error(self, p):
        say(f"[error] {p.get('message', p)}")

    # files and export approval (one-to-one only)

    def _ev_file_sent(self, p):
        say(f"[file sent] '{_fname(p)}' (transfer {_tid(p)}). Waiting for the other person.")

    def _ev_file_receive_started(self, p):
        size = p.get("size")
        say(f"[receiving] '{_fname(p)}'" + (f" ({size} bytes)" if size is not None else ""))

    def _ev_file_received(self, p):
        tid = _tid(p)
        say(f"[file received] '{_fname(p)}' is stored temporarily. transfer id: {tid}")
        say(f"  To keep a copy, ask the sender:  reqexport {tid}")

    def _ev_file_transfer_error(self, p):
        say(f"[file error] {p.get('message') or p.get('reason') or p}")

    def _ev_file_transfer_aborted(self, p):
        say(f"[file aborted] transfer {_tid(p)}: {p.get('reason', 'unknown reason')}")

    def _ev_export_request_sent(self, p):
        say(f"[export requested] waiting for the sender to approve transfer {_tid(p)}")

    def _ev_export_requested(self, p):
        tid = _tid(p)
        say(f"[export request] {self._peer_name(p)} wants a copy of '{_fname(p)}' (transfer {tid})")
        say(f"  approve {tid}   or   deny {tid}")

    def _ev_export_decided(self, p):
        verb = "approved" if p.get("approved") else "refused"
        say(f"[export decision] you {verb} transfer {_tid(p)}")

    def _ev_export_approved(self, p):
        say(f"[export approved] transfer {_tid(p)}. To save a copy, run:  export {_tid(p)}")

    def _ev_export_rejected(self, p):
        say(f"[export refused] the sender did not allow a copy of transfer {_tid(p)}")

    def _ev_file_exported(self, p):
        say(f"[saved] copy written to {p.get('path', '(path not reported)')}")

    def _ev_export_error(self, p):
        say(f"[export error] {p.get('message') or p.get('reason') or p}")

    # commands

    def _verify(self, peer, typed):
        expected = self.known_fp.get(peer)
        if expected is None:
            say(f"[error] no secure channel with {peer} yet, so there is no fingerprint to check")
            return
        if typed.upper() != expected.replace(" ", "").upper():
            say(f"[not verified] that does not match {peer}'s fingerprint. "
                f"Copy it again from {peer}'s 'fp' output.")
            return
        if self.core.verify_peer(peer, expected):
            say(f"[verified] {peer}")
        else:
            say(f"[error] could not record verification for {peer}")

    def _require_one_to_one(self):
        if self.group_size > 2:
            raise RuntimeError("file sharing is only available in one-to-one chats")

    def _list_files(self):
        for label, attr in (("sent", "sent_files"), ("received", "received_files")):
            items = getattr(self.core, attr, None) or []
            if isinstance(items, dict):
                items = list(items.items())
            if not items:
                say(f"{label}: none")
                continue
            say(f"{label}:")
            for item in items:
                say(f"  {item}")

    def handle(self, line):
        """Run one command. Returns False when the user wants to leave the chat."""
        head, _, rest = line.strip().partition(" ")
        cmd, rest = head.lower(), rest.strip()
        words = rest.split()
        try:
            if not cmd:
                return True
            if cmd == "help":
                say(HELP)
            elif cmd == "fp":
                say(f"your fingerprint: {self.core.fingerprint}")
            elif cmd == "invite":
                need(words, 1, "invite <name> [name ...]")
                run(self.core.invite(words))
            elif cmd == "accept":
                need(words, 1, "accept <invitation_id>")
                run(self.core.accept_invitation(words[0]))
            elif cmd == "reject":
                need(words, 1, "reject <invitation_id>")
                run(self.core.reject_invitation(words[0]))
            elif cmd == "verify":
                need(words, 2, "verify <name> <fingerprint>")
                self._verify(words[0], "".join(words[1:]))
            elif cmd == "msg":
                if not rest:
                    raise UsageError("msg <text>")
                run(self.core.send_message({"kind": "text", "text": rest}))
            elif cmd == "file":
                if not rest:
                    raise UsageError("file <path>")
                self._require_one_to_one()
                path = Path(os.path.expanduser(rest.strip().strip("'\""))).resolve()
                if not path.is_file():
                    say(f"no such file: {path}")
                else:
                    track(self.core.send_file(str(path)), "file")
            elif cmd == "files":
                self._list_files()
            elif cmd == "reqexport":
                need(words, 1, "reqexport <transfer_id>")
                self._require_one_to_one()
                track(self.core.request_export(words[0]), "export request")
            elif cmd in ("approve", "deny"):
                need(words, 1, f"{cmd} <transfer_id>")
                track(self.core.respond_export(words[0], cmd == "approve"), "export decision")
            elif cmd == "export":
                need(words, 1, "export <transfer_id>")
                track(self.core.export_file(words[0]), "export")
            elif cmd == "end":
                run(self.core.end_session())
            elif cmd == "disconnect":
                return False
            else:
                say(f"unknown command '{cmd}'. Type help.")
        except UsageError as exc:
            say(f"usage: {exc}")
        except Exception as exc:
            say(f"[error] {exc}")
        return True


class EventPump(threading.Thread):
    """Delivers queued ClientCore events to the listeners in Chat."""

    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self._stop = threading.Event()
        self._reported = False

    def run(self):
        while not self._stop.is_set():
            try:
                self.core.drain_events(50)
            except Exception as exc:
                if not self._reported:
                    self._reported = True
                    say(f"[error] event delivery failed: {exc}")
            time.sleep(0.05)

    def stop(self):
        self._stop.set()


def make_listener(event, session):
    def listener(*args):
        payload = args[-1] if args else {}
        if not isinstance(payload, dict):
            payload = {"value": payload}
        session.on_event(event, payload)
    return listener


def close_core(core):
    for step in (core.disconnect, core.shutdown):
        try:
            run(step(), timeout=5)
        except Exception:
            pass


def chat(name, host, port):
    paths = user_paths(name)
    paths["downloads"].mkdir(parents=True, exist_ok=True)
    core = ClientCore(
        host, port, name,
        identity_path=str(paths["identity"]),
        trust_path=str(paths["trust"]),
        download_dir=str(paths["downloads"]),
    )
    session = Chat(core, name)
    for event in EVENTS:
        core.on(event, make_listener(event, session))

    pump = EventPump(core)
    pump.start()
    try:
        run(core.connect(), timeout=20)
    except Exception as exc:
        pump.stop()
        say(f"[error] could not connect to {host}:{port}: {exc}")
        close_core(core)
        return

    say(f"connected as {name}. Type 'help' for commands, 'disconnect' to leave.")
    try:
        while session.handle(input(f"{name}> ")):
            pass
    except (EOFError, KeyboardInterrupt):
        say()
    finally:
        pump.stop()
        close_core(core)
    say("disconnected")


# ---------- server ----------

def server_env(host, port):
    env = dict(os.environ)
    env["SIGNAL_HOST"] = host
    env["SIGNAL_PORT"] = str(port)
    return env


def port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def start_local_server(port):
    """Start the server in the background unless one is already listening.
    The server keeps running after this app quits; stop it with: fuser -k 9000/tcp"""
    if port_open("127.0.0.1", port):
        say(f"server already running on 127.0.0.1:{port}")
        return
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    log_file = open(RUNTIME_DIR / "server.log", "a", encoding="utf-8")
    subprocess.Popen(
        SERVER_COMMAND,
        cwd=SRC_DIR,
        env=server_env("127.0.0.1", port),
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    for _ in range(50):
        if port_open("127.0.0.1", port):
            say(f"server started on 127.0.0.1:{port} (log: runtime/server.log)")
            return
        time.sleep(0.1)
    raise SystemExit("server did not start; see runtime/server.log")


def run_server_foreground(port):
    say(f"server listening on 0.0.0.0:{port}. Press Ctrl+C to stop.")
    try:
        subprocess.call(SERVER_COMMAND, cwd=SRC_DIR, env=server_env("0.0.0.0", port))
    except KeyboardInterrupt:
        pass


# ---------- menu ----------

def menu(host, port):
    while True:
        say("\n=== Secure Messenger ===")
        say("1) Connect")
        say("2) Register")
        say("3) Quit")
        choice = ask("> ")
        if choice == "1":
            connect_flow(host, port)
        elif choice == "2":
            register_flow()
        elif choice == "3":
            return
        else:
            say("choose 1, 2 or 3")


def main():
    parser = argparse.ArgumentParser(description="Secure messenger")
    parser.add_argument("--host", default="127.0.0.1", help="signaling server address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--server", action="store_true",
                        help="run the signaling server in the foreground")
    args = parser.parse_args()

    if args.server:
        run_server_foreground(args.port)
        return

    if args.host in LOCAL_HOSTS:
        start_local_server(args.port)
    elif not port_open(args.host, args.port):
        say(f"warning: no server answering at {args.host}:{args.port}")

    try:
        menu(args.host, args.port)
    except (EOFError, KeyboardInterrupt):
        say()
    say("bye")


if __name__ == "__main__":
    main()