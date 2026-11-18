"""
Interactive two-client test harness. Run from src/:

    python demo_client.py alice
    python demo_client.py bob

Not part of the client_core package.
"""
import os
import queue
import sys
import threading
import traceback 
from core import ClientCore 

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

EVENTS = [
    "connected", "disconnected", "connection_error", "registered",
    "invitation", "invite_sent", "invitation_rejected", "invitation_cancelled",
    "invitation_expired", "session_started", "session_ended", "session_expired",
    "session_state_changed", "message", "error", "file_receive_started",
    "file_progress", "file_sent", "file_received", "file_transfer_error",
    "file_transfer_aborted", "secure_session_established", "handshake_failed",
    "peer_key_changed", "peer_verified", "peer_key_forgotten", "message_rejected",
    "protocol_message", "export_request_sent", "export_requested", "export_decided",
    "export_approved", "export_rejected", "file_exported", "export_error",
]

HELP = """commands:
  connect | disconnect | quit
  invite <peer> [peer ...]     invite several people to one group | accept <inv_id> | reject <inv_id>
  msg <text> | file <path> | end
  fp                           show my fingerprint
  verify <peer> <fingerprint>  after comparing fingerprints out of band
  reqexport <tid>              receiver asks the sender to allow export
  approve <tid> | deny <tid>   sender decides
  export <tid>                 copy an approved file to downloads/<me>/"""


def wait(future):
    result = future.result(timeout=60)
    if result is not None:
        print(f"-> {result}")


def run_command(client, line):
    cmd, _, arg = line.partition(" ")
    arg = arg.strip()
    if cmd in ("", "help"):
        print(HELP)
    elif cmd == "quit":
        return False
    elif cmd == "connect":
        wait(client.connect())
    elif cmd == "disconnect":
        wait(client.disconnect())
    elif cmd == "invite":
        wait(client.invite(arg.split()))
    elif cmd == "accept":
        wait(client.accept_invitation(arg))
    elif cmd == "reject":
        wait(client.reject_invitation(arg))
    elif cmd == "msg":
        wait(client.send_message({"kind": "text", "text": arg}))
    elif cmd == "file":
        wait(client.send_file(arg))
    elif cmd == "end":
        wait(client.end_session())
    elif cmd == "fp":
        print(client.fingerprint)
    elif cmd == "verify":
        peer, _, fp = arg.partition(" ")
        ok = client.verify_peer(peer, fp.strip())
        print("verified" if ok else "fingerprint does not match")
    elif cmd == "reqexport":
        wait(client.request_export(arg))
    elif cmd == "approve":
        wait(client.respond_export(arg, True))
    elif cmd == "deny":
        wait(client.respond_export(arg, False))
    elif cmd == "export":
        wait(client.export_file(arg))
    else:
        print("unknown command; type 'help'")
    return True


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python demo_client.py <client_id>")
    me = sys.argv[1]
    os.makedirs("keys", exist_ok=True)

    client = ClientCore(
        SERVER_HOST, SERVER_PORT, me,
        identity_path=os.path.join("keys", f"{me}.key"),
        trust_path=os.path.join("keys", f"{me}_trust.json"),
        download_dir=os.path.join("downloads", me),
    )
    for name in EVENTS:
        client.on(name, lambda payload, n=name: print(f"\n[{n}] {payload}"))

    commands = queue.Queue()

    def read_stdin():
        for line in sys.stdin:
            commands.put(line.strip())
        commands.put("quit")

    threading.Thread(target=read_stdin, daemon=True).start()

    print(HELP)
    print(f"your fingerprint: {client.fingerprint}")
    try:
        while True:
            client.drain_events()          # deliver queued events on this thread
            try:
                line = commands.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if not run_command(client, line):
                    break
            except Exception as exc:
                print(f"error: {exc}")
                traceback.print_exc()
    finally:
        client.shutdown().result(timeout=5)
        client.join(5)
        print("stopped")


if __name__ == "__main__":
    main()