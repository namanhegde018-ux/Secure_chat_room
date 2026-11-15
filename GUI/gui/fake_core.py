"""In-process demonstration backend. Replace with Name 1's adapter at integration."""

import time


class FakeCore:
    def __init__(self, event_sink):
        self.ui = event_sink
        self._timer = None
        self._connected = False

    def connect(self):
        self._connected = True

    def invite(self, peer):
        self.ui.on_invite_received({"peer": peer, "peer_id": peer.casefold(), "fingerprint": "A12B C34D E56F 7890 1234 5678 9ABC DEF0"})

    def accept(self, request=None):
        self.ui.on_session_started({"peer": "Demo peer", "session_id": "demo-session"})

    def reject(self, request=None):
        pass

    def send_message(self, message):
        self.ui.on_message({"sender": "You", "text": message, "time": time.strftime("%H:%M")})

    def send_file(self, path):
        name = path.replace("\\", "/").split("/")[-1]
        self.ui.on_message({"sender": "You", "text": f"Demo selected file: {name}", "time": time.strftime("%H:%M")})

    def request_export(self, name):
        self.ui.on_export_request({"name": name, "requester": "Demo peer"})

    def decide_export(self, request, approved):
        self.ui.on_export_decision({"name": request.get("name", "file"), "approved": approved})

    def end_session(self):
        self.ui.on_session_ended({"reason": "Session ended"})

    def demo_received_file(self, path):
        name = path.replace("\\", "/").split("/")[-1]
        self.ui.on_file_received({"name": name, "path": path})

    def demo_peer_disconnected(self):
        self.ui.on_peer_disconnected({"reason": "Demo disconnection"})
