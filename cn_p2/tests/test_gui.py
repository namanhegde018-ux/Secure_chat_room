import tkinter as tk
import pytest

from gui.app import SecureMessagingApp
from crypto.peer_trust import PeerTrustStore


def test_gui_fake_invite_chat_export_disconnect_and_end(monkeypatch, tmp_path):
    try:
        app = SecureMessagingApp()
    except tk.TclError as exc:
        pytest.skip(f"Tk desktop session is unavailable: {exc}")
    app.withdraw()
    app.peer_trust = PeerTrustStore(tmp_path / "trusted-peers.json")
    prompts = iter([True, True, True])
    monkeypatch.setattr("gui.app.messagebox.askyesno", lambda *a, **k: next(prompts))
    notices = []
    monkeypatch.setattr("gui.app.messagebox.showinfo", lambda *a, **k: notices.append(a[0]))
    monkeypatch.setattr("gui.app.messagebox.showwarning", lambda *a, **k: notices.append(a[0]))
    try:
        app.on_invite_received({"peer": "Demo peer", "peer_id": "demo-peer", "fingerprint": "ABCD 1234"})
        app._drain_events()
        assert hasattr(app, "transcript")
        app.on_message({"sender": "Demo peer", "text": "hello", "time": "10:30"})
        app._drain_events()
        assert "hello" in app.transcript.get("1.0", "end")
        app.on_export_request({"name": "report.pdf", "requester": "Demo peer"})
        app._drain_events()
        assert "Export decision" in notices
        app.on_peer_disconnected({"reason": "test"})
        app._drain_events()
        assert "Peer disconnected" in notices
        assert "disconnected" in app.status.cget("text").lower()
        app.on_session_ended({"reason": "test complete"})
        app._drain_events()
        assert hasattr(app, "login")
        assert "Session ended" in notices
    finally:
        app.destroy()
