"""Clean Tkinter shell driven by the agreed core API and event names."""

import queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import time

from .fake_core import FakeCore
from .document_viewer import DocumentViewer
from .theme import COLORS
from crypto.identity import new_identity, load_identity, identity_fingerprint
from crypto.peer_trust import PeerTrustStore


class SecureMessagingApp(tk.Tk):
    def __init__(self, core_factory=FakeCore):
        super().__init__()
        self.title("Secure Messaging")
        self.geometry("1080x740")
        self.minsize(900, 620)
        self.configure(bg=COLORS["background"])
        self.events = queue.Queue()
        self.core = core_factory(self)
        self.identity = None
        self.identity_path = Path.home() / ".secure-messaging" / "identity.key"
        self.peer_trust = PeerTrustStore(self.identity_path.parent / "trusted-peers.json")
        self.session_started = None
        self._style()
        self._build_login()
        self.after(80, self._drain_events)
        self.after(1000, self._tick)

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=COLORS["background"])
        style.configure("Card.TFrame", background=COLORS["card"])
        style.configure("Inset.TFrame", background=COLORS["inset"])
        style.configure("TLabel", background=COLORS["background"], foreground=COLORS["text"], font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=COLORS["card"], foreground=COLORS["text"], font=("Segoe UI", 10))
        style.configure("Inset.TLabel", background=COLORS["inset"], foreground=COLORS["text"], font=("Segoe UI", 9))
        style.configure("Muted.TLabel", foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("Eyebrow.TLabel", foreground=COLORS["accent"], font=("Segoe UI", 9, "bold"))
        style.configure("CardMuted.TLabel", background=COLORS["card"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("CardEyebrow.TLabel", background=COLORS["card"], foreground=COLORS["accent"], font=("Segoe UI", 9, "bold"))
        style.configure("CardTitle.TLabel", background=COLORS["card"], foreground=COLORS["text"], font=("Segoe UI", 19, "bold"))
        style.configure("InsetEyebrow.TLabel", background=COLORS["inset"], foreground=COLORS["accent"], font=("Segoe UI", 9, "bold"))
        style.configure("Hero.TLabel", font=("Segoe UI", 34, "bold"), foreground=COLORS["text"])
        style.configure("Title.TLabel", font=("Segoe UI", 19, "bold"), foreground=COLORS["text"])
        style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"), foreground=COLORS["text"])
        style.configure("Logo.TLabel", background=COLORS["accent"], foreground=COLORS["accent_ink"], font=("Segoe UI", 13, "bold"), padding=(10, 6))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=(13, 10), background=COLORS["button"], foreground=COLORS["text"], borderwidth=0)
        style.map("TButton", background=[("active", COLORS["button_hover"])], foreground=[("disabled", COLORS["disabled"])])
        style.configure("Accent.TButton", background=COLORS["accent"], foreground=COLORS["accent_ink"])
        style.map("Accent.TButton", background=[("active", COLORS["accent_hover"]), ("pressed", COLORS["accent_pressed"])])
        style.configure("Danger.TButton", background=COLORS["danger"], foreground=COLORS["danger_text"])
        style.map("Danger.TButton", background=[("active", COLORS["danger_hover"])])
        style.configure("TEntry", fieldbackground=COLORS["input"], foreground=COLORS["text"], insertcolor=COLORS["text"], padding=11, borderwidth=0)
        style.configure("TSeparator", background=COLORS["inset"])
        style.configure("TScrollbar", background=COLORS["button"], troughcolor=COLORS["card"], bordercolor=COLORS["card"], arrowcolor=COLORS["muted"])
        style.map("TScrollbar", background=[("active", COLORS["accent_pressed"])])

    def _build_login(self):
        self.login = ttk.Frame(self, padding=(42, 30))
        self.login.pack(fill="both", expand=True)
        header = ttk.Frame(self.login)
        header.pack(fill="x", pady=(0, 28))
        ttk.Label(header, text="S", style="Logo.TLabel").pack(side="left")
        ttk.Label(header, text="SECURE MESSAGING", style="Section.TLabel").pack(side="left", padx=12)
        ttk.Label(header, text="PRIVATE DESKTOP CLIENT", style="Muted.TLabel").pack(side="right")

        body = ttk.Frame(self.login)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        intro = ttk.Frame(body, padding=(4, 34, 38, 20))
        intro.grid(row=0, column=0, sticky="nsew")
        ttk.Label(intro, text="PRIVATE  ·  VERIFIED  ·  EPHEMERAL", style="Eyebrow.TLabel").pack(anchor="w", pady=(16, 18))
        ttk.Label(intro, text="A quieter place\nto talk securely.", style="Hero.TLabel", justify="left").pack(anchor="w", pady=(0, 18))
        ttk.Label(intro, text="Start a private session with someone you trust. Messages stay in the active session and are not saved as chat history.", wraplength=440, justify="left", style="Muted.TLabel").pack(anchor="w", pady=(0, 32))
        self._feature(intro, "01", "Your identity", "A local key protects your account.")
        self._feature(intro, "02", "Verify your peer", "Compare fingerprints through another channel.")
        self._feature(intro, "03", "End when you’re done", "Close the session to clear live state.")

        card = ttk.Frame(body, style="Card.TFrame", padding=28)
        card.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=18)
        ttk.Label(card, text="WELCOME BACK", style="CardEyebrow.TLabel").pack(anchor="w", pady=(5, 7))
        ttk.Label(card, text="Unlock your identity", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(card, text="Your private key stays on this device.", style="CardMuted.TLabel", wraplength=310).pack(anchor="w", pady=(7, 22))
        identity_box = ttk.Frame(card, style="Inset.TFrame", padding=15)
        identity_box.pack(fill="x", pady=(0, 20))
        ttk.Label(identity_box, text="LOCAL IDENTITY", style="InsetEyebrow.TLabel").pack(anchor="w")
        self.identity_label = ttk.Label(identity_box, text="Locked · fingerprint appears after unlock", style="Inset.TLabel", wraplength=280, justify="left")
        self.identity_label.pack(anchor="w", pady=(9, 0))
        ttk.Button(card, text="Unlock & connect", style="Accent.TButton", command=self._connect).pack(fill="x", pady=(2, 10))
        ttk.Button(card, text="Try the demo invitation", command=self._demo_invite).pack(fill="x")
        self.status = ttk.Label(card, text="●  Offline", style="CardMuted.TLabel")
        self.status.pack(anchor="w", pady=(18, 0))

        footer = ttk.Frame(self.login)
        footer.pack(fill="x", pady=(16, 0))
        ttk.Label(footer, text="DEMO MODE USES FAKECORE · NO REAL SERVER CONNECTION", style="Muted.TLabel").pack(side="left")
        ttk.Label(footer, text="DATABASE-FREE", style="Eyebrow.TLabel").pack(side="right")

    @staticmethod
    def _feature(parent, number, title, detail):
        row = ttk.Frame(parent, padding=(0, 8))
        row.pack(fill="x", anchor="w")
        ttk.Label(row, text=number, style="Eyebrow.TLabel", width=4).pack(side="left", anchor="n")
        text = ttk.Frame(row)
        text.pack(side="left", fill="x")
        ttk.Label(text, text=title, style="Section.TLabel").pack(anchor="w")
        ttk.Label(text, text=detail, style="Muted.TLabel").pack(anchor="w", pady=(3, 0))

    def _connect(self):
        try:
            password = simpledialog.askstring("Unlock identity", "Enter your identity password:", show="•", parent=self)
            if not password:
                return
            if self.identity_path.exists():
                self.identity = load_identity(self.identity_path, password)
            else:
                self.identity_path.parent.mkdir(parents=True, exist_ok=True)
                self.identity = new_identity(self.identity_path, password)
            self.display_name = simpledialog.askstring("Your name", "Name shown to your peer and on document watermarks:", parent=self)
            if not self.display_name:
                self.display_name = "Recipient"
            self.identity_label.configure(text=f"Identity ready · Fingerprint: {identity_fingerprint(self.identity)}")
            self.core.connect()
            self.status.configure(text="Connected · signaling is simulated")
        except Exception as exc:
            messagebox.showerror("Connection failed", str(exc), parent=self)

    def _demo_invite(self):
        self.core.invite("Demo peer")

    def on_invite_received(self, event):
        self.events.put(("invite", event))

    def on_session_started(self, event):
        self.events.put(("started", event))

    def on_message(self, event):
        self.events.put(("message", event))

    def on_file_received(self, event):
        self.events.put(("file", event))

    def on_export_request(self, event):
        self.events.put(("export", event))

    def on_export_decision(self, event):
        self.events.put(("decision", event))

    def on_peer_disconnected(self, event):
        self.events.put(("disconnected", event))

    def on_session_ended(self, event):
        self.events.put(("ended", event))

    def _drain_events(self):
        while True:
            try:
                kind, event = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "invite":
                self._invite_dialog(event)
            elif kind == "started":
                self._show_chat(event)
            elif kind == "message":
                self._append_message(event)
            elif kind == "file":
                self._file_notice(event)
            elif kind == "export":
                self._export_dialog(event)
            elif kind == "decision":
                messagebox.showinfo("Export decision", f"{event['name']}: {'approved' if event['approved'] else 'rejected'}", parent=self)
            elif kind == "disconnected":
                if hasattr(self, "status"):
                    self.status.configure(text="● Peer disconnected · session may be unavailable")
                messagebox.showwarning("Peer disconnected", "The peer disconnected unexpectedly.", parent=self)
            elif kind == "ended":
                messagebox.showinfo("Session ended", event.get("reason", "Session ended"), parent=self)
                self._back_to_login()
        self.after(80, self._drain_events)

    def _invite_dialog(self, event):
        peer = event.get("peer", "Peer")
        fp = event.get("fingerprint", "Unknown")
        try:
            trust_state = self.peer_trust.check(str(event.get("peer_id", peer)), fp)
        except ValueError as exc:
            messagebox.showerror("Peer trust error", str(exc), parent=self)
            self.core.reject(event)
            return
        if trust_state == "changed":
            messagebox.showerror("Identity changed", f"{peer}'s fingerprint differs from the one you previously verified. Invitation rejected. Verify the new key with them independently before resetting trust.", parent=self)
            self.core.reject(event)
            return
        guidance = "This is a previously verified identity." if trust_state == "match" else "Compare this fingerprint through a trusted independent channel before trusting it."
        if not messagebox.askyesno("Session invitation", f"{peer} invites you.\n\nFingerprint: {fp}\n\n{guidance}", parent=self):
            self.core.reject(event)
            return
        if trust_state == "new" and not messagebox.askyesno("Verify identity", "Have you independently compared this fingerprint? Trust this identity on this device?", parent=self):
            self.core.reject(event)
            return
        if trust_state == "new":
            try:
                self.peer_trust.trust(str(event.get("peer_id", peer)), fp)
            except (OSError, ValueError) as exc:
                messagebox.showerror("Could not save trust", str(exc), parent=self)
                self.core.reject(event)
                return
        self.active_peer_fingerprint = fp
        self.core.accept(event)

    def _show_chat(self, event):
        if hasattr(self, "login"):
            self.login.destroy()
        self.peer = event.get("peer", "Peer")
        self.session_started = time.monotonic()
        self.session_event = event
        self.chat = ttk.Frame(self, padding=(26, 20))
        self.chat.pack(fill="both", expand=True)
        top = ttk.Frame(self.chat)
        top.pack(fill="x", pady=(0, 18))
        ttk.Label(top, text="S", style="Logo.TLabel").pack(side="left")
        ttk.Label(top, text="SECURE MESSAGING", style="Section.TLabel").pack(side="left", padx=12)
        ttk.Label(top, text="ACTIVE CONVERSATION", style="Muted.TLabel").pack(side="left", padx=(18, 0))
        self.timer = ttk.Label(top, text="00:00", style="Section.TLabel")
        self.timer.pack(side="right")
        ttk.Label(top, text="SESSION TIME  ", style="Muted.TLabel").pack(side="right", padx=(0, 4))

        content = ttk.Frame(self.chat)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=0, minsize=250)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        side = ttk.Frame(content, style="Card.TFrame", padding=19)
        side.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        ttk.Label(side, text="SESSION PARTICIPANT", style="CardEyebrow.TLabel").pack(anchor="w")
        avatar = ttk.Label(side, text=self.peer[:1].upper(), style="Logo.TLabel", padding=(13, 10))
        avatar.pack(anchor="w", pady=(22, 12))
        ttk.Label(side, text=self.peer, style="CardTitle.TLabel", wraplength=210).pack(anchor="w")
        ttk.Label(side, text="PEER", style="CardMuted.TLabel").pack(anchor="w", pady=(4, 20))
        ttk.Separator(side).pack(fill="x", pady=(0, 18))
        ttk.Label(side, text="FINGERPRINT", style="CardEyebrow.TLabel").pack(anchor="w")
        self.peer_fingerprint_label = ttk.Label(side, text=getattr(self, "active_peer_fingerprint", "Not provided"), style="Card.TLabel", wraplength=210, justify="left")
        self.peer_fingerprint_label.pack(anchor="w", pady=(8, 5))
        ttk.Label(side, text="Compared outside this app", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 18))
        ttk.Separator(side).pack(fill="x", pady=(0, 18))
        ttk.Label(side, text="SESSION STATUS", style="CardEyebrow.TLabel").pack(anchor="w")
        if isinstance(self.core, FakeCore):
            status_text = "DEMO MODE · no network or encryption"
        elif event.get("security_verified") and event.get("transport_secure"):
            status_text = "Secure transport · peer verified"
        else:
            status_text = "Connected · security not confirmed"
        self.status = ttk.Label(side, text=f"●  {status_text}", style="CardMuted.TLabel", wraplength=210, justify="left")
        self.status.pack(anchor="w", pady=(8, 0))

        main = ttk.Frame(content)
        main.grid(row=0, column=1, sticky="nsew")
        main.rowconfigure(1, weight=1)
        main.columnconfigure(0, weight=1)
        heading = ttk.Frame(main)
        heading.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(heading, text="Messages", style="Title.TLabel").pack(side="left")
        ttk.Label(heading, text="Live session · not saved as chat history", style="Muted.TLabel").pack(side="right")
        transcript_card = ttk.Frame(main, style="Card.TFrame", padding=10)
        transcript_card.grid(row=1, column=0, sticky="nsew")
        transcript_card.rowconfigure(0, weight=1)
        transcript_card.columnconfigure(0, weight=1)
        self.transcript = tk.Text(transcript_card, bg=COLORS["card"], fg=COLORS["text"], insertbackground=COLORS["accent"], relief="flat", wrap="word", state="disabled", font=("Segoe UI", 10), padx=16, pady=14, spacing1=3, spacing3=8, borderwidth=0)
        self.transcript.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(transcript_card, command=self.transcript.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.transcript.configure(yscrollcommand=scroll.set)
        self.transcript.tag_configure("meta", foreground=COLORS["meta"], font=("Segoe UI", 8, "bold"))
        self.transcript.tag_configure("own", foreground=COLORS["accent"], font=("Segoe UI", 10, "bold"))
        self.transcript.tag_configure("peer", foreground=COLORS["peer"], font=("Segoe UI", 10, "bold"))
        self.transcript.tag_configure("body", foreground=COLORS["text"], lmargin1=4, lmargin2=4)

        composer = ttk.Frame(main, style="Card.TFrame", padding=10)
        composer.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        composer.columnconfigure(0, weight=1)
        self.input = ttk.Entry(composer)
        self.input.grid(row=0, column=0, sticky="ew", padx=(0, 9))
        self.input.bind("<Return>", lambda _e: self._send())
        ttk.Button(composer, text="Send", style="Accent.TButton", command=self._send).grid(row=0, column=1)
        actions = ttk.Frame(main)
        actions.grid(row=3, column=0, sticky="ew", pady=(11, 0))
        ttk.Button(actions, text="＋  Send file", command=self._send_file).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="↗  Request export", command=self._request_export).pack(side="left")
        ttk.Button(actions, text="End session", style="Danger.TButton", command=self._end_confirm).pack(side="right")
        self._append_message({"sender": "System", "text": "This conversation is active. End the session when you’re finished.", "time": time.strftime("%H:%M")})

    def _append_message(self, event):
        if not hasattr(self, "transcript"):
            return
        self.transcript.configure(state="normal")
        sender = event.get("sender", "Peer")
        header_tag = "own" if sender == "You" else "peer"
        self.transcript.insert("end", f"{sender}   ", header_tag)
        self.transcript.insert("end", f"{event.get('time', '')}\n", "meta")
        self.transcript.insert("end", f"{event.get('text', '')}\n\n", "body")
        self.transcript.see("end")
        self.transcript.configure(state="disabled")

    def _send(self):
        text = self.input.get().strip()
        if text:
            self.input.delete(0, "end")
            self.core.send_message(text)

    def _send_file(self):
        path = filedialog.askopenfilename(parent=self)
        if path:
            self.core.send_file(path)

    def _file_notice(self, event):
        if messagebox.askyesno("Document received", f"Open {event.get('name', 'document')} in the watermarked viewer?", parent=self):
            try:
                DocumentViewer(self, event.get("path"), getattr(self, "display_name", "Recipient"))
            except Exception as exc:
                messagebox.showerror("Cannot display document", str(exc), parent=self)

    def _request_export(self):
        name = simpledialog.askstring("Request export", "Which file do you need exported?", parent=self)
        if name:
            self.core.request_export(name)

    def _export_dialog(self, event):
        approved = messagebox.askyesno("Export request", f"{event.get('requester', 'Peer')} requests export of {event.get('name', 'a file')}. Approve?", parent=self)
        self.core.decide_export(event, approved)

    def _end_confirm(self):
        if messagebox.askyesno("End session", "End this session and discard its temporary state?", parent=self):
            self.core.end_session()

    def _back_to_login(self):
        if hasattr(self, "chat"):
            self.chat.destroy()
        self.session_started = None
        self.active_peer_fingerprint = None
        self.login = None
        self._build_login()

    def _tick(self):
        if self.session_started and hasattr(self, "timer"):
            seconds = int(time.monotonic() - self.session_started)
            self.timer.configure(text=f"{seconds // 60:02d}:{seconds % 60:02d}")
        self.after(1000, self._tick)


def main():
    SecureMessagingApp().mainloop()


if __name__ == "__main__":
    main()
