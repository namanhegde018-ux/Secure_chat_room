# Name 1 integration contract

`gui.app.SecureMessagingApp` accepts a `core_factory(event_sink)` object. The object must expose `connect()`, `invite(peer)`, `accept(request)`, `reject(request)`, `send_message(text)`, `send_file(path)`, `request_export(name)`, `decide_export(request, approved)`, and `end_session()`.

The event sink methods are `on_invite_received(dict)`, `on_session_started(dict)`, `on_message(dict)`, `on_file_received(dict)`, `on_export_request(dict)`, `on_export_decision(dict)`, `on_peer_disconnected(dict)`, and `on_session_ended(dict)`. Event callbacks may arrive from worker threads; the UI queues them onto Tk's main loop.

Suggested payloads for the demo UI: invitation `{peer, fingerprint}`, session start `{peer, session_id}`, message `{sender, text, time}`, file `{name, path}`, export request `{name, requester}`, export decision `{name, approved}`, end `{reason}`. Name 1's agreed JSON protocol remains authoritative; adapt these fields rather than changing the wire message types.

Use `crypto.encryption.encrypt/decrypt` for application payload bytes and Base64 at the JSON boundary. Use verified TLS from `crypto.tls.create_client_context(cafile=...)`; pass the actual server hostname for certificate hostname verification. Do not add an unverified/self-signed trust-all mode.
