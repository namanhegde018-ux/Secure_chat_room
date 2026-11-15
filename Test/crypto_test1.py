## Using it with the server

from client_core import ClientCore

client = ClientCore(
    "127.0.0.1", 9000, "alice",
    identity_path="keys/alice.key",       # keep the identity stable across runs
    trust_path="keys/alice_trust.json",   # keep pins and verification state
    require_verified_peers=True,
)

client.on("secure_session_established", on_established)
client.on("peer_key_changed", on_key_changed)
client.on("message", on_message)

def on_established(e):
    # Show both fingerprints. The user compares them with Bob through another channel.
    print("Your fingerprint: ", client.fingerprint)
    print("Bob's fingerprint:", e["peer_fingerprint"])
    print("Safety number:    ", e["safety_number"])
    if not e["verified"]:
        print("Messages are blocked until you call client.verify_peer('bob', <Bob's fingerprint>).")

def on_key_changed(e):
    print("WARNING:", e["message"])   # do not proceed without out-of-band verification

# After the user confirms the fingerprint out of band:
client.verify_peer("bob", "3FA2C 91BD0 ...")