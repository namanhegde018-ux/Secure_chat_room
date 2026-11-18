"""Central configuration. Some values can be overridden with environment variables."""

import os

HOST = os.getenv("SIGNAL_HOST", "0.0.0.0")
PORT = int(os.getenv("SIGNAL_PORT", "9000"))

# --- Framing -----------------------------------------------------------------
MAX_MESSAGE_SIZE = int(os.getenv("SIGNAL_MAX_MESSAGE_SIZE", str(1024 * 1024)))  # bytes

# --- Client liveness -----------------------------------------------------------
# A client must send *some* frame (a "ping" is enough) within this many seconds,
# otherwise it is considered disconnected and dropped.
CLIENT_IDLE_TIMEOUT = float(os.getenv("SIGNAL_CLIENT_IDLE_TIMEOUT", "60"))

# --- Invitations ---------------------------------------------------------------
INVITATION_TTL = 60.0                # seconds a pending invitation stays valid

# --- Sessions ------------------------------------------------------------------
SESSION_IDLE_TIMEOUT = 300.0         # seconds without relayed traffic before expiry
FINISHED_RETENTION = 600.0           # seconds ended/expired records are kept, then purged

# --- Maintenance ---------------------------------------------------------------
SWEEP_INTERVAL = 5.0                 # how often the expiry sweep runs

# --- Per-client outbound buffering ---------------------------------------------
OUTBOUND_QUEUE_SIZE = 256            # queued frames per client before it is treated as too slow
FLUSH_TIMEOUT = 2.0                  # seconds allowed to flush queued frames on orderly close
MAX_GROUP_SIZE = 20   # members per group, including the creator

# --- Identity rules ------------------------------------------------------------
MAX_CLIENT_ID_LENGTH = 32
SESSION_ID_BYTES = 16                # secrets.token_urlsafe(16) -> ~22 characters
INVITATION_ID_BYTES = 16