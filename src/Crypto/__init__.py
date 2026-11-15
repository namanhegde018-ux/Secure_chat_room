"""Public API for the encrypted signalling client.

Cryptographic primitives and handshake logic live in this package; the
shared networking/session infrastructure is provided by :mod:`gui_core`.
"""

from .core import ClientCore, SecurityError
from gui_core.session import SessionSnapshot
from .trust import PeerKeyChanged

__all__ = ["ClientCore", "SecurityError", "SessionSnapshot", "PeerKeyChanged"]
