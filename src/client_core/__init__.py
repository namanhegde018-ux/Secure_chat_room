"""UI-independent client core for the central signalling server."""

from .core import ClientCore
from .session import SessionSnapshot
self._outbox: Optional[asyncio.Queue] = None
self._pump_task: Optional[asyncio.Task] = None

__all__ = ["ClientCore", "SessionSnapshot"]