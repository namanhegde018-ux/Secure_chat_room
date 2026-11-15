"""UI-independent client core for the central signalling server."""

from .core import ClientCore
from .session import SessionSnapshot

__all__ = ["ClientCore", "SessionSnapshot"]