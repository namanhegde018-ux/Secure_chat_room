
"""UI-independent client core for the central signalling server.
 
The modules in this directory import each other by their bare names
(``from crypto import ...``, ``from trust import ...``), so this directory has to
be on ``sys.path``. Doing that here lets ``import client_core`` work from any
working directory without touching the other files.
"""
 
import os
import sys
 
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
 
from core import ClientCore          # noqa: E402
from session import SessionSnapshot  # noqa: E402
 
__all__ = ["ClientCore", "SessionSnapshot"]
 