"""Use a workspace-local temp root because some locked-down Windows sandboxes
deny pytest's default per-user temp directory.
"""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path():
    root = Path(__file__).resolve().parents[1] / ".test-tmp"
    root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="case-", dir=root) as temp:
        yield Path(temp)
