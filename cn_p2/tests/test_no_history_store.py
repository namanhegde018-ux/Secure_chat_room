from pathlib import Path


def test_project_has_no_database_or_persistent_chat_history_files():
    root = Path(__file__).resolve().parents[1]
    ignored = {".git", ".venv", ".pytest_cache", "__pycache__"}
    forbidden_suffixes = {".sqlite", ".sqlite3", ".db"}
    forbidden_names = {"chat_history.json", "message_history.json", "history.jsonl"}
    offenders = []
    for path in root.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        if path.is_file() and (path.suffix.lower() in forbidden_suffixes or path.name.lower() in forbidden_names):
            offenders.append(str(path.relative_to(root)))
    assert offenders == []
