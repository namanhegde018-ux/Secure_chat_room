"""Strict per-session sequence/replay tracking."""


class ReplayError(ValueError):
    pass


class ReplayGuard:
    def __init__(self, session_id: str):
        if not session_id:
            raise ValueError("session_id is required")
        self.session_id = session_id
        self.last_sequence = -1
        self.ended = False

    def accept(self, session_id: str, sequence: int) -> None:
        if self.ended or session_id != self.session_id:
            raise ReplayError("message belongs to an invalid or ended session")
        if not isinstance(sequence, int) or sequence != self.last_sequence + 1:
            raise ReplayError("duplicate, replayed, or out-of-order message")
        self.last_sequence = sequence

    def end(self) -> None:
        self.ended = True
