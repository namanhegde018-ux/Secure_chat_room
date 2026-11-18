"""Thread-safe event dispatch for client-core callbacks."""

import logging
import threading
from queue import Empty, SimpleQueue
from typing import Any, Callable, Mapping

log = logging.getLogger(__name__)

EventCallback = Callable[[dict[str, Any]], None]
UiDispatcher = Callable[[Callable[[], None]], None]


class EventEmitter:
    def __init__(self, dispatch_to_ui: UiDispatcher | None = None) -> None:
        self._dispatch_to_ui = dispatch_to_ui
        self._listeners: dict[str, list[EventCallback]] = {}
        self._lock = threading.RLock()
        self._pending: SimpleQueue[Callable[[], None]] = SimpleQueue()

    def on(self, event_name: str, callback: EventCallback) -> Callable[[], None]:
        """Subscribe to an event. Returns a function that unsubscribes it."""
        if not callable(callback):
            raise TypeError("callback must be callable")

        with self._lock:
            self._listeners.setdefault(event_name, []).append(callback)

        return lambda: self.off(event_name, callback)

    def off(self, event_name: str, callback: EventCallback) -> None:
        with self._lock:
            callbacks = self._listeners.get(event_name, [])
            try:
                callbacks.remove(callback)
            except ValueError:
                pass
            if not callbacks:
                self._listeners.pop(event_name, None)

    def emit(
        self,
        event_name: str,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        """Schedule a copy of the payload for each current listener."""
        with self._lock:
            callbacks = tuple(self._listeners.get(event_name, ()))

        data = dict(payload or {})
        for callback in callbacks:
            def invoke(
                callback: EventCallback = callback,
                data: dict[str, Any] = data,
            ) -> None:
                try:
                    callback(dict(data))
                except Exception:
                    log.exception("callback for event %r failed", event_name)

            if self._dispatch_to_ui is None:
                self._pending.put(invoke)
            else:
                try:
                    self._dispatch_to_ui(invoke)
                except Exception:
                    # Retain the event if the UI dispatcher is temporarily unavailable.
                    log.exception("UI dispatcher failed for event %r", event_name)
                    self._pending.put(invoke)

    def drain(self, limit: int | None = None) -> int:
        """
        Run queued callbacks in the calling thread.

        Use this from the UI thread, typically via a framework timer, when no
        dispatch_to_ui function was supplied.
        """
        count = 0
        while limit is None or count < limit:
            try:
                callback = self._pending.get_nowait()
            except Empty:
                break
            callback()
            count += 1
        return count