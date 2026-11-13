"""
Asyncio TCP server: accept loop, per-client read loop, and the background sweeper.

Run with:   python -m signaling_server.server
"""

from __future__ import annotations

import asyncio
import logging

import configuration as config
from connection import Connection, ConnectionClosed, FramingError, read_frame
from session_manager import SessionManager
from signaling import ClientRegistry, SignalingService

log = logging.getLogger("signaling.server")


class SignalingServer:
    def __init__(self) -> None:
        self.registry = ClientRegistry()
        self.sessions = SessionManager()
        self.service = SignalingService(self.registry, self.sessions)
        self._connections: set[Connection] = set()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Called by asyncio once per accepted connection. Each call runs in its own task."""
        conn = Connection(reader, writer)
        self._connections.add(conn)
        log.info("connected: %s", conn.peer)
        try:
            await self._read_loop(conn)
        except (ConnectionError, OSError) as exc:
            log.info("socket error from %s: %s", conn, exc)
        except Exception:
            log.exception("unexpected error handling %s", conn)
        finally:
            # Runs on every exit path: EOF, reset, idle timeout, protocol error, or shutdown.
            self.service.handle_disconnect(conn)
            self._connections.discard(conn)
            conn.abort()
            log.info("disconnected: %s", conn)

    async def _read_loop(self, conn: Connection) -> None:
        while not conn.closed:
            try:
                # Every frame (including "ping") resets the idle clock.
                msg = await asyncio.wait_for(read_frame(conn.reader), timeout=config.CLIENT_IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                log.info("idle timeout: %s", conn)
                conn.send({"type": "error", "code": "idle_timeout", "message": "no heartbeat received"})
                await conn.close()
                return
            except ConnectionClosed:
                return
            except FramingError as exc:
                # The stream is out of sync. Report the error and close.
                log.warning("framing error from %s: %s", conn, exc)
                conn.send({"type": "error", "code": "framing_error", "message": str(exc)})
                await conn.close()
                return

            self.service.handle(conn, msg)

    async def sweep_loop(self) -> None:
        """Periodically expire invitations and sessions."""
        while True:
            await asyncio.sleep(config.SWEEP_INTERVAL)
            try:
                self.service.sweep()
            except Exception:
                log.exception("expiry sweep failed")

    async def shutdown(self) -> None:
        """Flush and close every open connection."""
        await asyncio.gather(
            *(conn.close() for conn in list(self._connections)),
            return_exceptions=True,
        )


async def run(host: str = config.HOST, port: int = config.PORT) -> None:
    server = SignalingServer()
    listener = await asyncio.start_server(server.handle_client, host, port)
    sweeper = asyncio.create_task(server.sweep_loop(), name="expiry-sweeper")

    addrs = ", ".join(str(s.getsockname()) for s in listener.sockets)
    log.info("signalling server listening on %s", addrs)

    try:
        await listener.serve_forever()
    finally:
        sweeper.cancel()
        listener.close()
        await server.shutdown()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("shutting down")


if __name__ == "__main__":
    main()