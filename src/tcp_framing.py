import json
import socket
import struct
# import threading
import time

HEADER_FORMAT = "!I"                         # 4-byte unsigned int, big-endian (network order)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # 4
MAX_MESSAGE_SIZE = 1024 * 1024               # 1 MiB safety limit on payload size


class FramingError(Exception):
    """Base class for framing errors."""


class ConnectionClosed(FramingError):
    """The peer closed the connection before a full frame arrived."""


class MessageTooLarge(FramingError):
    """The declared payload length exceeds MAX_MESSAGE_SIZE."""


def recv_exact(sock, n, deadline=None):
    """
    Receive exactly n bytes from sock.

    Repeatedly calls recv() to handle partial reads. Raises ConnectionClosed
    if the peer disconnects, and TimeoutError if the deadline (a value from
    time.monotonic()) passes before all bytes arrive.
    """
    buf = bytearray()
    while len(buf) < n:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out after receiving {len(buf)} of {n} bytes")
            sock.settimeout(remaining)

        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise TimeoutError(f"timed out after receiving {len(buf)} of {n} bytes") from None

        if not chunk:  # recv() returns b'' only when the peer has closed the connection
            raise ConnectionClosed(f"connection closed after receiving {len(buf)} of {n} bytes")

        buf.extend(chunk)

    return bytes(buf)


def send_frame(sock, data):
    """Serialize a dict to JSON and send it as a length-prefixed frame."""
    if not isinstance(data, dict):
        raise TypeError("data must be a dict")

    # 1. Dict -> JSON string
    json_text = json.dumps(data, separators=(",", ":"))

    # 2. JSON string -> UTF-8 bytes
    payload = json_text.encode("utf-8")

    # 3. Payload length
    length = len(payload)
    if length > MAX_MESSAGE_SIZE:
        raise MessageTooLarge(f"payload is {length} bytes; limit is {MAX_MESSAGE_SIZE}")

    # 4. Length -> 4-byte big-endian header
    header = struct.pack(HEADER_FORMAT, length)

    # 5. Send header + payload (sendall loops internally over partial sends)
    sock.sendall(header + payload)


def receive_frame(sock, timeout=None):
    """
    Receive one length-prefixed JSON frame and return it as a dict.

    timeout: optional overall time limit (seconds) for receiving the whole frame.
             If None, the socket's own timeout setting (if any) applies.
    """
    deadline = None if timeout is None else time.monotonic() + timeout

    # 1. Read exactly 4 header bytes
    header = recv_exact(sock, HEADER_SIZE, deadline)

    # 2. Decode the payload length
    (length,) = struct.unpack(HEADER_FORMAT, header)

    # 3. Validate the length before allocating/reading anything
    if length > MAX_MESSAGE_SIZE:
        raise MessageTooLarge(f"declared payload is {length} bytes; limit is {MAX_MESSAGE_SIZE}")

    # 4. Read exactly that many payload bytes
    payload = recv_exact(sock, length, deadline)

    # 5. Decode UTF-8 and 6. parse JSON
    try:
        obj = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise FramingError("payload is not valid UTF-8") from e
    except json.JSONDecodeError as e:
        raise FramingError(f"payload is not valid JSON: {e}") from e

    # 7. Return the dictionary
    if not isinstance(obj, dict):
        raise FramingError(f"expected a JSON object, got {type(obj).__name__}")
    return obj