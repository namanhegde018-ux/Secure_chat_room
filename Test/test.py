import json
import socket
import struct
import threading
import time


import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from tcp_framing import (
    ConnectionClosed,
    HEADER_FORMAT,
    receive_frame,
    send_frame,
)


if __name__ == "__main__":
    # 1. Normal round trip
    a, b = socket.socketpair()
    a.settimeout(5)
    b.settimeout(5)
    send_frame(a, {"type": "greeting", "msg": "héllo wörld"})
    print("Received:", receive_frame(b))

    # 2. Partial reads: sender dribbles the frame out one byte at a time
    def slow_sender(sock, data):
        payload = json.dumps(data).encode("utf-8")
        frame = struct.pack(HEADER_FORMAT, len(payload)) + payload
        for i in range(len(frame)):
            sock.send(frame[i:i + 1])
            time.sleep(0.01)

    threading.Thread(target=slow_sender, args=(a, {"slow": True}), daemon=True).start()
    print("Partial-read frame:", receive_frame(b, timeout=5))

    # 3. Disconnection
    a.close()
    try:
        receive_frame(b, timeout=5)
    except ConnectionClosed as e:
        print("Disconnect detected:", e)
    b.close()

    # 4. Timeout: peer is connected but never sends anything
    c, d = socket.socketpair()
    try:
        receive_frame(d, timeout=0.5)
    except TimeoutError as e:
        print("Timeout detected:", e)
    finally:
        c.close()
        d.close()