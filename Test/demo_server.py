import asyncio
import json
import struct

HOST, PORT = "127.0.0.1", 9000


async def send(writer, msg):
    data = json.dumps(msg).encode("utf-8")
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()


async def recv(reader):
    (length,) = struct.unpack("!I", await reader.readexactly(4))
    return json.loads(await reader.readexactly(length))


async def main():
    ra, wa = await asyncio.open_connection(HOST, PORT)
    rb, wb = await asyncio.open_connection(HOST, PORT)

    await send(wa, {"type": "register", "client_id": "alice"})
    print("alice:", await recv(ra))
    await send(wb, {"type": "register", "client_id": "bob"})
    print("bob:  ", await recv(rb))

    await send(wa, {"type": "invite", "to": "bob"})
    print("alice:", await recv(ra))                     # invite_sent
    invitation = await recv(rb)                         # invitation
    print("bob:  ", invitation)

    await send(wb, {"type": "accept", "invitation_id": invitation["invitation_id"]})
    started = await recv(ra)
    print("alice:", started)
    print("bob:  ", await recv(rb))

    sid = started["session_id"]
    await send(wa, {"type": "message", "session_id": sid, "body": {"text": "hi bob"}})
    print("bob:  ", await recv(rb))

    await send(wb, {"type": "end_session", "session_id": sid})
    print("alice:", await recv(ra))
    print("bob:  ", await recv(rb))

    wa.close()
    wb.close()


asyncio.run(main())