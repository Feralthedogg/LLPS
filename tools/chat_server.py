#!/usr/bin/env python3
"""Small TCP chat server used as an LLPS backend target."""

import argparse
import asyncio
import itertools
import signal
from typing import Dict


clients: Dict[asyncio.StreamWriter, str] = {}
clients_lock = asyncio.Lock()
client_ids = itertools.count(1)


def log(message: str) -> None:
    print(f"[chat-server] {message}", flush=True)


async def broadcast(message: str) -> None:
    async with clients_lock:
        writers = list(clients.keys())

    stale = []
    for writer in writers:
        try:
            writer.write(message.encode("utf-8"))
            await writer.drain()
        except OSError:
            stale.append(writer)

    if stale:
        async with clients_lock:
            for writer in stale:
                clients.pop(writer, None)


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    name = f"client{next(client_ids)}"
    peer = writer.get_extra_info("peername")

    async with clients_lock:
        clients[writer] = name

    log(f"{name} connected peer={peer}")
    await broadcast(f"system: {name} joined\n")

    try:
        while True:
            line = await reader.readline()
            if not line:
                break

            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if text:
                log(f"{name} says {text}")
                await broadcast(f"{name}: {text}\n")
    except OSError:
        pass
    finally:
        async with clients_lock:
            clients.pop(writer, None)

        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

        log(f"{name} disconnected")
        await broadcast(f"system: {name} left\n")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    server = await asyncio.start_server(handle_client, args.host, args.port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    log(f"listening on {sockets}")

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:
            pass

    async with server:
        await stop.wait()

    log("stopped")


if __name__ == "__main__":
    asyncio.run(main())
