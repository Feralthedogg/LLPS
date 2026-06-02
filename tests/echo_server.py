#!/usr/bin/env python3
"""Small asyncio echo backend for local LLPS proxy benchmarks."""

import asyncio
import sys

async def handle_echo(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def main():
    server = await asyncio.start_server(handle_echo, '127.0.0.1', 25566)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
