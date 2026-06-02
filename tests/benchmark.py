#!/usr/bin/env python3
"""Async echo-through-proxy benchmark client for local LLPS checks."""

import asyncio
import time
import sys

NUM_CLIENTS = 200
PAYLOAD_SIZE = 1024 * 64
DURATION = 5.0

stats = {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'errors': 0,
    'connected': 0,
}

payload = b'X' * PAYLOAD_SIZE

async def client_task(client_id):
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', 25565)
        stats['connected'] += 1
    except Exception as e:
        stats['errors'] += 1
        return

    end_time = time.time() + DURATION

    try:
        while time.time() < end_time:
            writer.write(payload)
            await writer.drain()
            stats['bytes_sent'] += PAYLOAD_SIZE

            recv_size = 0
            while recv_size < PAYLOAD_SIZE:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                recv_size += len(chunk)

            stats['bytes_recv'] += recv_size

            if recv_size < PAYLOAD_SIZE:
                break
    except Exception as e:
        stats['errors'] += 1
    finally:
        writer.close()

async def main():
    print(f"Starting {NUM_CLIENTS} concurrent clients for {DURATION} seconds...")
    start_time = time.time()

    tasks = [asyncio.create_task(client_task(i)) for i in range(NUM_CLIENTS)]
    await asyncio.gather(*tasks)

    elapsed = time.time() - start_time

    mb_sent = stats['bytes_sent'] / (1024 * 1024)
    mb_recv = stats['bytes_recv'] / (1024 * 1024)

    print("\n--- Benchmark Results ---")
    print(f"Duration:         {elapsed:.2f} seconds")
    print(f"Connected:        {stats['connected']} clients")
    print(f"Errors:           {stats['errors']}")
    print(f"Total Sent:       {mb_sent:.2f} MB")
    print(f"Total Received:   {mb_recv:.2f} MB")
    print(f"Throughput (TX):  {mb_sent / elapsed:.2f} MB/s")
    print(f"Throughput (RX):  {mb_recv / elapsed:.2f} MB/s")

if __name__ == '__main__':
    asyncio.run(main())
