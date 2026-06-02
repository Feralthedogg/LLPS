#!/usr/bin/env python3
"""Small TCP chat client for manual LLPS proxy testing."""

import argparse
import socket
import sys
import threading
import time
from typing import List


def reader_thread(sock: socket.socket, lines: List[str], stop: threading.Event) -> None:
    with sock.makefile("r", encoding="utf-8", errors="replace", newline="\n") as fp:
        while not stop.is_set():
            line = fp.readline()
            if line == "":
                break
            lines.append(line)
            print(line, end="", flush=True)


def wait_for_expectations(lines: List[str], expects: List[str], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = "".join(lines)
        if all(expect in text for expect in expects):
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--message", action="append", default=[])
    parser.add_argument("--expect", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    lines: List[str] = []
    stop = threading.Event()

    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        thread = threading.Thread(
            target=reader_thread,
            args=(sock, lines, stop),
            daemon=True,
        )
        thread.start()

        if args.message:
            for message in args.message:
                sock.sendall((message + "\n").encode("utf-8"))

            expects = args.expect or args.message
            if not wait_for_expectations(lines, expects, args.timeout):
                print("expected chat text did not arrive", file=sys.stderr, flush=True)
                return 1
            return 0

        try:
            for line in sys.stdin:
                sock.sendall(line.encode("utf-8"))
        finally:
            stop.set()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
