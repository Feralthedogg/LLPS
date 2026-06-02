#!/usr/bin/env python3
"""Run a Dockerfile-only LLPS throughput benchmark."""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
LLPS_COMPILED_MAX_CLIENTS = 256


class BenchError(RuntimeError):
    """Raised when a benchmark step fails."""


def run(
    command: list[str],
    *,
    timeout: float | None = None,
    capture: bool = False,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    if not quiet:
        print(f"\n$ {printable}", flush=True)
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=os.environ.copy(),
            check=False,
            timeout=timeout,
            text=True,
            capture_output=capture,
        )
    except subprocess.TimeoutExpired as exc:
        raise BenchError(f"timed out after {timeout:.1f}s: {printable}") from exc

    if capture and not quiet:
        if result.stdout:
            print(result.stdout, end="", flush=True)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr, flush=True)

    if result.returncode != 0:
        if quiet:
            if result.stdout:
                print(result.stdout, end="", flush=True)
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr, flush=True)
        raise BenchError(f"command failed with exit code {result.returncode}: {printable}")
    return result


def output(command: list[str], *, timeout: float = 10.0) -> str:
    return run(command, timeout=timeout, capture=True, quiet=True).stdout


def build_target(target: str, image: str, timeout: float) -> None:
    run(
        ["docker", "build", "--target", target, "-t", image, "."],
        timeout=timeout,
        capture=True,
    )


def docker_rm(name: str) -> None:
    subprocess.run(
        ["docker", "rm", "-f", name],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
    )


def docker_network_rm(name: str) -> None:
    subprocess.run(
        ["docker", "network", "rm", name],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
    )


def wait_for_container_status(name: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_status = "unknown"

    while time.monotonic() < deadline:
        status = output(
            [
                "docker",
                "inspect",
                "-f",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                name,
            ],
            timeout=10.0,
        ).strip()
        last_status = status
        if status in ("healthy", "running"):
            print(f"{name}: {status}", flush=True)
            return
        if status in ("unhealthy", "exited", "dead"):
            raise BenchError(f"{name} entered {status} state")
        time.sleep(0.5)

    raise BenchError(f"{name} did not become healthy; last_status={last_status}")


def parse_native_summary(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in line.split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


def find_summary_line(text: str, marker: str) -> str:
    summary = ""
    for line in text.splitlines():
        index = line.find(marker)
        if index >= 0:
            summary = line[index:]
    return summary


def parse_int_field(fields: dict[str, str], key: str, summary_name: str) -> int:
    value = fields.get(key, "0")
    try:
        return int(value)
    except ValueError as exc:
        raise BenchError(
            f"{summary_name} field {key} is not an integer: {value}"
        ) from exc


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clients", type=int, default=100)
    parser.add_argument("--duration", type=float, default=5.0)
    parser.add_argument("--payload-bytes", type=int, default=65536)
    parser.add_argument("--max-clients", type=int, default=LLPS_COMPILED_MAX_CLIENTS)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--log-tail", type=int, default=80)
    parser.add_argument("--payload-ecc", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--logs", action="store_true", default=True)
    parser.add_argument("--quiet-llps-logs", action="store_false", dest="logs")
    parser.add_argument("--io-logs", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    configured_max_clients = min(args.max_clients, LLPS_COMPILED_MAX_CLIENTS)
    if args.clients > configured_max_clients:
        print(
            "FAIL: --clients exceeds the configured LLPS max_clients ceiling "
            f"({configured_max_clients})",
            file=sys.stderr,
        )
        return 2

    suffix = str(os.getpid())
    network = f"llps-bench-net-{suffix}"
    sink = f"llps-bench-target-{suffix}"
    proxy = f"llps-bench-{suffix}"
    load = f"llps-bench-load-{suffix}"
    logs_dir = ROOT / "logs"
    logs_dir.mkdir(exist_ok=True)

    load_result: subprocess.CompletedProcess[str] | None = None
    sink_logs = ""
    runtime_logs = ""

    try:
        if not args.skip_build:
            build_target("bench-sink", "llps-bench-target:local", args.timeout)
            build_target("runtime", "llps:local", args.timeout)
            build_target("bench-load", "llps-bench-load:local", args.timeout)

        docker_rm(sink)
        docker_rm(proxy)
        docker_rm(load)
        docker_network_rm(network)
        run(["docker", "network", "create", network], timeout=20.0, capture=True)

        run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                sink,
                "--network",
                network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "llps-bench-target:local",
                "25566",
                str(max(args.duration + 30.0, args.duration * 6.0)),
            ],
            timeout=20.0,
            capture=True,
        )
        wait_for_container_status(sink, args.timeout)

        run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                proxy,
                "--network",
                network,
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=1m,mode=1777",
                "-v",
                f"{logs_dir}:/var/log/llps:rw",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--ulimit",
                "nofile=65535:65535",
                "--ulimit",
                "memlock=-1:-1",
                "-e",
                "LLPS_LISTEN_HOST=0.0.0.0",
                "-e",
                "LLPS_LISTEN_PORT=25565",
                "-e",
                f"LLPS_TARGET_HOST={sink}",
                "-e",
                "LLPS_TARGET_PORT=25566",
                "-e",
                f"LLPS_MAX_CLIENTS={configured_max_clients}",
                "-e",
                "LLPS_BUFFER_SIZE=4096",
                "-e",
                "LLPS_LISTEN_BACKLOG=256",
                "-e",
                "LLPS_ACCEPT_BATCH_MAX=32",
                "-e",
                "LLPS_SESSION_IDLE_TIMEOUT_MS=30000",
                "-e",
                "LLPS_MAX_SESSIONS_PER_CLIENT_IP=0",
                "-e",
                "LLPS_MAX_NEW_SESSIONS_PER_CLIENT_IP_PER_WINDOW=0",
                "-e",
                "LLPS_CLIENT_IP_RATE_WINDOW_MS=1000",
                "-e",
                "LLPS_CLIENT_PREFACE_TIMEOUT_MS=0",
                "-e",
                "LLPS_PROTOCOL_HANDSHAKE_GATE_ENABLED=0",
                "-e",
                f"LLPS_PAYLOAD_ECC_ENABLED={1 if args.payload_ecc else 0}",
                "-e",
                f"LLPS_IP_AUDIT_ENABLED={1 if args.audit else 0}",
                "-e",
                "LLPS_IP_AUDIT_PATH=/var/log/llps/llps-bench-audit.pxf",
                "-e",
                "LLPS_AUDIT_MAC_ENABLED=0",
                "-e",
                "LLPS_REQUIRE_READINESS=0",
                "-e",
                "LLPS_LOG=1" if args.logs else "LLPS_LOG=0",
                "-e",
                "LLPS_LOG_AUDIT=0",
                "-e",
                "LLPS_LOG_EVIDENCE=0",
                "-e",
                "LLPS_LOG_IO=1" if args.io_logs else "LLPS_LOG_IO=0",
                "llps:local",
            ],
            timeout=20.0,
            capture=True,
        )
        wait_for_container_status(proxy, args.timeout)

        load_result = run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                load,
                "--network",
                network,
                "llps-bench-load:local",
                proxy,
                "25565",
                str(args.clients),
                str(args.duration),
                str(args.payload_bytes),
            ],
            timeout=args.timeout,
            capture=True,
        )

        run(["docker", "stop", sink], timeout=20.0, capture=True)
        sink_logs = output(["docker", "logs", sink], timeout=20.0)
        print(f"\nRecent benchmark logs (tail={args.log_tail})", flush=True)
        runtime_logs = output(["docker", "logs", "--tail", str(args.log_tail), proxy], timeout=20.0)
        print(runtime_logs, end="", flush=True)
        print(sink_logs, end="", flush=True)
    except BenchError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        if not args.keep_running:
            docker_rm(load)
            docker_rm(proxy)
            docker_rm(sink)
            docker_network_rm(network)

    summary = ""
    if load_result is not None:
        for line in load_result.stdout.splitlines():
            if line.startswith("native_load "):
                summary = line
                break

    if not summary:
        print("\nFAIL: Docker LLPS benchmark did not report native_load summary", file=sys.stderr)
        return 1

    try:
        metrics = parse_native_summary(summary)
        connected = parse_int_field(metrics, "connected", "native_load")
        errors = parse_int_field(metrics, "errors", "native_load")
        byte_count = parse_int_field(metrics, "bytes", "native_load")
        if connected <= 0 or errors != 0 or byte_count == 0:
            print(f"\nFAIL: Docker LLPS benchmark produced invalid result; {summary}", file=sys.stderr)
            return 1

        sink_summary = find_summary_line(sink_logs, "native_sink ")
        if not sink_summary:
            print(
                "\nFAIL: Docker LLPS benchmark did not report native_sink summary",
                file=sys.stderr,
            )
            return 1
        sink_metrics = parse_native_summary(sink_summary)
        sink_accepted = parse_int_field(sink_metrics, "accepted", "native_sink")
        sink_errors = parse_int_field(sink_metrics, "errors", "native_sink")
        sink_bytes = parse_int_field(sink_metrics, "bytes", "native_sink")
        if sink_accepted <= 0 or sink_errors != 0 or sink_bytes == 0:
            print(
                "\nFAIL: Docker LLPS benchmark backend sink produced invalid "
                f"result; {sink_summary}",
                file=sys.stderr,
            )
            return 1

        mode = "payload_ecc=1" if args.payload_ecc else "payload_ecc=0"
        sink_active_mib_per_sec = sink_metrics.get("active_mib_per_sec", "0.00")
        print(
            f"\nOK: Docker LLPS benchmark passed; {mode}; "
            f"backend_active_mib_per_sec={sink_active_mib_per_sec}; "
            f"{summary}; {sink_summary}"
        )
    except BenchError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
