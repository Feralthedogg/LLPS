#!/usr/bin/env python3
"""Run a local chat-server -> LLPS -> chat-client smoke test."""

import argparse
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Optional


ROOT = pathlib.Path(__file__).resolve().parents[1]
PXF_AUDIT_FIELDS = (
    "seq",
    "request_no",
    "event",
    "event_no",
    "total_events",
    "time_ns",
    "session",
    "reason",
    "duration_ns",
    "crc32",
)
PXF_ENDPOINT_FIELDS = ("seq", "role", "host", "port")
PXF_MAC_FIELDS = ("seq", "key_fingerprint", "hmac_sha256")
PXF_EVENTS = frozenset(("accept", "drop", "backend_connect", "backend_fail", "close"))
PXF_ENDPOINT_ROLES = frozenset(("client", "listen", "target", "backend"))


def log(message: str) -> None:
    print(f"[smoke] {message}", flush=True)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def stream_output(proc: subprocess.Popen[str], label: str) -> threading.Thread:
    def run() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(f"[{label}] {line}", end="", flush=True)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def terminate(proc: Optional[subprocess.Popen[str]]) -> None:
    if proc is None:
        return
    if proc.poll() is not None:
        return

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def wait_tcp(host: str, port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for {host}:{port}: {last_error}")


def recv_until(sock: socket.socket, token: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    data = bytearray()
    token_bytes = token.encode("utf-8")

    while time.monotonic() < deadline:
        sock.settimeout(max(0.05, min(0.2, deadline - time.monotonic())))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue

        if not chunk:
            break

        data.extend(chunk)
        if token_bytes in data:
            return data.decode("utf-8", errors="replace")

    text = data.decode("utf-8", errors="replace")
    raise RuntimeError(f"did not receive token {token!r}; received: {text!r}")


def default_llps_path() -> pathlib.Path:
    for candidate in (ROOT / "build-test" / "llps", ROOT / "build" / "llps"):
        if candidate.exists():
            return candidate
    return ROOT / "build-test" / "llps"


def audit_requests_missing_close(records: list[dict[str, str]]) -> set[str]:
    accepted = {record["request_no"] for record in records if record["event"] == "accept"}
    closed = {record["request_no"] for record in records if record["event"] == "close"}
    return accepted - closed


def wait_pxf_records(
    path: pathlib.Path,
    tokens: tuple[str, ...],
    timeout: float,
    require_closed_sessions: bool,
) -> list[dict[str, str]]:
    deadline = time.monotonic() + timeout
    text = ""
    last_error: Optional[Exception] = None

    while time.monotonic() < deadline:
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if all(token in text for token in tokens):
                try:
                    records = parse_pxf_records(text)
                    missing_close = audit_requests_missing_close(records)
                    if (not require_closed_sessions) or (not missing_close):
                        return records
                    last_error = RuntimeError(
                        f"accepted request_no values still missing close: "
                        f"{sorted(missing_close)!r}"
                    )
                except RuntimeError as exc:
                    last_error = exc
        time.sleep(0.05)

    if last_error is not None:
        raise RuntimeError(f"PXF audit log did not stabilize: {last_error}") from last_error
    raise RuntimeError(f"audit log missing {tokens!r}; received: {text!r}")


def require_uint(record: dict[str, str], key: str, line_no: int) -> None:
    if not record[key].isdigit():
        raise RuntimeError(f"PXF line {line_no}: {key} is not unsigned decimal")


def require_crc32(record: dict[str, str], line_no: int) -> None:
    value = record["crc32"]
    hexdigits = "0123456789abcdefABCDEF"
    if (
        len(value) != 10
        or not value.startswith("0x")
        or any(ch not in hexdigits for ch in value[2:])
    ):
        raise RuntimeError(f"PXF line {line_no}: malformed crc32")


def parse_pxf_records(text: str) -> list[dict[str, str]]:
    records_by_seq: dict[str, dict[str, str]] = {}
    endpoints_by_seq: dict[str, dict[str, dict[str, str]]] = {}
    mac_by_seq: dict[str, dict[str, str]] = {}
    lines = text.splitlines()
    saw_audit_table = False
    saw_endpoint_table = False
    saw_mac_table = False

    if (not lines) or (lines[0] != "pxf/1"):
        raise RuntimeError("PXF document must start with pxf/1")

    for line_no, line in enumerate(lines[1:], start=2):
        if line == "":
            continue

        if line.startswith("#"):
            continue

        if line.startswith("@table "):
            tokens = line.split()
            if len(tokens) < 3:
                raise RuntimeError(f"PXF line {line_no}: unsupported table")
            if tokens[1] == "audit":
                saw_audit_table = True
            elif tokens[1] == "audit_endpoint":
                saw_endpoint_table = True
            elif tokens[1] == "audit_mac":
                saw_mac_table = True
            else:
                raise RuntimeError(f"PXF line {line_no}: unsupported table")
            continue

        if line.startswith("@"):
            continue

        tokens = line.split()
        if len(tokens) == 0:
            continue

        if not (saw_audit_table and saw_endpoint_table):
            raise RuntimeError(f"PXF line {line_no}: +audit appears before @table")

        if tokens[0] == "+audit":
            if len(tokens) != (len(PXF_AUDIT_FIELDS) + 1):
                raise RuntimeError(f"PXF line {line_no}: wrong +audit field count")
            record = dict(zip(PXF_AUDIT_FIELDS, tokens[1:]))
            if record["seq"] in records_by_seq:
                raise RuntimeError(f"PXF line {line_no}: duplicate audit seq")
            if record["event"] not in PXF_EVENTS:
                raise RuntimeError(f"PXF line {line_no}: unknown event {record['event']!r}")
            for key in (
                "seq",
                "request_no",
                "event_no",
                "total_events",
                "time_ns",
                "session",
                "duration_ns",
            ):
                require_uint(record, key, line_no)
            if record["total_events"] != record["seq"]:
                raise RuntimeError(f"PXF line {line_no}: total_events must match seq")
            require_crc32(record, line_no)
            records_by_seq[record["seq"]] = record
            continue

        if tokens[0] == "+audit_mac":
            if not saw_mac_table:
                raise RuntimeError(f"PXF line {line_no}: +audit_mac before @table")
            if len(tokens) != (len(PXF_MAC_FIELDS) + 1):
                raise RuntimeError(f"PXF line {line_no}: wrong +audit_mac field count")
            mac_record = dict(zip(PXF_MAC_FIELDS, tokens[1:]))
            require_uint(mac_record, "seq", line_no)
            if (
                len(mac_record["key_fingerprint"]) != 10
                or not mac_record["key_fingerprint"].startswith("0x")
                or any(ch not in "0123456789abcdefABCDEF" for ch in mac_record["key_fingerprint"][2:])
            ):
                raise RuntimeError(f"PXF line {line_no}: malformed key fingerprint")
            if (
                len(mac_record["hmac_sha256"]) != 64
                or any(ch not in "0123456789abcdefABCDEF" for ch in mac_record["hmac_sha256"])
            ):
                raise RuntimeError(f"PXF line {line_no}: malformed hmac_sha256")
            if mac_record["seq"] in mac_by_seq:
                raise RuntimeError(f"PXF line {line_no}: duplicate audit mac seq")
            mac_by_seq[mac_record["seq"]] = mac_record
            continue

        if tokens[0] != "+audit_endpoint":
            raise RuntimeError(
                f"PXF line {line_no}: expected +audit, +audit_endpoint, or +audit_mac row"
            )

        if len(tokens) != (len(PXF_ENDPOINT_FIELDS) + 1):
            raise RuntimeError(f"PXF line {line_no}: wrong +audit field count")

        endpoint = dict(zip(PXF_ENDPOINT_FIELDS, tokens[1:]))
        require_uint(endpoint, "seq", line_no)
        require_uint(endpoint, "port", line_no)
        if endpoint["role"] not in PXF_ENDPOINT_ROLES:
            raise RuntimeError(f"PXF line {line_no}: unknown endpoint role")
        if endpoint["host"] == "":
            raise RuntimeError(f"PXF line {line_no}: empty endpoint host")
        endpoints = endpoints_by_seq.setdefault(endpoint["seq"], {})
        if endpoint["role"] in endpoints:
            raise RuntimeError(f"PXF line {line_no}: duplicate endpoint role")
        endpoints[endpoint["role"]] = endpoint

    if not (saw_audit_table and saw_endpoint_table):
        raise RuntimeError("PXF audit tables are missing")
    if not records_by_seq:
        raise RuntimeError("PXF audit log is empty")

    records: list[dict[str, str]] = []
    for seq, record in records_by_seq.items():
        endpoints = endpoints_by_seq.get(seq, {})
        missing_roles = sorted(PXF_ENDPOINT_ROLES - set(endpoints))
        if missing_roles:
            raise RuntimeError(f"PXF audit seq {seq}: missing endpoint roles {missing_roles!r}")
        for role, endpoint in endpoints.items():
            record[f"{role}_host"] = endpoint["host"]
            record[f"{role}_port"] = endpoint["port"]
        mac_record = mac_by_seq.get(seq)
        if mac_record is not None:
            record["audit_mac_key_fingerprint"] = mac_record["key_fingerprint"]
            record["audit_hmac_sha256"] = mac_record["hmac_sha256"]
        records.append(record)

    return records


def write_config(
    path: pathlib.Path,
    listen_port: int,
    target_port: int,
    audit_path: pathlib.Path,
) -> None:
    path.write_text(
        "\n".join(
            [
                "max_clients: 16",
                "buffer_size: 4096",
                "listen_host: 127.0.0.1",
                f"listen_port: {listen_port}",
                "target_host: 127.0.0.1",
                f"target_port: {target_port}",
                "listen_backlog: 16",
                "accept_batch_max: 4",
                "session_idle_timeout_ms: 5000",
                "payload_ecc_enabled: 0",
                "ip_audit_enabled: 1",
                f"ip_audit_path: {audit_path}",
                "audit_mac_enabled: 0",
                "audit_mac_key_path: /run/llps-secrets/llps-audit.key",
                "require_readiness: 0",
                "platform_safety_flags: 0",
                "platform_safety_evidence_id: 0",
                "platform_attestation_fingerprint: 0",
                "platform_observation_digest: 0",
                "platform_evidence_mode: real",
                "phys_mem_domain0: 0",
                "phys_mem_domain1: 0",
                "phys_mem_domain2: 0",
                "hw_tmr_domain0: 0",
                "hw_tmr_domain1: 0",
                "hw_tmr_domain2: 0",
                "hw_tmr_voter_domain: 0",
                "software_ecc_enabled: 0",
                "software_ecc_controller_count: 0",
                "software_ecc_dimm_count: 0",
                "software_ecc_scrub_rate: 0",
                "software_ecc_controller_corrected_error_count: 0",
                "software_ecc_controller_uncorrected_error_count: 0",
                "software_ecc_dimm_corrected_error_count: 0",
                "software_ecc_dimm_uncorrected_error_count: 0",
                "software_numa_enabled: 0",
                "software_numa_memtotal_kib: 0",
                "evidence_mac_enabled: 0",
                "evidence_mac_key_path: /run/llps-secrets/llps-evidence.key",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llps", type=pathlib.Path, default=default_llps_path())
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    if not args.llps.exists():
        print(f"LLPS binary not found: {args.llps}", file=sys.stderr)
        print("Build it first, for example: cmake --build build-test", file=sys.stderr)
        return 1

    server_port = free_port()
    proxy_port = free_port()
    token_a = f"hello-through-llps-{uuid.uuid4().hex[:12]}"
    token_b = f"reply-through-llps-{uuid.uuid4().hex[:12]}"
    token_c = f"client-tool-through-llps-{uuid.uuid4().hex[:12]}"

    server_proc: Optional[subprocess.Popen[str]] = None
    llps_proc: Optional[subprocess.Popen[str]] = None

    with tempfile.TemporaryDirectory(prefix="llps-chat-smoke-") as tmpdir:
        config_path = pathlib.Path(tmpdir) / "llps.yml"
        audit_path = pathlib.Path(tmpdir) / "llps-ip-audit.pxf"
        write_config(config_path, proxy_port, server_port, audit_path)

        try:
            server_cmd = [
                sys.executable,
                str(ROOT / "tools" / "chat_server.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(server_port),
            ]
            server_proc = subprocess.Popen(
                server_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            stream_output(server_proc, "target")
            wait_tcp("127.0.0.1", server_port, args.timeout)

            env = os.environ.copy()
            env.setdefault("LLPS_LOG", "1")
            env["LLPS_LOG_IO"] = "1"
            llps_cmd = [str(args.llps), "-c", str(config_path)]
            llps_proc = subprocess.Popen(
                llps_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            stream_output(llps_proc, "llps")
            wait_tcp("127.0.0.1", proxy_port, args.timeout)
            # The readiness probe is a real proxied TCP session. Give LLPS time
            # to finish its backend half-close before the assertion clients join.
            time.sleep(0.5)

            with socket.create_connection(("127.0.0.1", proxy_port), timeout=args.timeout) as c1:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=args.timeout) as c2:
                    c1.sendall((token_a + "\n").encode("utf-8"))
                    seen_c1_a = recv_until(c1, token_a, args.timeout)
                    seen_c2_a = recv_until(c2, token_a, args.timeout)
                    log(f"client1 saw: {seen_c1_a.strip()}")
                    log(f"client2 saw: {seen_c2_a.strip()}")

                    c2.sendall((token_b + "\n").encode("utf-8"))
                    seen_c1_b = recv_until(c1, token_b, args.timeout)
                    seen_c2_b = recv_until(c2, token_b, args.timeout)
                    log(f"client1 saw: {seen_c1_b.strip()}")
                    log(f"client2 saw: {seen_c2_b.strip()}")

            client_cmd = [
                sys.executable,
                str(ROOT / "tools" / "chat_client.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(proxy_port),
                "--message",
                token_c,
                "--expect",
                token_c,
                "--timeout",
                str(args.timeout),
            ]
            client_proc = subprocess.Popen(
                client_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            stream_output(client_proc, "client-tool")
            if client_proc.wait(timeout=args.timeout + 2.0) != 0:
                raise RuntimeError("standalone chat_client.py failed")

            audit_records = wait_pxf_records(
                audit_path,
                (
                    "pxf/1\n",
                    "@table audit",
                    "@table audit_endpoint",
                    "+audit",
                    "+audit_endpoint",
                    " accept ",
                    " backend_connect ",
                    " close ",
                    "127.0.0.1",
                    "0x",
                ),
                args.timeout,
                require_closed_sessions=True,
            )
            audit_events = {record["event"] for record in audit_records}
            for event in ("accept", "backend_connect", "close"):
                if event not in audit_events:
                    raise RuntimeError(f"PXF audit log missing event={event}")
            if not any(record["client_host"] == "127.0.0.1"
                       for record in audit_records):
                raise RuntimeError("PXF audit log missing localhost client endpoint")
            tracked = [
                record
                for record in audit_records
                if record["event"] in ("accept", "backend_connect", "close")
            ]
            if not tracked or any(record["request_no"] == "0" for record in tracked):
                raise RuntimeError("PXF audit log missing nonzero request_no on session events")
            request_numbers = {record["request_no"] for record in tracked}
            log(f"audit records: {len(audit_records)}")
            log(f"audit requests: {len(request_numbers)}")
            log("PASS: chat messages crossed LLPS in both directions")
            return 0
        finally:
            terminate(llps_proc)
            terminate(server_proc)


if __name__ == "__main__":
    raise SystemExit(main())
