#!/usr/bin/env python3
"""Verify LLPS PXF audit records, optionally authenticating HMAC rows."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import pathlib
import sys
import zlib


AUDIT_FIELDS = (
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
ENDPOINT_FIELDS = ("seq", "role", "host", "port")
MAC_FIELDS = ("seq", "key_fingerprint", "hmac_sha256")
EVIDENCE_MAC_FIELDS = ("seq", "key_fingerprint", "hmac_sha256")
EVIDENCE_FIELDS = (
    "seq",
    "event",
    "time_ns",
    "status",
    "failure_mask",
    "monitor_passes",
    "software_evidence_patrol",
    "synthetic_ecc_topology_patrol",
    "synthetic_ecc_topology_patrol_failures",
    "synthetic_fault_patrol",
    "synthetic_fault_patrol_failures",
    "synthetic_numa_patrol",
    "synthetic_numa_patrol_failures",
    "require_readiness",
    "platform_evidence_mode",
    "software_ecc_enabled",
    "software_numa_enabled",
    "software_fault_injection_mode",
    "crc32",
)
ENDPOINT_ROLES = frozenset(("client", "listen", "target", "backend"))
EVENT_TYPES = {
    "accept": 0,
    "drop": 1,
    "backend_connect": 2,
    "backend_fail": 3,
    "close": 4,
}
CLIENT_IP_TEXT_LEN = 16
HOST_TEXT_LEN = 256
REASON_TEXT_LEN = 32
KEY_BYTES_MAX = 128
HOST_TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "._-:"
)
REASON_TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_-"
)


class VerificationError(RuntimeError):
    """Raised when a PXF audit document cannot be authenticated."""


def require_uint(text: str, line_no: int, field: str) -> None:
    if not text.isdecimal():
        raise VerificationError(f"PXF line {line_no}: {field} is not unsigned decimal")


def require_u16(text: str, line_no: int, field: str) -> None:
    require_uint(text, line_no, field)
    if int(text) > 65535:
        raise VerificationError(f"PXF line {line_no}: {field} exceeds u16 range")


def require_hex32(text: str, line_no: int, field: str) -> None:
    if (
        len(text) != 10
        or not text.startswith("0x")
        or any(ch not in "0123456789abcdefABCDEF" for ch in text[2:])
    ):
        raise VerificationError(f"PXF line {line_no}: malformed {field}")


def require_hex256(text: str, line_no: int, field: str) -> None:
    if len(text) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in text):
        raise VerificationError(f"PXF line {line_no}: malformed {field}")


def require_safe_token(
    text: str,
    line_no: int,
    field: str,
    allowed_chars: frozenset[str],
    cap: int,
) -> None:
    try:
        encoded = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise VerificationError(f"PXF line {line_no}: unsafe {field}") from exc

    if not encoded or len(encoded) >= cap:
        raise VerificationError(f"PXF line {line_no}: unsafe {field}")
    if any(ch not in allowed_chars for ch in text):
        raise VerificationError(f"PXF line {line_no}: unsafe {field}")


def find_record_for_related_row(
    records: list[dict[str, object]],
    seq: str,
    relation: str,
) -> dict[str, object]:
    for entry in reversed(records):
        record = entry["record"]
        if not isinstance(record, dict):
            continue
        if record.get("seq") != seq:
            continue
        if relation == "endpoint":
            return entry
        if relation == "mac" and entry.get("mac") is None:
            return entry

    raise VerificationError(f"PXF audit seq {seq}: orphan {relation} row")


def parse_pxf(text: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    records: list[dict[str, object]] = []
    evidence_records: list[dict[str, object]] = []
    saw_audit_table = False
    saw_endpoint_table = False
    saw_mac_table = False
    saw_evidence_table = False
    saw_evidence_mac_table = False
    lines = text.splitlines()

    if not lines or lines[0] != "pxf/1":
        raise VerificationError("PXF document must start with pxf/1")

    for line_no, line in enumerate(lines[1:], start=2):
        if line == "" or line.startswith("#"):
            continue

        if line.startswith("@table "):
            tokens = line.split()
            if len(tokens) < 3:
                raise VerificationError(f"PXF line {line_no}: unsupported table")
            if tokens[1] == "audit":
                saw_audit_table = True
            elif tokens[1] == "audit_endpoint":
                saw_endpoint_table = True
            elif tokens[1] == "audit_mac":
                saw_mac_table = True
            elif tokens[1] == "evidence":
                saw_evidence_table = True
            elif tokens[1] == "evidence_mac":
                saw_evidence_mac_table = True
            else:
                raise VerificationError(f"PXF line {line_no}: unsupported table")
            continue

        if line.startswith("@"):
            continue

        tokens = line.split()
        if not tokens:
            continue

        if tokens[0] == "+audit":
            if not saw_audit_table:
                raise VerificationError(f"PXF line {line_no}: +audit before @table")
            if len(tokens) != len(AUDIT_FIELDS) + 1:
                raise VerificationError(f"PXF line {line_no}: wrong +audit field count")
            record = dict(zip(AUDIT_FIELDS, tokens[1:]))
            for key in (
                "seq",
                "request_no",
                "event_no",
                "total_events",
                "time_ns",
                "session",
                "duration_ns",
            ):
                require_uint(record[key], line_no, key)
            require_hex32(record["crc32"], line_no, "crc32")
            if record["seq"] != record["total_events"]:
                raise VerificationError(f"PXF line {line_no}: total_events must match seq")
            if record["event"] not in EVENT_TYPES:
                raise VerificationError(f"PXF line {line_no}: unknown event")
            require_safe_token(
                record["reason"],
                line_no,
                "reason",
                REASON_TOKEN_CHARS,
                REASON_TEXT_LEN,
            )
            records.append({"record": record, "endpoints": {}, "mac": None})
            continue

        if tokens[0] == "+audit_endpoint":
            if not saw_endpoint_table:
                raise VerificationError(f"PXF line {line_no}: +audit_endpoint before @table")
            if len(tokens) != len(ENDPOINT_FIELDS) + 1:
                raise VerificationError(f"PXF line {line_no}: wrong +audit_endpoint field count")
            endpoint = dict(zip(ENDPOINT_FIELDS, tokens[1:]))
            require_uint(endpoint["seq"], line_no, "seq")
            require_u16(endpoint["port"], line_no, "port")
            if endpoint["role"] not in ENDPOINT_ROLES:
                raise VerificationError(f"PXF line {line_no}: unknown endpoint role")
            cap = HOST_TEXT_LEN
            if endpoint["role"] in ("client", "backend"):
                cap = CLIENT_IP_TEXT_LEN
            require_safe_token(
                endpoint["host"],
                line_no,
                f"{endpoint['role']} host",
                HOST_TOKEN_CHARS,
                cap,
            )
            entry = find_record_for_related_row(records, endpoint["seq"], "endpoint")
            endpoints = entry["endpoints"]
            if not isinstance(endpoints, dict):
                raise VerificationError(f"PXF line {line_no}: invalid endpoint state")
            if endpoint["role"] in endpoints:
                raise VerificationError(f"PXF line {line_no}: duplicate endpoint role")
            endpoints[endpoint["role"]] = endpoint
            continue

        if tokens[0] == "+audit_mac":
            if not saw_mac_table:
                raise VerificationError(f"PXF line {line_no}: +audit_mac before @table")
            if len(tokens) != len(MAC_FIELDS) + 1:
                raise VerificationError(f"PXF line {line_no}: wrong +audit_mac field count")
            mac_record = dict(zip(MAC_FIELDS, tokens[1:]))
            require_uint(mac_record["seq"], line_no, "seq")
            require_hex32(mac_record["key_fingerprint"], line_no, "key_fingerprint")
            require_hex256(mac_record["hmac_sha256"], line_no, "hmac_sha256")
            entry = find_record_for_related_row(records, mac_record["seq"], "mac")
            entry["mac"] = mac_record
            continue

        if tokens[0] == "+evidence":
            if not saw_evidence_table:
                raise VerificationError(f"PXF line {line_no}: +evidence before @table")
            if len(tokens) != len(EVIDENCE_FIELDS) + 1:
                raise VerificationError(f"PXF line {line_no}: wrong +evidence field count")
            evidence = dict(zip(EVIDENCE_FIELDS, tokens[1:]))
            for key in (
                "seq",
                "time_ns",
                "monitor_passes",
                "software_evidence_patrol",
                "synthetic_ecc_topology_patrol",
                "synthetic_ecc_topology_patrol_failures",
                "synthetic_fault_patrol",
                "synthetic_fault_patrol_failures",
                "synthetic_numa_patrol",
                "synthetic_numa_patrol_failures",
            ):
                require_uint(evidence[key], line_no, key)
            for key in (
                "status",
                "failure_mask",
                "require_readiness",
                "platform_evidence_mode",
                "software_ecc_enabled",
                "software_numa_enabled",
                "software_fault_injection_mode",
                "crc32",
            ):
                require_hex32(evidence[key], line_no, key)
            require_safe_token(
                evidence["event"],
                line_no,
                "evidence event",
                REASON_TOKEN_CHARS,
                REASON_TEXT_LEN,
            )
            expected_seq = len(evidence_records) + 1
            if int(evidence["seq"]) != expected_seq:
                raise VerificationError(
                    f"PXF evidence seq {evidence['seq']}: expected sequential seq {expected_seq}"
                )
            evidence_records.append({"record": evidence, "mac": None})
            continue

        if tokens[0] == "+evidence_mac":
            if not saw_evidence_mac_table:
                raise VerificationError(f"PXF line {line_no}: +evidence_mac before @table")
            if len(tokens) != len(EVIDENCE_MAC_FIELDS) + 1:
                raise VerificationError(f"PXF line {line_no}: wrong +evidence_mac field count")
            mac_record = dict(zip(EVIDENCE_MAC_FIELDS, tokens[1:]))
            require_uint(mac_record["seq"], line_no, "seq")
            require_hex32(mac_record["key_fingerprint"], line_no, "key_fingerprint")
            require_hex256(mac_record["hmac_sha256"], line_no, "hmac_sha256")
            for entry in reversed(evidence_records):
                record = entry["record"]
                if not isinstance(record, dict):
                    continue
                if record.get("seq") == mac_record["seq"] and entry.get("mac") is None:
                    entry["mac"] = mac_record
                    break
            else:
                raise VerificationError(
                    f"PXF evidence seq {mac_record['seq']}: orphan evidence_mac row"
                )
            continue

        raise VerificationError(
            "PXF line "
            f"{line_no}: expected +audit, +audit_endpoint, +audit_mac, +evidence, or +evidence_mac row"
        )

    if not (saw_audit_table and saw_endpoint_table):
        raise VerificationError("PXF audit and endpoint tables are required")
    if not records:
        raise VerificationError("PXF audit log is empty")

    return records, evidence_records


def load_key(path: pathlib.Path) -> bytes:
    key = path.read_bytes()
    if not key or len(key) > KEY_BYTES_MAX:
        raise VerificationError("audit MAC key must be 1..128 bytes")
    return key


def key_fingerprint(key: bytes) -> str:
    value = zlib.crc32(key) & 0xFFFFFFFF
    if value == 0:
        value = 0xFFFFFFFF
    return f"0x{value:08x}"


def crc32_update_byte(crc: int, byte: int) -> int:
    crc ^= byte
    for _ in range(8):
        mask = 0xFFFFFFFF if (crc & 1) else 0
        crc = ((crc >> 1) ^ (0xEDB88320 & mask)) & 0xFFFFFFFF
    return crc


def crc32_update_u32(crc: int, value: int) -> int:
    for shift in range(0, 32, 8):
        crc = crc32_update_byte(crc, (value >> shift) & 0xFF)
    return crc


def crc32_update_u64(crc: int, value: int) -> int:
    for shift in range(0, 64, 8):
        crc = crc32_update_byte(crc, (value >> shift) & 0xFF)
    return crc


def crc32_update_cstr_bounded(crc: int, text: str, cap: int, field: str) -> int:
    data = text.encode("ascii")
    if len(data) >= cap:
        raise VerificationError(f"{field} exceeds bounded C string capacity")
    for byte in data:
        crc = crc32_update_byte(crc, byte)
    return crc32_update_byte(crc, 0)


def audit_crc32(record: dict[str, str], endpoints: dict[str, dict[str, str]]) -> str:
    crc = 0xFFFFFFFF
    crc = crc32_update_u64(crc, int(record["seq"]))
    crc = crc32_update_u64(crc, int(record["request_no"]))
    crc = crc32_update_u64(crc, int(record["event_no"]))
    crc = crc32_update_u64(crc, int(record["total_events"]))
    crc = crc32_update_u32(crc, EVENT_TYPES[record["event"]])
    crc = crc32_update_u64(crc, int(record["time_ns"]))
    crc = crc32_update_u64(crc, int(record["duration_ns"]))
    crc = crc32_update_u32(crc, int(record["session"]))
    crc = crc32_update_cstr_bounded(
        crc,
        endpoints["client"]["host"],
        CLIENT_IP_TEXT_LEN,
        "client host",
    )
    crc = crc32_update_u32(crc, int(endpoints["client"]["port"]))
    crc = crc32_update_cstr_bounded(
        crc,
        endpoints["listen"]["host"],
        HOST_TEXT_LEN,
        "listen host",
    )
    crc = crc32_update_u32(crc, int(endpoints["listen"]["port"]))
    crc = crc32_update_cstr_bounded(
        crc,
        endpoints["target"]["host"],
        HOST_TEXT_LEN,
        "target host",
    )
    crc = crc32_update_u32(crc, int(endpoints["target"]["port"]))
    crc = crc32_update_cstr_bounded(
        crc,
        endpoints["backend"]["host"],
        CLIENT_IP_TEXT_LEN,
        "backend host",
    )
    crc = crc32_update_u32(crc, int(endpoints["backend"]["port"]))
    crc = crc32_update_cstr_bounded(crc, record["reason"], REASON_TEXT_LEN, "reason")
    return f"0x{crc ^ 0xFFFFFFFF:08x}"


def hex32_value(text: str) -> int:
    return int(text, 16)


def evidence_crc32(record: dict[str, str]) -> str:
    crc = 0xFFFFFFFF
    crc = crc32_update_u64(crc, int(record["seq"]))
    crc = crc32_update_cstr_bounded(
        crc,
        record["event"],
        REASON_TEXT_LEN,
        "evidence event",
    )
    crc = crc32_update_u64(crc, int(record["time_ns"]))
    crc = crc32_update_u32(crc, hex32_value(record["status"]))
    crc = crc32_update_u32(crc, hex32_value(record["failure_mask"]))
    crc = crc32_update_u64(crc, int(record["monitor_passes"]))
    crc = crc32_update_u64(crc, int(record["software_evidence_patrol"]))
    crc = crc32_update_u64(crc, int(record["synthetic_ecc_topology_patrol"]))
    crc = crc32_update_u64(
        crc,
        int(record["synthetic_ecc_topology_patrol_failures"]),
    )
    crc = crc32_update_u64(crc, int(record["synthetic_fault_patrol"]))
    crc = crc32_update_u64(crc, int(record["synthetic_fault_patrol_failures"]))
    crc = crc32_update_u64(crc, int(record["synthetic_numa_patrol"]))
    crc = crc32_update_u64(crc, int(record["synthetic_numa_patrol_failures"]))
    crc = crc32_update_u32(crc, hex32_value(record["require_readiness"]))
    crc = crc32_update_u32(crc, hex32_value(record["platform_evidence_mode"]))
    crc = crc32_update_u32(crc, hex32_value(record["software_ecc_enabled"]))
    crc = crc32_update_u32(crc, hex32_value(record["software_numa_enabled"]))
    crc = crc32_update_u32(
        crc,
        hex32_value(record["software_fault_injection_mode"]),
    )
    return f"0x{crc ^ 0xFFFFFFFF:08x}"


def build_evidence_mac_message(record: dict[str, str]) -> bytes:
    parts = [
        "evidence/v1",
        record["seq"],
        record["event"],
        record["time_ns"],
        record["status"].lower(),
        record["failure_mask"].lower(),
        record["monitor_passes"],
        record["software_evidence_patrol"],
        record["synthetic_ecc_topology_patrol"],
        record["synthetic_ecc_topology_patrol_failures"],
        record["synthetic_fault_patrol"],
        record["synthetic_fault_patrol_failures"],
        record["synthetic_numa_patrol"],
        record["synthetic_numa_patrol_failures"],
        record["require_readiness"].lower(),
        record["platform_evidence_mode"].lower(),
        record["software_ecc_enabled"].lower(),
        record["software_numa_enabled"].lower(),
        record["software_fault_injection_mode"].lower(),
        record["crc32"].lower(),
    ]
    return "|".join(parts).encode("ascii")


def build_mac_message(
    record: dict[str, str],
    endpoints: dict[str, dict[str, str]],
) -> bytes:
    parts = [
        "audit/v1",
        record["seq"],
        record["request_no"],
        record["event"],
        record["event_no"],
        record["total_events"],
        record["time_ns"],
        record["session"],
        record["reason"],
        record["duration_ns"],
        record["crc32"].lower(),
        endpoints["client"]["host"],
        endpoints["client"]["port"],
        endpoints["listen"]["host"],
        endpoints["listen"]["port"],
        endpoints["target"]["host"],
        endpoints["target"]["port"],
        endpoints["backend"]["host"],
        endpoints["backend"]["port"],
    ]
    return "|".join(parts).encode("ascii")


def verify(
    audit_path: pathlib.Path,
    key_path: pathlib.Path | None,
    require_mac: bool,
    min_records: int,
    min_evidence_records: int,
    required_events: tuple[str, ...],
    required_evidence_events: tuple[str, ...],
    require_nonzero_request_no: bool,
    require_closed_requests: bool,
    require_sequential_seq: bool,
) -> tuple[int, int, int, int, str | None]:
    key: bytes | None = None
    expected_fingerprint: str | None = None
    if key_path is not None:
        key = load_key(key_path)
        expected_fingerprint = key_fingerprint(key)
        require_mac = True
    elif require_mac:
        raise VerificationError("--require-mac needs --key")

    records, evidence_records = parse_pxf(
        audit_path.read_text(encoding="utf-8", errors="strict")
    )
    mac_count = 0
    evidence_mac_count = 0
    events_seen: set[str] = set()
    evidence_events_seen: set[str] = set()
    accepted_requests: set[str] = set()
    closed_requests: set[str] = set()

    if min_records < 1:
        raise VerificationError("--min-records must be at least 1")
    if min_evidence_records < 0:
        raise VerificationError("--min-evidence-records must not be negative")

    for index, entry in enumerate(records, start=1):
        record_obj = entry["record"]
        endpoints_obj = entry["endpoints"]
        mac_obj = entry["mac"]
        if not isinstance(record_obj, dict) or not isinstance(endpoints_obj, dict):
            raise VerificationError("invalid parsed PXF state")

        record: dict[str, str] = record_obj
        endpoints: dict[str, dict[str, str]] = endpoints_obj
        seq = record["seq"]
        event = record["event"]
        events_seen.add(event)
        if event == "accept":
            accepted_requests.add(record["request_no"])
        if event == "close":
            closed_requests.add(record["request_no"])
        if mac_obj is not None:
            mac_count += 1

        if require_sequential_seq and (int(seq) != index):
            raise VerificationError(
                f"PXF audit seq {seq}: expected sequential seq {index}"
            )
        if require_nonzero_request_no and (record["request_no"] == "0"):
            raise VerificationError(f"PXF audit seq {seq}: request_no is zero")

        missing_roles = sorted(ENDPOINT_ROLES - set(endpoints))
        if missing_roles:
            raise VerificationError(f"PXF audit seq {seq}: missing endpoint roles {missing_roles!r}")
        expected_crc = audit_crc32(record, endpoints)
        if record["crc32"].lower() != expected_crc:
            raise VerificationError(f"PXF audit seq {seq}: CRC mismatch")

        mac_record = mac_obj
        if require_mac and mac_record is None:
            raise VerificationError(f"PXF audit seq {seq}: missing audit_mac row")
        if key is None:
            continue

        if mac_record is None:
            raise VerificationError(f"PXF audit seq {seq}: missing audit_mac row")
        if not isinstance(mac_record, dict):
            raise VerificationError(f"PXF audit seq {seq}: invalid audit_mac row")
        if mac_record["key_fingerprint"].lower() != expected_fingerprint:
            raise VerificationError(f"PXF audit seq {seq}: key fingerprint mismatch")

        message = build_mac_message(record, endpoints)
        expected_mac = hmac.new(key, message, hashlib.sha256).hexdigest()
        if mac_record["hmac_sha256"].lower() != expected_mac:
            raise VerificationError(f"PXF audit seq {seq}: HMAC mismatch")

    for entry in evidence_records:
        evidence_obj = entry["record"]
        evidence_mac_obj = entry["mac"]
        if not isinstance(evidence_obj, dict):
            raise VerificationError("invalid parsed PXF evidence state")

        evidence: dict[str, str] = evidence_obj
        evidence_events_seen.add(evidence["event"])
        expected_crc = evidence_crc32(evidence)
        if evidence["crc32"].lower() != expected_crc:
            raise VerificationError(
                f"PXF evidence seq {evidence['seq']}: CRC mismatch"
            )

        if evidence_mac_obj is not None:
            evidence_mac_count += 1
        if require_mac and evidence_mac_obj is None:
            raise VerificationError(
                f"PXF evidence seq {evidence['seq']}: missing evidence_mac row"
            )
        if key is None:
            continue

        if evidence_mac_obj is None:
            raise VerificationError(
                f"PXF evidence seq {evidence['seq']}: missing evidence_mac row"
            )
        if not isinstance(evidence_mac_obj, dict):
            raise VerificationError(
                f"PXF evidence seq {evidence['seq']}: invalid evidence_mac row"
            )
        if evidence_mac_obj["key_fingerprint"].lower() != expected_fingerprint:
            raise VerificationError(
                f"PXF evidence seq {evidence['seq']}: key fingerprint mismatch"
            )

        message = build_evidence_mac_message(evidence)
        expected_mac = hmac.new(key, message, hashlib.sha256).hexdigest()
        if evidence_mac_obj["hmac_sha256"].lower() != expected_mac:
            raise VerificationError(
                f"PXF evidence seq {evidence['seq']}: HMAC mismatch"
            )

    if len(records) < min_records:
        raise VerificationError(
            f"PXF audit log has {len(records)} records, expected at least {min_records}"
        )
    if len(evidence_records) < min_evidence_records:
        raise VerificationError(
            "PXF audit log has "
            f"{len(evidence_records)} evidence records, expected at least "
            f"{min_evidence_records}"
        )
    missing_events = sorted(set(required_events) - events_seen)
    if missing_events:
        raise VerificationError(f"PXF audit log missing events {missing_events!r}")
    missing_evidence_events = sorted(
        set(required_evidence_events) - evidence_events_seen
    )
    if missing_evidence_events:
        raise VerificationError(
            f"PXF audit log missing evidence events {missing_evidence_events!r}"
        )
    if require_closed_requests:
        missing_close = sorted(accepted_requests - closed_requests)
        if missing_close:
            raise VerificationError(
                f"PXF audit accepted request_no values missing close {missing_close!r}"
            )

    return (
        len(records),
        mac_count,
        len(evidence_records),
        evidence_mac_count,
        expected_fingerprint,
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-log", required=True, type=pathlib.Path)
    parser.add_argument("--key", type=pathlib.Path)
    parser.add_argument(
        "--require-mac",
        action="store_true",
        help="fail unless every audit record has a matching audit_mac row",
    )
    parser.add_argument(
        "--min-records",
        type=int,
        default=1,
        help="fail unless the audit log contains at least this many records",
    )
    parser.add_argument(
        "--min-evidence-records",
        type=int,
        default=0,
        help="fail unless the audit log contains at least this many evidence records",
    )
    parser.add_argument(
        "--require-event",
        action="append",
        choices=sorted(EVENT_TYPES),
        default=[],
        help="fail unless the audit log contains this event; may be repeated",
    )
    parser.add_argument(
        "--require-evidence-event",
        action="append",
        default=[],
        help="fail unless the audit log contains this evidence event; may be repeated",
    )
    parser.add_argument(
        "--require-nonzero-request-no",
        action="store_true",
        help="fail if any audit record has request_no=0",
    )
    parser.add_argument(
        "--require-closed-requests",
        action="store_true",
        help="fail if an accepted request_no does not have a close event",
    )
    parser.add_argument(
        "--require-sequential-seq",
        action="store_true",
        help="fail unless seq values are contiguous starting at 1",
    )
    args = parser.parse_args(argv)

    try:
        count, mac_count, evidence_count, evidence_mac_count, fingerprint = verify(
            args.audit_log,
            args.key,
            args.require_mac,
            args.min_records,
            args.min_evidence_records,
            tuple(args.require_event),
            tuple(args.require_evidence_event),
            args.require_nonzero_request_no,
            args.require_closed_requests,
            args.require_sequential_seq,
        )
    except (OSError, UnicodeDecodeError, VerificationError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if fingerprint is None:
        print(
            f"OK: verified {count} audit CRC rows; "
            f"audit_mac_rows={mac_count}; evidence_rows={evidence_count}; "
            f"evidence_mac_rows={evidence_mac_count}"
        )
    else:
        print(
            f"OK: verified {count} audit CRC rows and {mac_count} audit MAC rows "
            f"with key_fingerprint={fingerprint}; evidence_rows={evidence_count}; "
            f"evidence_mac_rows={evidence_mac_count}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
