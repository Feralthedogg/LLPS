#!/usr/bin/env python3
"""Regression tests for tools/verify_pxf_audit_mac.py."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "verify_pxf_audit_mac.py"
KEY = b"fixture-key"
PXF = """pxf/1
# LLPS IP audit
@table audit seq:tok request_no:tok event:tok event_no:tok total_events:tok time_ns:tok session:tok reason:tok duration_ns:tok crc32:tok
@table audit_endpoint seq:tok role:tok host:host port:u16
@table audit_mac seq:tok key_fingerprint:tok hmac_sha256:tok
@table evidence seq:tok event:tok time_ns:tok status:tok failure_mask:tok monitor_passes:tok software_evidence_patrol:tok synthetic_ecc_topology_patrol:tok synthetic_ecc_topology_patrol_failures:tok synthetic_fault_patrol:tok synthetic_fault_patrol_failures:tok synthetic_numa_patrol:tok synthetic_numa_patrol_failures:tok require_readiness:tok platform_evidence_mode:tok software_ecc_enabled:tok software_numa_enabled:tok software_fault_injection_mode:tok crc32:tok
@table evidence_mac seq:tok key_fingerprint:tok hmac_sha256:tok
# ---- llps audit event ----
#   seq: 1
#   request_no: 7
#   event: accept
#   event_no: 1
#   total_events: 1
#   time_ns: 123456789
#   session: 3
#   reason: accepted
#   duration_ns: 987
#   crc32: 0xa37357f4
#   mac_key_fingerprint: 0x139492a9
#   hmac_sha256: 8d427fb474d9e1945b16bd3cc3c0e11f1198def85ad690a0000e81ef929ce3d7
#   endpoints:
#     client: 203.0.113.9:54321
#     listen: 127.0.0.1:25565
#     target: mc.example.com:25566
#     backend: 10.0.0.8:25566
+audit 1 7 accept 1 1 123456789 3 accepted 987 0xa37357f4
+audit_endpoint 1 client 203.0.113.9 54321
+audit_endpoint 1 listen 127.0.0.1 25565
+audit_endpoint 1 target mc.example.com 25566
+audit_endpoint 1 backend 10.0.0.8 25566
+audit_mac 1 0x139492a9 8d427fb474d9e1945b16bd3cc3c0e11f1198def85ad690a0000e81ef929ce3d7
# ---- llps readiness evidence ----
#   evidence_seq: 1
#   event: readiness_monitor_pass
#   time_ns: 123456999
#   status: 0x00000000
#   failure_mask: 0x00000000
#   monitor_passes: 1
#   software_evidence_patrol: 1
#   synthetic_ecc_topology_patrol: 1
#   synthetic_ecc_topology_patrol_failures: 0
#   synthetic_fault_patrol: 1
#   synthetic_fault_patrol_failures: 0
#   synthetic_numa_patrol: 1
#   synthetic_numa_patrol_failures: 0
#   require_readiness: 1
#   platform_evidence_mode: 1
#   software_ecc_enabled: 1
#   software_numa_enabled: 1
#   software_fault_injection_mode: 3
#   crc32: 0x73938f8c
#   evidence_mac_key_fingerprint: 0x139492a9
#   evidence_hmac_sha256: 2c30cebd517b329c64fbd27c59ad1556194c5b23695c0e86a113ccd13a8ffaf6
+evidence 1 readiness_monitor_pass 123456999 0x00000000 0x00000000 1 1 1 0 1 0 1 0 0x00000001 0x00000001 0x00000001 0x00000001 0x00000003 0x73938f8c
+evidence_mac 1 0x139492a9 2c30cebd517b329c64fbd27c59ad1556194c5b23695c0e86a113ccd13a8ffaf6
"""
PXF_CRC_ONLY = """pxf/1
# LLPS IP audit
@table audit seq:tok request_no:tok event:tok event_no:tok total_events:tok time_ns:tok session:tok reason:tok duration_ns:tok crc32:tok
@table audit_endpoint seq:tok role:tok host:host port:u16
+audit 1 7 accept 1 1 123456789 3 accepted 987 0xa37357f4
+audit_endpoint 1 client 203.0.113.9 54321
+audit_endpoint 1 listen 127.0.0.1 25565
+audit_endpoint 1 target mc.example.com 25566
+audit_endpoint 1 backend 10.0.0.8 25566
"""


def run_tool(
    log_path: pathlib.Path,
    key_path: pathlib.Path | None = None,
    require_mac: bool = False,
    extra_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    argv = [
        sys.executable,
        str(TOOL),
        "--audit-log",
        str(log_path),
    ]
    if key_path is not None:
        argv.extend(("--key", str(key_path)))
    if require_mac:
        argv.append("--require-mac")
    argv.extend(extra_args)

    return subprocess.run(
        argv,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="llps-pxf-verify-") as tmp_text:
        tmp = pathlib.Path(tmp_text)
        key_path = tmp / "audit.key"
        good_log = tmp / "good.pxf"
        crc_only_log = tmp / "crc-only.pxf"
        bad_crc_log = tmp / "bad-crc.pxf"
        bad_mac_log = tmp / "bad-mac.pxf"
        bad_evidence_log = tmp / "bad-evidence.pxf"
        bad_evidence_mac_log = tmp / "bad-evidence-mac.pxf"
        unsafe_reason_log = tmp / "unsafe-reason.pxf"
        unsafe_host_log = tmp / "unsafe-host.pxf"
        bad_port_log = tmp / "bad-port.pxf"

        key_path.write_bytes(KEY)
        good_log.write_text(PXF, encoding="utf-8")
        crc_only_log.write_text(PXF_CRC_ONLY, encoding="utf-8")
        bad_crc_log.write_text(
            PXF.replace(
                "+audit 1 7 accept 1 1 123456789 3 accepted 987 0xa37357f4",
                "+audit 1 7 accept 1 1 123456789 3 accepted 987 0xa37357f5",
            ),
            encoding="utf-8",
        )
        bad_mac_log.write_text(
            PXF.replace(
                "+audit_mac 1 0x139492a9 "
                "8d427fb474d9e1945b16bd3cc3c0e11f1198def85ad690a0000e81ef929ce3d7",
                "+audit_mac 1 0x139492a9 "
                "8d427fb474d9e1945b16bd3cc3c0e11f1198def85ad690a0000e81ef929ce3d0",
                1,
            ),
            encoding="utf-8",
        )
        bad_evidence_log.write_text(
            PXF.replace(
                "+evidence 1 readiness_monitor_pass 123456999 0x00000000 0x00000000 1 1 1 0 1 0 1 0 0x00000001 0x00000001 0x00000001 0x00000001 0x00000003 0x73938f8c",
                "+evidence 1 readiness_monitor_pass 123456999 0x00000000 0x00000000 1 1 1 0 1 0 1 0 0x00000001 0x00000001 0x00000001 0x00000001 0x00000003 0x73938f8d",
                1,
            ),
            encoding="utf-8",
        )
        bad_evidence_mac_log.write_text(
            PXF.replace(
                "+evidence_mac 1 0x139492a9 "
                "2c30cebd517b329c64fbd27c59ad1556194c5b23695c0e86a113ccd13a8ffaf6",
                "+evidence_mac 1 0x139492a9 "
                "2c30cebd517b329c64fbd27c59ad1556194c5b23695c0e86a113ccd13a8ffaf0",
                1,
            ),
            encoding="utf-8",
        )
        unsafe_reason_log.write_text(
            PXF.replace(
                "+audit 1 7 accept 1 1 123456789 3 accepted 987 0xa37357f4",
                "+audit 1 7 accept 1 1 123456789 3 accepted|forged 987 0xa37357f4",
                1,
            ),
            encoding="utf-8",
        )
        unsafe_host_log.write_text(
            PXF.replace(
                "+audit_endpoint 1 target mc.example.com 25566",
                "+audit_endpoint 1 target mc|example.com 25566",
                1,
            ),
            encoding="utf-8",
        )
        bad_port_log.write_text(
            PXF.replace(
                "+audit_endpoint 1 target mc.example.com 25566",
                "+audit_endpoint 1 target mc.example.com 70000",
                1,
            ),
            encoding="utf-8",
        )

        result = run_tool(good_log, key_path)
        require(result.returncode == 0, result.stderr)
        require("OK: verified 1 audit CRC rows and 1 audit MAC rows" in result.stdout, result.stdout)

        result = run_tool(good_log)
        require(result.returncode == 0, result.stderr)
        require("OK: verified 1 audit CRC rows; audit_mac_rows=1" in result.stdout, result.stdout)
        require("evidence_mac_rows=1" in result.stdout, result.stdout)

        result = run_tool(
            good_log,
            extra_args=(
                "--min-records",
                "1",
                "--require-event",
                "accept",
                "--require-nonzero-request-no",
                "--require-sequential-seq",
                "--min-evidence-records",
                "1",
                "--require-evidence-event",
                "readiness_monitor_pass",
            ),
        )
        require(result.returncode == 0, result.stderr)

        result = run_tool(good_log, extra_args=("--min-records", "2"))
        require(result.returncode != 0, "min-records policy unexpectedly passed")
        require("expected at least 2" in result.stderr, result.stderr)

        result = run_tool(good_log, extra_args=("--require-event", "close"))
        require(result.returncode != 0, "missing-event policy unexpectedly passed")
        require("missing events" in result.stderr, result.stderr)

        result = run_tool(good_log, extra_args=("--require-closed-requests",))
        require(result.returncode != 0, "missing-close policy unexpectedly passed")
        require("missing close" in result.stderr, result.stderr)

        result = run_tool(crc_only_log, extra_args=("--min-evidence-records", "1"))
        require(result.returncode != 0, "missing-evidence policy unexpectedly passed")
        require("evidence records" in result.stderr, result.stderr)

        result = run_tool(crc_only_log)
        require(result.returncode == 0, result.stderr)
        require("OK: verified 1 audit CRC rows; audit_mac_rows=0" in result.stdout, result.stdout)

        result = run_tool(crc_only_log, require_mac=True)
        require(result.returncode != 0, "CRC-only log unexpectedly passed require-mac")
        require("--require-mac needs --key" in result.stderr, result.stderr)

        result = run_tool(bad_crc_log, key_path)
        require(result.returncode != 0, "bad CRC log unexpectedly passed")
        require("CRC mismatch" in result.stderr, result.stderr)

        result = run_tool(bad_mac_log, key_path)
        require(result.returncode != 0, "bad MAC log unexpectedly passed")
        require("HMAC mismatch" in result.stderr, result.stderr)

        result = run_tool(bad_evidence_log)
        require(result.returncode != 0, "bad evidence log unexpectedly passed")
        require("PXF evidence seq 1: CRC mismatch" in result.stderr, result.stderr)

        result = run_tool(bad_evidence_mac_log, key_path)
        require(result.returncode != 0, "bad evidence MAC log unexpectedly passed")
        require("PXF evidence seq 1: HMAC mismatch" in result.stderr, result.stderr)

        result = run_tool(unsafe_reason_log)
        require(result.returncode != 0, "unsafe reason log unexpectedly passed")
        require("unsafe reason" in result.stderr, result.stderr)

        result = run_tool(unsafe_host_log)
        require(result.returncode != 0, "unsafe host log unexpectedly passed")
        require("unsafe target host" in result.stderr, result.stderr)

        result = run_tool(bad_port_log)
        require(result.returncode != 0, "bad port log unexpectedly passed")
        require("port exceeds u16 range" in result.stderr, result.stderr)

    print("test_verify_pxf_audit_mac passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
