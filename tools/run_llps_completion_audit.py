#!/usr/bin/env python3
"""Audit LLPS requirement coverage against current source evidence."""

from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN_TOKENS = (
    "SI" + "L4",
    "Safety Integrity Level " + "4",
    "SPDX-" + "License-Identifier",
    "Copy" + "right",
)
SCAN_PATHS = (
    "include",
    "src",
    "tests",
    "tools",
    "docker",
    "config.yml",
    "README.md",
    "CMakeLists.txt",
)
TEXT_SUFFIXES = {
    "",
    ".c",
    ".h",
    ".md",
    ".py",
    ".sh",
    ".txt",
    ".yml",
    ".yaml",
}


class AuditError(RuntimeError):
    """Raised when audit input cannot be read."""


def read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8", errors="ignore")


def text_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for name in SCAN_PATHS:
        root = ROOT / name
        if not root.exists():
            continue
        if root.is_file():
            files.append(root)
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            if path.suffix.lower() in TEXT_SUFFIXES:
                files.append(path)
    return sorted(files)


def contains(path: str, *tokens: str) -> bool:
    text = read_text(path)
    return all(token in text for token in tokens)


def file_exists(path: str) -> bool:
    return (ROOT / path).exists()


def public_header_layout_ok() -> bool:
    public_headers = sorted((ROOT / "include").rglob("*.h"))
    expected = [ROOT / "include" / "llps" / "llps.h"]
    if public_headers != expected:
        return False

    for header in (ROOT / "src").rglob("*.h"):
        rel = header.relative_to(ROOT).as_posix()
        if not rel.startswith("src/internal/"):
            return False
    return True


def no_forbidden_text() -> bool:
    for path in text_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(token in text for token in FORBIDDEN_TOKENS):
            return False
    return True


def check_cmake_test(name: str) -> bool:
    return contains("CMakeLists.txt", f"NAME {name}")


def requirement_checks() -> list[tuple[str, tuple[tuple[str, bool], ...]]]:
    return [
        (
            "forbidden_names_and_headers_removed",
            (
                ("no forbidden text in LLPS scope", no_forbidden_text()),
                ("single public header/internal private headers", public_header_layout_ok()),
                ("repo layout policy test registered", check_cmake_test("test_repo_layout_policy")),
            ),
        ),
        (
            "linux_and_llam_kept_with_runtime_contract",
            (
                (
                    "LLAM single worker predicate",
                    contains(
                        "src/support/llps_llam_contract.c",
                        "active_workers == 1u",
                        "online_workers == 1u",
                        "active_nodes == 1u",
                        "dynamic_workers == 0u",
                    ),
                ),
                (
                    "startup LLAM contract log",
                    contains(
                        "src/app/main.c",
                        "llam_runtime_contract",
                        "profile=io-latency",
                    ),
                ),
                (
                    "LLAM wrapper policy test registered",
                    check_cmake_test("test_llam_contract_wrappers"),
                ),
            ),
        ),
        (
            "free_list_single_scheduler_contract_guarded",
            (
                (
                    "free-list mutators guard scheduler contract",
                    contains(
                        "src/core/llps_state.c",
                        "llps_free_list_scheduler_contract_is_valid",
                        "llps_find_free_session",
                        "llps_return_session_to_freelist",
                    ),
                ),
                (
                    "test enforces free-list guard",
                    contains(
                        "tests/test_llam_contract_wrappers.py",
                        "verify_free_list_mutators_guard_scheduler_contract",
                    ),
                ),
            ),
        ),
        (
            "domain_targets_and_docker_env_supported",
            (
                (
                    "YAML accepts target_host and legacy target_ip",
                    contains("src/config/yml_parser.c", "target_host", "target_ip"),
                ),
                (
                    "network layer resolves host names",
                    contains("src/net/llps_net.c", "getaddrinfo", "llps_resolve_ipv4_sockaddr"),
                ),
                (
                    "Docker entrypoint exposes target host",
                    contains("docker/entrypoint.sh", "LLPS_TARGET_HOST", "target_host:"),
                ),
            ),
        ),
        (
            "docker_production_like_and_pxf_audit",
            (
                (
                    "Dockerfile-only hardening path is present",
                    contains(
                        "tools/run_docker_prod_check.py",
                        "--read-only",
                        "--cap-drop",
                        "no-new-privileges:true",
                    ) and
                    contains(
                        "Dockerfile",
                        "FROM ubuntu:24.04 AS runtime",
                        "USER llps:llps",
                    ),
                ),
                (
                    "PXF audit and MAC verifier present",
                    file_exists("tools/verify_pxf_audit_mac.py") and
                    contains("src/audit/llps_ip_audit.c", "audit_mac", "hmac_sha256"),
                ),
                (
                    "production check verifies audit detail",
                    contains(
                        "tools/run_docker_prod_check.py",
                        "verify_runtime_audit_log_detail",
                        "request_no=",
                        "mac=enabled",
                    ),
                ),
                (
                    "PXF audit carries readiness evidence rows",
                    contains(
                        "src/audit/llps_ip_audit.c",
                        "@table evidence",
                        "@table evidence_mac",
                        "+evidence",
                        "+evidence_mac",
                        "llps_ip_audit_build_evidence_mac_message",
                        "llps_ip_audit_record_evidence",
                    ) and
                    contains(
                        "tools/verify_pxf_audit_mac.py",
                        "EVIDENCE_FIELDS",
                        "EVIDENCE_MAC_FIELDS",
                        "--min-evidence-records",
                        "evidence_crc32",
                        "build_evidence_mac_message",
                        "evidence_mac_rows",
                    ),
                ),
                (
                    "production Docker check requires readiness evidence rows",
                    contains(
                        "tools/run_docker_prod_check.py",
                        "require_readiness_evidence=args.synthetic_readiness",
                        "--min-evidence-records",
                        "readiness_monitor_pass",
                    ),
                ),
            ),
        ),
        (
            "secded_payload_and_tmr_integrity",
            (
                (
                    "SECDED implementation and header present",
                    file_exists("src/support/llps_secded.c") and
                    file_exists("src/internal/llps_secded.h"),
                ),
                (
                    "payload ECC sealed in session integrity",
                    contains(
                        "src/session/llps_session_integrity.c",
                        "payload_ecc",
                        "llps_secded_encode_u32",
                    ),
                ),
                (
                    "SECDED and payload tests present",
                    contains(
                        "tests/test_llps.c",
                        "test_llps_secded_corrects_single_bit_and_detects_double_bit",
                        "test_llps_payload_ecc_fails_closed_on_double_bit_payload_fault",
                    ),
                ),
            ),
        ),
        (
            "software_ecc_numa_dimm_model",
            (
                (
                    "software evidence model present",
                    contains(
                        "src/support/llps_software_evidence.c",
                        "software_ecc",
                        "software_numa",
                        "fault_injection",
                    ),
                ),
                (
                    "config exposes software ECC/NUMA",
                    contains(
                        "config.yml",
                        "software_ecc_enabled",
                        "software_numa_enabled",
                        "software_fault_injection_mode",
                    ),
                ),
                (
                    "Docker synthetic readiness and soak tools present",
                    file_exists("tools/run_docker_synthetic_readiness_check.py") and
                    file_exists("tools/run_docker_synthetic_soak.py"),
                ),
            ),
        ),
        (
            "blocking_platform_io_offloaded_from_watchdog",
            (
                (
                    "readiness worker uses LLAM blocking offload",
                    contains(
                        "src/readiness/llps_readiness_monitor_worker.c",
                        "llam_call_blocking_result",
                        "llps_readiness_monitor_call_blocking_checked",
                    ),
                ),
                (
                    "blocking I/O policy test registered",
                    check_cmake_test("test_runtime_blocking_io_policy"),
                ),
            ),
        ),
        (
            "protocol_remote_input_gate_verified",
            (
                (
                    "Protocol invalid preface matrix present",
                    contains(
                        "tools/run_docker_prod_check.py",
                        "protocol_invalid_preface_cases",
                        "noncanonical_packet_length",
                        "oversized_address",
                    ),
                ),
                (
                    "Docker audit requires all invalid cases",
                    contains(
                        "tools/run_docker_prod_check.py",
                        "expected_invalid_count",
                        "protocol_handshake_invalid",
                    ),
                ),
                (
                    "Protocol helper test registered",
                    check_cmake_test("test_run_docker_prod_check_protocol"),
                ),
            ),
        ),
        (
            "integrated_verification_and_benchmarking",
            (
                (
                    "verification suite present",
                    file_exists("tools/run_llps_verification_suite.py"),
                ),
                (
                    "suite runs synthetic, Protocol, soak, and both benchmarks",
                    contains(
                        "tools/run_llps_verification_suite.py",
                        "docker_prod_synthetic_readiness",
                        "docker_protocol_gate",
                        "docker_synthetic_soak",
                        "docker_benchmark_baseline",
                        "docker_benchmark_payload_ecc",
                    ),
                ),
                (
                    "suite test registered",
                    check_cmake_test("test_run_llps_verification_suite"),
                ),
            ),
        ),
        (
            "verification_temp_paths_process_isolated",
            (
                (
                    "test temp serial mixes process id and mock time",
                    contains(
                        "tests/test_llps.c",
                        "test_tmp_serial",
                        "getpid() * 1000003UL",
                        "mock_llam_now_ns",
                    ),
                ),
                (
                    "generated LLPS temp paths use process-isolated serials",
                    contains(
                        "tests/test_llps.c",
                        "/tmp/llps_test_config_%lu.yml",
                        "/tmp/llps_edac_test_%lu",
                        "/tmp/llps_numa_test_%lu",
                        "/tmp/llps_protocol_handshake_reject_%lu_%s.pxf",
                    ),
                ),
            ),
        ),
        (
            "truthful_software_only_hardware_boundary",
            (
                (
                    "software evidence path remains explicitly synthetic",
                    contains(
                        "include/llps/llps.h",
                        "LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC",
                    ) and
                    contains(
                        "src/support/llps_software_evidence.c",
                        "LLPS_PLATFORM_EVIDENCE_MODE_SYNTHETIC",
                    ),
                ),
                (
                    "audit and evidence authentication use HMAC, not CRC",
                    contains(
                        "src/audit/llps_ip_audit.c",
                        "audit_mac",
                        "evidence_mac",
                        "llps_hmac_sha256_file_message",
                    ) and
                    contains(
                        "include/llps/llps.h",
                        "LLPS_PLATFORM_EVIDENCE_MAC_BYTES",
                    ),
                ),
            ),
        ),
    ]


def main() -> int:
    try:
        checks = requirement_checks()
    except OSError as exc:
        print(f"FAIL: {exc}", file=sys.stderr, flush=True)
        return 1

    failed: list[str] = []
    for requirement, evidences in checks:
        missing = [label for label, ok in evidences if not ok]
        if missing:
            print(f"audit_fail requirement={requirement}", flush=True)
            for label in missing:
                print(f"  missing={label}", flush=True)
            failed.append(requirement)
        else:
            print(f"audit_ok requirement={requirement}", flush=True)

    if failed:
        print(
            "\nFAIL: LLPS completion audit failed; "
            f"failed_requirements={len(failed)}",
            file=sys.stderr,
            flush=True,
        )
        return 1

    print(
        "\nOK: LLPS completion audit passed; "
        f"requirements={len(checks)}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
