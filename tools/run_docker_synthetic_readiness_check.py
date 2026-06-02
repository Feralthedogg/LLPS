#!/usr/bin/env python3
"""Verify Docker startup with self-tested synthetic ECC/NUMA readiness."""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "logs" / "llps-synthetic-readiness.generated.yml"
EVIDENCE_KEY_NAME = "llps-evidence.key"
EVIDENCE_KEY_BYTES_MAX = 128
CONTAINER_EVIDENCE_KEY_PATH = f"/run/llps-secrets/{EVIDENCE_KEY_NAME}"
MISSING_OBSERVATION_DIGEST_BINDING = 0x00000400


class SyntheticReadinessError(RuntimeError):
    """Raised when the synthetic readiness check fails."""


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
            check=False,
            timeout=timeout,
            text=True,
            capture_output=capture,
        )
    except subprocess.TimeoutExpired as exc:
        raise SyntheticReadinessError(
            f"timed out after {timeout:.1f}s: {printable}"
        ) from exc

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
        raise SyntheticReadinessError(
            f"command failed with exit code {result.returncode}: {printable}"
        )
    return result


def parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def require_key(values: dict[str, str], key: str) -> str:
    value = values.get(key)
    if value is None or value == "":
        raise SyntheticReadinessError(f"missing diagnostic key: {key}")
    return value


def require_value(values: dict[str, str], key: str, expected: str) -> None:
    actual = require_key(values, key)
    if actual != expected:
        raise SyntheticReadinessError(
            f"{key} expected {expected!r}, got {actual!r}"
        )


def require_same_value(
    values: dict[str, str],
    left_key: str,
    right_key: str,
) -> None:
    left = require_key(values, left_key)
    right = require_key(values, right_key)
    if left != right:
        raise SyntheticReadinessError(
            f"{left_key} expected to match {right_key}, "
            f"got {left!r} vs {right!r}"
        )


def parse_int_value(value: str, key: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise SyntheticReadinessError(
            f"{key} expected an integer, got {value!r}"
        ) from exc


def docker_run_base(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
    remove: bool = True,
) -> list[str]:
    command = [
        "docker",
        "run",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=1m,mode=1777",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--ulimit",
        "nofile=65535:65535",
        "--ulimit",
        "memlock=-1:-1",
        "-v",
        f"{config_path}:/etc/llps/synthetic-readiness.yml:ro",
        "-e",
        "LLPS_CONFIG=/etc/llps/synthetic-readiness.yml",
    ]
    if remove:
        command.insert(2, "--rm")
    if secrets_dir is not None:
        command.extend(["-v", f"{secrets_dir}:/run/llps-secrets:ro"])
    command.append(args.image)
    return command


def docker_diag(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    diagnostic_arg: str,
    *,
    secrets_dir: pathlib.Path | None,
) -> dict[str, str]:
    result = run(
        docker_run_base(config_path, args, secrets_dir=secrets_dir) +
        [diagnostic_arg],
        timeout=args.timeout,
        capture=True,
    )
    return parse_key_values(result.stdout)


def stage_evidence_mac_key(
    args: argparse.Namespace,
) -> tuple[tempfile.TemporaryDirectory[str] | None, pathlib.Path | None]:
    if not args.evidence_mac and args.evidence_key is None:
        return None, None

    staged_dir = tempfile.TemporaryDirectory(prefix="llps-readiness-secrets-")
    staged_path = pathlib.Path(staged_dir.name) / EVIDENCE_KEY_NAME
    if args.evidence_key is not None:
        source_key = args.evidence_key
        if not source_key.is_absolute():
            source_key = ROOT / source_key
        key_bytes = source_key.read_bytes()
    else:
        key_bytes = os.urandom(32)

    if (len(key_bytes) == 0) or (len(key_bytes) > EVIDENCE_KEY_BYTES_MAX):
        staged_dir.cleanup()
        raise SyntheticReadinessError("evidence MAC key must be 1..128 bytes")

    staged_path.write_bytes(key_bytes)
    staged_path.chmod(0o444)
    return staged_dir, staged_path


def stage_generated_evidence_mac_key(
    prefix: str,
    *,
    forbidden_key_path: pathlib.Path | None = None,
) -> tempfile.TemporaryDirectory[str]:
    staged_dir = tempfile.TemporaryDirectory(prefix=prefix)
    staged_path = pathlib.Path(staged_dir.name) / EVIDENCE_KEY_NAME
    key_bytes = os.urandom(32)

    if forbidden_key_path is not None:
        forbidden_bytes = forbidden_key_path.read_bytes()
        while key_bytes == forbidden_bytes:
            key_bytes = os.urandom(32)

    staged_path.write_bytes(key_bytes)
    staged_path.chmod(0o444)
    return staged_dir


def write_config(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    *,
    attestation_fingerprint: int,
    observation_digest: int,
    evidence_mac_enabled: bool,
) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    text = f"""# Generated by tools/run_docker_synthetic_readiness_check.py
max_clients: 64
buffer_size: 4096
listen_host: 0.0.0.0
listen_port: 25565
target_host: 127.0.0.1
target_port: 25566
listen_backlog: 64
accept_batch_max: 16
session_idle_timeout_ms: 30000
payload_ecc_enabled: 1
ip_audit_enabled: 0
ip_audit_path: /tmp/llps-synthetic-readiness.pxf
audit_mac_enabled: 0
audit_mac_key_path: /run/llps-secrets/llps-audit.key
require_readiness: 1
platform_safety_flags: 15
platform_safety_evidence_id: {args.evidence_id}
platform_attestation_fingerprint: {attestation_fingerprint}
platform_observation_digest: {observation_digest}
platform_evidence_mode: synthetic
phys_mem_domain0: 11
phys_mem_domain1: 22
phys_mem_domain2: 33
hw_tmr_domain0: 101
hw_tmr_domain1: 202
hw_tmr_domain2: 303
hw_tmr_voter_domain: 404
software_ecc_enabled: 1
software_ecc_controller_count: {args.software_ecc_controllers}
software_ecc_dimm_count: {args.software_ecc_dimms}
software_ecc_scrub_rate: {args.software_ecc_scrub_rate}
software_ecc_controller_corrected_error_count: {args.software_ecc_controller_corrected_errors}
software_ecc_controller_uncorrected_error_count: {args.software_ecc_controller_uncorrected_errors}
software_ecc_dimm_corrected_error_count: {args.software_ecc_dimm_corrected_errors}
software_ecc_dimm_uncorrected_error_count: {args.software_ecc_dimm_uncorrected_errors}
software_numa_enabled: 1
software_numa_memtotal_kib: {args.software_numa_memtotal_kib}
software_numa_local_distance: {args.software_numa_local_distance}
software_numa_remote_distance: {args.software_numa_remote_distance}
software_fault_injection_mode: {args.software_fault_injection_mode}
evidence_mac_enabled: {1 if evidence_mac_enabled else 0}
evidence_mac_key_path: {CONTAINER_EVIDENCE_KEY_PATH}
"""
    config_path.write_text(text, encoding="utf-8")


def replace_config_values(
    config_path: pathlib.Path,
    replacements: dict[str, str],
) -> None:
    lines = config_path.read_text(encoding="utf-8").splitlines()
    replaced: set[str] = set()

    for index, line in enumerate(lines):
        for key, value in replacements.items():
            if line.startswith(f"{key}: "):
                lines[index] = f"{key}: {value}"
                replaced.add(key)

    missing = sorted(set(replacements) - replaced)
    if missing:
        raise SyntheticReadinessError(
            "generated config did not contain keys: " + ", ".join(missing)
        )

    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def docker_diag_expect_config_rejected(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
    case_name: str,
) -> None:
    command = docker_run_base(config_path, args, secrets_dir=secrets_dir) + [
        "--print-readiness-report",
    ]
    printable = " ".join(command)
    print(f"\n$ {printable}", flush=True)
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            timeout=args.timeout,
            text=True,
            capture_output=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise SyntheticReadinessError(
            f"negative profile {case_name} timed out after "
            f"{args.timeout:.1f}s"
        ) from exc

    combined = result.stdout + result.stderr
    if result.returncode == 0:
        raise SyntheticReadinessError(
            f"negative profile {case_name} unexpectedly passed:\n"
            f"{combined}"
        )
    if "value out of range" not in combined:
        raise SyntheticReadinessError(
            f"negative profile {case_name} failed for an unexpected reason:\n"
            f"{combined}"
        )
    print(f"negative profile rejected: {case_name}", flush=True)


def verify_invalid_software_profiles_rejected(
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
    attestation_fingerprint: int,
    observation_digest: int,
    evidence_mac_enabled: bool,
) -> None:
    cases: tuple[tuple[str, dict[str, str]], ...] = (
        (
            "software_ecc_requires_payload_ecc",
            {"payload_ecc_enabled": "0"},
        ),
        (
            "software_ecc_requires_positive_controller_count",
            {"software_ecc_controller_count": "0"},
        ),
        (
            "software_ecc_requires_positive_dimm_count",
            {"software_ecc_dimm_count": "0"},
        ),
        (
            "software_ecc_requires_positive_scrub_rate",
            {"software_ecc_scrub_rate": "0"},
        ),
        (
            "software_numa_requires_memtotal",
            {"software_numa_memtotal_kib": "0"},
        ),
        (
            "software_numa_requires_remote_distance_gt_local",
            {
                "software_numa_local_distance": "20",
                "software_numa_remote_distance": "20",
            },
        ),
        (
            "software_numa_requires_distinct_domains",
            {"phys_mem_domain2": "22"},
        ),
        (
            "real_mode_rejects_software_evidence",
            {"platform_evidence_mode": "real"},
        ),
    )

    for case_name, replacements in cases:
        with tempfile.TemporaryDirectory(
            prefix=f"llps-readiness-invalid-{case_name}-"
        ) as temp_dir:
            invalid_config = pathlib.Path(temp_dir) / "synthetic-readiness.yml"
            write_config(
                invalid_config,
                args,
                attestation_fingerprint=attestation_fingerprint,
                observation_digest=observation_digest,
                evidence_mac_enabled=evidence_mac_enabled,
            )
            replace_config_values(invalid_config, replacements)
            docker_diag_expect_config_rejected(
                invalid_config,
                args,
                secrets_dir=secrets_dir,
                case_name=case_name,
            )


def verify_dirty_ecc_counter_fails_clean_gate(
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
    attestation_fingerprint: int,
    evidence_mac_enabled: bool,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="llps-readiness-dirty-ecc-counter-"
    ) as temp_dir:
        dirty_config = pathlib.Path(temp_dir) / "synthetic-readiness.yml"
        replacements = {
            "software_ecc_controller_corrected_error_count": "1",
        }
        write_config(
            dirty_config,
            args,
            attestation_fingerprint=attestation_fingerprint,
            observation_digest=0,
            evidence_mac_enabled=evidence_mac_enabled,
        )
        replace_config_values(dirty_config, replacements)
        first_report = docker_diag(
            dirty_config,
            args,
            "--print-readiness-report",
            secrets_dir=secrets_dir,
        )
        observation_digest = int(
            require_key(first_report, "platform_evidence_observation_digest"),
            0,
        )
        if observation_digest == 0:
            raise SyntheticReadinessError(
                "dirty ECC counter observation digest is zero"
            )

        write_config(
            dirty_config,
            args,
            attestation_fingerprint=attestation_fingerprint,
            observation_digest=observation_digest,
            evidence_mac_enabled=evidence_mac_enabled,
        )
        replace_config_values(dirty_config, replacements)
        dirty_report = docker_diag(
            dirty_config,
            args,
            "--print-readiness-report",
            secrets_dir=secrets_dir,
        )
        require_value(dirty_report, "diagnostic_init_status", "0")
        require_value(dirty_report, "evidence_collection_status", "0")
        require_value(dirty_report, "report_status", "0")
        require_value(dirty_report, "ecc_memory_ready", "1")
        require_value(dirty_report, "ecc_counters_clean", "0")
        require_value(dirty_report, "evidence_edac_corrected_error_count", "1")
        require_value(dirty_report, "edac_corrected_error_count", "1")
        require_value(dirty_report, "gate_passed", "0")
        missing = parse_int_value(
            require_key(dirty_report, "missing_requirements"),
            "missing_requirements",
        )
        if (missing & 0x00000004) == 0:
            raise SyntheticReadinessError(
                "dirty ECC counter did not set missing ECC_CLEAN requirement"
            )
        print("dirty ECC counter failed clean gate as expected", flush=True)


def expected_fault_injection_coverage(mode: str) -> str:
    if mode == "off":
        return "0x00000000"
    if mode == "single":
        return "0x00000c05"
    if mode == "double":
        return "0x0000120a"
    if mode == "full":
        return "0x0000ffff"
    raise SyntheticReadinessError(f"unsupported fault-injection mode: {mode}")


def expected_fault_injection_mode_value(mode: str) -> str:
    mapping = {
        "off": "0",
        "single": "1",
        "double": "2",
        "full": "3",
    }
    try:
        return mapping[mode]
    except KeyError as exc:
        raise SyntheticReadinessError(
            f"unsupported fault-injection mode: {mode}"
        ) from exc


def expected_fault_injection_mode_text(mode: str) -> str:
    if mode in {"off", "single", "double", "full"}:
        return mode
    raise SyntheticReadinessError(f"unsupported fault-injection mode: {mode}")


def verify_report(values: dict[str, str], args: argparse.Namespace) -> None:
    require_value(values, "diagnostic_init_status", "0")
    require_value(values, "evidence_collection_status", "0")
    require_value(values, "report_status", "0")
    require_value(values, "configured_require_readiness", "1")
    require_value(values, "configured_platform_safety_flags", "15")
    require_value(values, "configured_platform_evidence_mode", "1")
    require_value(values, "configured_platform_evidence_mode_text", "synthetic")
    require_value(values, "configured_platform_evidence_scope",
                  "software-platform-model")
    require_value(values, "configured_synthetic_evidence_active", "1")
    require_value(values, "configured_software_platform_model_active", "1")
    require_value(values, "configured_ecc_evidence_scope", "software-ecc-model")
    require_value(values, "configured_physical_memory_evidence_scope",
                  "software-numa-model")
    require_value(values, "configured_independent_tmr_evidence_scope",
                  "software-domain-model")
    require_value(values, "configured_payload_ecc_enabled", "1")
    require_value(values, "configured_software_ecc_enabled", "1")
    require_value(
        values,
        "configured_software_ecc_controller_count",
        str(args.software_ecc_controllers),
    )
    require_value(
        values,
        "configured_software_ecc_dimm_count",
        str(args.software_ecc_dimms),
    )
    require_value(
        values,
        "configured_software_ecc_scrub_rate",
        str(args.software_ecc_scrub_rate),
    )
    require_value(
        values,
        "configured_software_ecc_controller_corrected_error_count",
        str(args.software_ecc_controller_corrected_errors),
    )
    require_value(
        values,
        "configured_software_ecc_controller_uncorrected_error_count",
        str(args.software_ecc_controller_uncorrected_errors),
    )
    require_value(
        values,
        "configured_software_ecc_dimm_corrected_error_count",
        str(args.software_ecc_dimm_corrected_errors),
    )
    require_value(
        values,
        "configured_software_ecc_dimm_uncorrected_error_count",
        str(args.software_ecc_dimm_uncorrected_errors),
    )
    require_value(values, "configured_software_numa_enabled", "1")
    require_value(
        values,
        "configured_software_numa_memtotal_kib",
        str(args.software_numa_memtotal_kib),
    )
    require_value(
        values,
        "configured_software_numa_local_distance",
        str(args.software_numa_local_distance),
    )
    require_value(
        values,
        "configured_software_numa_remote_distance",
        str(args.software_numa_remote_distance),
    )
    require_value(
        values,
        "configured_software_fault_injection_mode",
        expected_fault_injection_mode_value(args.software_fault_injection_mode),
    )
    require_value(
        values,
        "configured_software_fault_injection_mode_text",
        expected_fault_injection_mode_text(args.software_fault_injection_mode),
    )
    require_value(values, "evidence_version", "55")
    require_value(values, "evidence_platform_evidence_mode", "1")
    require_value(values, "platform_evidence_mode", "1")
    require_value(values, "platform_evidence_mode_text", "synthetic")
    require_value(values, "platform_evidence_scope", "software-platform-model")
    require_value(values, "synthetic_evidence_active", "1")
    require_value(values, "software_platform_model_active", "1")
    require_value(values, "ecc_evidence_scope", "software-ecc-model")
    require_value(values, "physical_memory_evidence_scope",
                  "software-numa-model")
    require_value(values, "independent_tmr_evidence_scope",
                  "software-domain-model")
    require_same_value(
        values,
        "evidence_platform_evidence_mode",
        "platform_evidence_mode",
    )
    require_value(values, "platform_evidence_valid", "1")
    require_value(
        values,
        "configured_evidence_mac_enabled",
        "1" if args.evidence_mac or args.evidence_key is not None else "0",
    )
    require_value(values, "evidence_mac_valid", "1")
    if args.evidence_mac or args.evidence_key is not None:
        key_fingerprint = int(require_key(values, "evidence_mac_key_fingerprint"))
        if key_fingerprint == 0:
            raise SyntheticReadinessError("evidence MAC key fingerprint is zero")
    require_value(values, "software_tmr_ready", "1")
    require_value(values, "ecc_memory_ready", "1")
    require_value(values, "ecc_counters_clean", "1")
    require_value(
        values,
        "evidence_edac_corrected_error_count",
        str(args.software_ecc_controller_corrected_errors),
    )
    require_value(
        values,
        "evidence_edac_uncorrected_error_count",
        str(args.software_ecc_controller_uncorrected_errors),
    )
    require_value(
        values,
        "evidence_edac_dimm_corrected_error_count",
        str(args.software_ecc_dimm_corrected_errors),
    )
    require_value(
        values,
        "evidence_edac_dimm_uncorrected_error_count",
        str(args.software_ecc_dimm_uncorrected_errors),
    )
    require_value(
        values,
        "edac_corrected_error_count",
        str(args.software_ecc_controller_corrected_errors),
    )
    require_value(
        values,
        "edac_uncorrected_error_count",
        str(args.software_ecc_controller_uncorrected_errors),
    )
    require_value(
        values,
        "edac_dimm_corrected_error_count",
        str(args.software_ecc_dimm_corrected_errors),
    )
    require_value(
        values,
        "edac_dimm_uncorrected_error_count",
        str(args.software_ecc_dimm_uncorrected_errors),
    )
    require_value(values, "physical_memory_separation_ready", "1")
    require_value(
        values,
        "physical_domain_memtotal_kib",
        str(args.software_numa_memtotal_kib * 3),
    )
    expected_distance_sum = (
        (3 * args.software_numa_local_distance)
        + (6 * args.software_numa_remote_distance)
    )
    require_value(values, "physical_domain_distance_sum", str(expected_distance_sum))
    require_value(
        values,
        "physical_domain_distance_01",
        str(args.software_numa_remote_distance),
    )
    require_value(
        values,
        "physical_domain_distance_02",
        str(args.software_numa_remote_distance),
    )
    require_value(
        values,
        "physical_domain_distance_12",
        str(args.software_numa_remote_distance),
    )
    require_value(values, "independent_hardware_tmr_ready", "1")
    require_value(values, "software_evidence_self_test_ready", "1")
    require_value(values, "payload_ecc_ready", "1")
    require_value(values, "evidence_software_schema_version", "1")
    require_value(values, "software_evidence_schema_version", "1")
    require_same_value(
        values,
        "evidence_software_schema_version",
        "software_evidence_schema_version",
    )
    require_value(values, "evidence_software_self_test_passed", "1")
    require_value(values, "evidence_software_self_test_coverage", "0x0000ffff")
    require_value(values, "software_evidence_self_test_coverage", "0x0000ffff")
    require_same_value(
        values,
        "evidence_software_self_test_coverage",
        "software_evidence_self_test_coverage",
    )
    require_value(
        values,
        "evidence_software_self_test_required_coverage",
        "0x0000ffff",
    )
    require_value(
        values,
        "software_evidence_self_test_required_coverage",
        "0x0000ffff",
    )
    require_same_value(
        values,
        "evidence_software_self_test_required_coverage",
        "software_evidence_self_test_required_coverage",
    )
    require_value(
        values,
        "evidence_software_dimm_fault_injection_coverage",
        expected_fault_injection_coverage(args.software_fault_injection_mode),
    )
    require_value(
        values,
        "software_dimm_fault_injection_coverage",
        expected_fault_injection_coverage(args.software_fault_injection_mode),
    )
    require_same_value(
        values,
        "evidence_software_dimm_fault_injection_coverage",
        "software_dimm_fault_injection_coverage",
    )
    require_value(
        values,
        "evidence_software_fault_injection_mode",
        expected_fault_injection_mode_value(args.software_fault_injection_mode),
    )
    require_value(
        values,
        "evidence_software_fault_injection_mode_text",
        expected_fault_injection_mode_text(args.software_fault_injection_mode),
    )
    require_value(
        values,
        "software_fault_injection_mode",
        expected_fault_injection_mode_value(args.software_fault_injection_mode),
    )
    require_value(
        values,
        "software_fault_injection_mode_text",
        expected_fault_injection_mode_text(args.software_fault_injection_mode),
    )
    require_same_value(
        values,
        "evidence_software_fault_injection_mode",
        "software_fault_injection_mode",
    )
    require_same_value(
        values,
        "evidence_software_fault_injection_mode_text",
        "software_fault_injection_mode_text",
    )
    require_value(
        values,
        "evidence_software_ecc_controller_count",
        str(args.software_ecc_controllers),
    )
    require_value(
        values,
        "evidence_software_dimm_bank_count",
        str(args.software_ecc_dimms),
    )
    require_value(
        values,
        "evidence_software_ecc_scrub_rate",
        str(args.software_ecc_scrub_rate),
    )
    require_value(
        values,
        "software_ecc_controller_count",
        str(args.software_ecc_controllers),
    )
    require_value(values, "software_dimm_bank_count", str(args.software_ecc_dimms))
    require_value(values, "software_ecc_scrub_rate", str(args.software_ecc_scrub_rate))
    require_same_value(
        values,
        "evidence_software_ecc_controller_count",
        "software_ecc_controller_count",
    )
    require_same_value(
        values,
        "evidence_software_dimm_bank_count",
        "software_dimm_bank_count",
    )
    require_same_value(
        values,
        "evidence_software_ecc_scrub_rate",
        "software_ecc_scrub_rate",
    )
    require_same_value(
        values,
        "evidence_software_dimm_generation",
        "software_dimm_generation",
    )
    require_same_value(
        values,
        "evidence_software_dimm_scrub_generation",
        "software_dimm_scrub_generation",
    )
    require_same_value(
        values,
        "evidence_software_dimm_observation_fingerprint",
        "software_dimm_observation_fingerprint",
    )
    dimm_fingerprint = int(require_key(values, "software_dimm_observation_fingerprint"))
    if dimm_fingerprint == 0:
        raise SyntheticReadinessError("software DIMM observation fingerprint is zero")
    require_same_value(
        values,
        "evidence_software_numa_profile_fingerprint",
        "software_numa_profile_fingerprint",
    )
    numa_profile_fingerprint = int(require_key(values, "software_numa_profile_fingerprint"))
    if numa_profile_fingerprint == 0:
        raise SyntheticReadinessError("software NUMA profile fingerprint is zero")
    require_value(values, "configured_evidence_request_bound", "1")
    require_value(values, "configured_platform_observation_digest_bound", "1")
    require_value(values, "gate_passed", "1")
    require_value(values, "missing_requirements", "0x00000000")


def require_missing_bit(values: dict[str, str], mask: int) -> None:
    missing = int(require_key(values, "missing_requirements"), 16)
    if (missing & mask) == 0:
        raise SyntheticReadinessError(
            f"missing_requirements expected mask 0x{mask:08x}, got 0x{missing:08x}"
        )


def verify_wrong_evidence_key_rejected(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    *,
    good_evidence_key: pathlib.Path | None,
    observation_digest: int,
    verify_startup: bool,
) -> None:
    wrong_secrets: tempfile.TemporaryDirectory[str] | None = None

    if good_evidence_key is None:
        return

    try:
        wrong_secrets = stage_generated_evidence_mac_key(
            "llps-readiness-wrong-secrets-",
            forbidden_key_path=good_evidence_key,
        )
        wrong_values = docker_diag(
            config_path,
            args,
            "--print-readiness-report",
            secrets_dir=pathlib.Path(wrong_secrets.name),
        )
        require_value(wrong_values, "diagnostic_init_status", "0")
        require_value(wrong_values, "evidence_collection_status", "0")
        require_value(wrong_values, "report_status", "0")
        require_value(wrong_values, "configured_evidence_mac_enabled", "1")
        require_value(wrong_values, "configured_evidence_request_bound", "1")
        require_value(
            wrong_values,
            "configured_platform_observation_digest_bound",
            "0",
        )
        require_value(wrong_values, "gate_passed", "0")
        require_missing_bit(wrong_values, MISSING_OBSERVATION_DIGEST_BINDING)

        wrong_digest = int(
            require_key(wrong_values, "platform_evidence_observation_digest")
        )
        if wrong_digest == observation_digest:
            raise SyntheticReadinessError(
                "wrong evidence key unexpectedly preserved observation digest"
            )

        if verify_startup:
            verify_startup_rejected(
                config_path,
                args,
                secrets_dir=pathlib.Path(wrong_secrets.name),
                expected_log="readiness gate rejected startup",
            )
    finally:
        if wrong_secrets is not None:
            wrong_secrets.cleanup()


def verify_startup_rejected(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
    expected_log: str,
) -> None:
    container_name = f"llps-synthetic-readiness-reject-{int(time.time())}"
    command = docker_run_base(
        config_path,
        args,
        secrets_dir=secrets_dir,
        remove=False,
    )
    command[2:2] = ["--name", container_name]
    command.insert(len(command) - 1, "--detach")

    started = False
    try:
        result = run(command, timeout=args.timeout, capture=True)
        container_id = result.stdout.strip()
        if not container_id:
            raise SyntheticReadinessError("docker run did not return a container id")
        started = True
        time.sleep(args.startup_wait)

        inspect = run(
            [
                "docker",
                "inspect",
                "-f",
                "{{.State.Running}} {{.State.ExitCode}}",
                container_name,
            ],
            timeout=10.0,
            capture=True,
            quiet=True,
        )
        state = inspect.stdout.strip()
        parts = state.split()
        if len(parts) != 2:
            raise SyntheticReadinessError(
                f"unexpected startup reject inspect state: {state}"
            )
        if parts[0] == "true":
            logs = run(
                ["docker", "logs", container_name],
                timeout=10.0,
                capture=True,
                quiet=True,
            )
            raise SyntheticReadinessError(
                "startup rejection check unexpectedly kept running:\n"
                f"{logs.stdout}"
            )
        if int(parts[1]) == 0:
            logs = run(
                ["docker", "logs", container_name],
                timeout=10.0,
                capture=True,
                quiet=True,
            )
            raise SyntheticReadinessError(
                "startup rejection check exited successfully:\n"
                f"{logs.stdout}"
            )

        logs = run(
            ["docker", "logs", container_name],
            timeout=10.0,
            capture=True,
            quiet=True,
        )
        if expected_log not in (logs.stdout + logs.stderr):
            raise SyntheticReadinessError(
                "startup rejection log did not contain expected text:\n"
                f"{logs.stdout}{logs.stderr}"
            )
    finally:
        if started:
            run(
                ["docker", "rm", "-f", container_name],
                timeout=20.0,
                capture=True,
                quiet=True,
            )


def docker_logs(container_name: str) -> str:
    logs = run(
        ["docker", "logs", container_name],
        timeout=10.0,
        capture=True,
        quiet=True,
    )
    return logs.stdout + logs.stderr


def strip_container_log_prefix(line: str) -> str:
    if "|" in line:
        return line.split("|", 1)[1].strip()
    return line.strip()


def parse_runtime_patrol_blocks(logs: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for raw_line in logs.splitlines():
        line = strip_container_log_prefix(raw_line)
        if "readiness_monitor_pass" in line:
            if current is not None:
                blocks.append(current)
            current = {}
            for token in line.split():
                if "=" in token:
                    key, value = token.split("=", 1)
                    current[key.strip()] = value.strip()
            continue
        if current is None:
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        current[key.strip()] = value.strip()

    if current is not None:
        blocks.append(current)
    return blocks


def runtime_patrol_block_matches(
    block: dict[str, str],
    args: argparse.Namespace,
) -> bool:
    required = (
        "total",
        "software_evidence_patrol",
        "synthetic_ecc_topology_patrol",
        "synthetic_ecc_topology_patrol_failures",
        "synthetic_fault_patrol",
        "synthetic_fault_patrol_failures",
        "synthetic_numa_patrol",
        "synthetic_numa_patrol_failures",
        "require_readiness",
        "platform_evidence_mode",
        "platform_evidence_mode_text",
        "platform_evidence_scope",
        "synthetic_evidence_active",
        "software_platform_model_active",
        "ecc_evidence_scope",
        "physical_memory_evidence_scope",
        "independent_tmr_evidence_scope",
        "software_ecc_enabled",
        "software_ecc_controller_count",
        "software_ecc_dimm_count",
        "software_ecc_scrub_rate",
        "software_ecc_controller_corrected_error_count",
        "software_ecc_controller_uncorrected_error_count",
        "software_ecc_dimm_corrected_error_count",
        "software_ecc_dimm_uncorrected_error_count",
        "software_numa_enabled",
        "software_numa_memtotal_kib",
        "software_numa_local_distance",
        "software_numa_remote_distance",
        "software_fault_injection_mode",
        "software_fault_injection_mode_text",
    )
    if any(key not in block for key in required):
        return False

    synthetic_fault_patrol = parse_int_value(
        block["synthetic_fault_patrol"],
        "readiness_monitor_pass.synthetic_fault_patrol",
    )
    synthetic_ecc_topology_patrol = parse_int_value(
        block["synthetic_ecc_topology_patrol"],
        "readiness_monitor_pass.synthetic_ecc_topology_patrol",
    )
    if args.software_fault_injection_mode == "off":
        synthetic_fault_patrol_matches = synthetic_fault_patrol == 0
    else:
        synthetic_fault_patrol_matches = synthetic_fault_patrol > 0
    synthetic_numa_patrol = parse_int_value(
        block["synthetic_numa_patrol"],
        "readiness_monitor_pass.synthetic_numa_patrol",
    )

    return (
        parse_int_value(block["total"], "readiness_monitor_pass.total") > 0 and
        parse_int_value(
            block["software_evidence_patrol"],
            "readiness_monitor_pass.software_evidence_patrol",
        ) > 0 and
        synthetic_ecc_topology_patrol > 0 and
        block["synthetic_ecc_topology_patrol_failures"] == "0" and
        synthetic_fault_patrol_matches and
        block["synthetic_fault_patrol_failures"] == "0" and
        synthetic_numa_patrol > 0 and
        block["synthetic_numa_patrol_failures"] == "0" and
        block["require_readiness"] == "1" and
        block["platform_evidence_mode"] == "1" and
        block["platform_evidence_mode_text"] == "synthetic" and
        block["platform_evidence_scope"] == "software-platform-model" and
        block["synthetic_evidence_active"] == "1" and
        block["software_platform_model_active"] == "1" and
        block["ecc_evidence_scope"] == "software-ecc-model" and
        block["physical_memory_evidence_scope"] == "software-numa-model" and
        block["independent_tmr_evidence_scope"] == "software-domain-model" and
        block["software_ecc_enabled"] == "1" and
        block["software_ecc_controller_count"] ==
            str(args.software_ecc_controllers) and
        block["software_ecc_dimm_count"] == str(args.software_ecc_dimms) and
        block["software_ecc_scrub_rate"] == str(args.software_ecc_scrub_rate) and
        block["software_ecc_controller_corrected_error_count"] ==
            str(args.software_ecc_controller_corrected_errors) and
        block["software_ecc_controller_uncorrected_error_count"] ==
            str(args.software_ecc_controller_uncorrected_errors) and
        block["software_ecc_dimm_corrected_error_count"] ==
            str(args.software_ecc_dimm_corrected_errors) and
        block["software_ecc_dimm_uncorrected_error_count"] ==
            str(args.software_ecc_dimm_uncorrected_errors) and
        block["software_numa_enabled"] == "1" and
        block["software_numa_memtotal_kib"] ==
            str(args.software_numa_memtotal_kib) and
        block["software_numa_local_distance"] ==
            str(args.software_numa_local_distance) and
        block["software_numa_remote_distance"] ==
            str(args.software_numa_remote_distance) and
        block["software_fault_injection_mode"] ==
            expected_fault_injection_mode_value(args.software_fault_injection_mode) and
        block["software_fault_injection_mode_text"] ==
            expected_fault_injection_mode_text(args.software_fault_injection_mode)
    )


def verify_runtime_llam_contract_log(logs: str) -> None:
    required_tokens = (
        "llam_runtime_contract",
        "single_worker=1",
        "single_node=1",
        "deterministic=1",
        "profile=io-latency",
        "active_workers=1",
        "online_workers=1",
        "online_workers_floor=1",
        "online_workers_min=1",
        "online_workers_max=1",
        "active_nodes=1",
        "dynamic_workers=0",
        "worker_rings=0",
        "worker_rings_multishot=0",
        "lockfree_normq=0",
        "sqpoll=0",
    )

    for token in required_tokens:
        if token not in logs:
            raise SyntheticReadinessError(
                "runtime LLAM contract log did not contain "
                f"{token!r}:\n{logs}"
            )


def verify_runtime_patrol_log(container_name: str,
                              args: argparse.Namespace) -> None:
    deadline = time.monotonic() + args.runtime_patrol_wait
    last_logs = ""

    while time.monotonic() <= deadline:
        last_logs = docker_logs(container_name)
        if "readiness_monitor_fail" in last_logs:
            raise SyntheticReadinessError(
                "runtime readiness monitor reported failure:\n"
                f"{last_logs}"
            )
        if any(
            runtime_patrol_block_matches(block, args)
            for block in parse_runtime_patrol_blocks(last_logs)
        ):
            verify_runtime_llam_contract_log(last_logs)
            return
        time.sleep(0.25)

    raise SyntheticReadinessError(
        "runtime readiness monitor did not report a software patrol pass:\n"
        f"{last_logs}"
    )


def verify_startup(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
) -> None:
    container_name = f"llps-synthetic-readiness-{int(time.time())}"
    command = docker_run_base(config_path, args, secrets_dir=secrets_dir)
    command[2:2] = ["--name", container_name]
    command.insert(len(command) - 1, "--detach")

    started = False
    try:
        result = run(command, timeout=args.timeout, capture=True)
        container_id = result.stdout.strip()
        if not container_id:
            raise SyntheticReadinessError("docker run did not return a container id")
        started = True
        time.sleep(args.startup_wait)
        inspect = run(
            [
                "docker",
                "inspect",
                "-f",
                "{{.State.Running}} {{.State.ExitCode}}",
                container_name,
            ],
            timeout=10.0,
            capture=True,
            quiet=True,
        )
        state = inspect.stdout.strip()
        if state != "true 0":
            raise SyntheticReadinessError(
                "startup container did not stay running: "
                f"{state}\n{docker_logs(container_name)}"
            )
        verify_runtime_patrol_log(container_name, args)
    finally:
        if started:
            run(["docker", "stop", container_name], timeout=20.0, capture=True)


def verify_fault_mode_binding(
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
    attestation_fingerprint: int,
    evidence_mac_enabled: bool,
    reference_observation_digest: int,
    reference_dimm_fingerprint: int,
) -> None:
    modes = ("off", "single", "double", "full")

    for mode in modes:
        if mode == args.software_fault_injection_mode:
            continue

        alt_args = argparse.Namespace(**vars(args))
        alt_args.software_fault_injection_mode = mode
        with tempfile.TemporaryDirectory(
            prefix=f"llps-readiness-mode-{mode}-"
        ) as temp_dir:
            alt_config = pathlib.Path(temp_dir) / "synthetic-readiness.yml"
            write_config(
                alt_config,
                alt_args,
                attestation_fingerprint=attestation_fingerprint,
                observation_digest=0,
                evidence_mac_enabled=evidence_mac_enabled,
            )
            first_report = docker_diag(
                alt_config,
                alt_args,
                "--print-readiness-report",
                secrets_dir=secrets_dir,
            )
            observation_digest = int(
                require_key(first_report, "platform_evidence_observation_digest")
            )
            dimm_fingerprint = int(
                require_key(first_report, "software_dimm_observation_fingerprint")
            )
            if observation_digest == reference_observation_digest:
                raise SyntheticReadinessError(
                    f"fault mode {mode} reused reference observation digest"
                )
            if dimm_fingerprint == reference_dimm_fingerprint:
                raise SyntheticReadinessError(
                    f"fault mode {mode} reused reference DIMM fingerprint"
                )

            write_config(
                alt_config,
                alt_args,
                attestation_fingerprint=attestation_fingerprint,
                observation_digest=observation_digest,
                evidence_mac_enabled=evidence_mac_enabled,
            )
            final_report = docker_diag(
                alt_config,
                alt_args,
                "--print-readiness-report",
                secrets_dir=secrets_dir,
            )
            verify_report(final_report, alt_args)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="llps:local")
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONFIG)
    parser.add_argument("--evidence-id", type=int, default=42424242)
    parser.add_argument("--software-ecc-dimms", type=int, default=8)
    parser.add_argument("--software-ecc-controllers", type=int, default=1)
    parser.add_argument("--software-ecc-scrub-rate", type=int, default=4096)
    parser.add_argument("--software-ecc-controller-corrected-errors",
                        type=int,
                        default=0)
    parser.add_argument("--software-ecc-controller-uncorrected-errors",
                        type=int,
                        default=0)
    parser.add_argument("--software-ecc-dimm-corrected-errors",
                        type=int,
                        default=0)
    parser.add_argument("--software-ecc-dimm-uncorrected-errors",
                        type=int,
                        default=0)
    parser.add_argument("--software-numa-memtotal-kib", type=int, default=65536)
    parser.add_argument("--software-numa-local-distance", type=int, default=10)
    parser.add_argument("--software-numa-remote-distance", type=int, default=20)
    parser.add_argument(
        "--software-fault-injection-mode",
        choices=("off", "single", "double", "full"),
        default="full",
    )
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--startup-wait", type=float, default=2.0)
    parser.add_argument("--runtime-patrol-wait", type=float, default=6.0)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-startup", action="store_true")
    parser.add_argument("--skip-mode-binding-check", action="store_true")
    parser.add_argument(
        "--evidence-key",
        type=pathlib.Path,
        help="enable evidence HMAC using this host key, staged into a temporary read-only mount",
    )
    parser.add_argument(
        "--evidence-mac",
        action="store_true",
        help="enable evidence HMAC with a generated temporary read-only key",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    config_path = args.config if args.config.is_absolute() else ROOT / args.config
    staged_secrets: tempfile.TemporaryDirectory[str] | None = None
    staged_evidence_key: pathlib.Path | None = None

    try:
        staged_secrets, staged_evidence_key = stage_evidence_mac_key(args)
        secrets_dir = (
            pathlib.Path(staged_secrets.name)
            if staged_secrets is not None
            else None
        )
        if not args.skip_build:
            run(
                ["docker", "build", "--target", "runtime", "-t", "llps:local", "."],
                timeout=args.timeout,
                capture=True,
            )

        write_config(
            config_path,
            args,
            attestation_fingerprint=0,
            observation_digest=0,
            evidence_mac_enabled=staged_evidence_key is not None,
        )
        attestation_values = docker_diag(
            config_path,
            args,
            "--print-platform-attestation-fingerprint",
            secrets_dir=secrets_dir,
        )
        attestation_fingerprint = int(
            require_key(attestation_values, "platform_attestation_fingerprint")
        )
        if attestation_fingerprint == 0:
            raise SyntheticReadinessError("attestation fingerprint is zero")

        write_config(
            config_path,
            args,
            attestation_fingerprint=attestation_fingerprint,
            observation_digest=0,
            evidence_mac_enabled=staged_evidence_key is not None,
        )
        first_report = docker_diag(
            config_path,
            args,
            "--print-readiness-report",
            secrets_dir=secrets_dir,
        )
        observation_digest = int(
            require_key(first_report, "platform_evidence_observation_digest")
        )
        if observation_digest == 0:
            raise SyntheticReadinessError("observation digest is zero")

        write_config(
            config_path,
            args,
            attestation_fingerprint=attestation_fingerprint,
            observation_digest=observation_digest,
            evidence_mac_enabled=staged_evidence_key is not None,
        )
        final_report = docker_diag(
            config_path,
            args,
            "--print-readiness-report",
            secrets_dir=secrets_dir,
        )
        verify_report(final_report, args)
        verify_invalid_software_profiles_rejected(
            args,
            secrets_dir=secrets_dir,
            attestation_fingerprint=attestation_fingerprint,
            observation_digest=observation_digest,
            evidence_mac_enabled=staged_evidence_key is not None,
        )
        verify_dirty_ecc_counter_fails_clean_gate(
            args,
            secrets_dir=secrets_dir,
            attestation_fingerprint=attestation_fingerprint,
            evidence_mac_enabled=staged_evidence_key is not None,
        )
        if not args.skip_mode_binding_check:
            verify_fault_mode_binding(
                args,
                secrets_dir=secrets_dir,
                attestation_fingerprint=attestation_fingerprint,
                evidence_mac_enabled=staged_evidence_key is not None,
                reference_observation_digest=observation_digest,
                reference_dimm_fingerprint=int(
                    require_key(
                        final_report,
                        "software_dimm_observation_fingerprint",
                    )
                ),
            )
        verify_wrong_evidence_key_rejected(
            config_path,
            args,
            good_evidence_key=staged_evidence_key,
            observation_digest=observation_digest,
            verify_startup=not args.skip_startup,
        )

        if not args.skip_startup:
            verify_startup(config_path, args, secrets_dir=secrets_dir)
    except (OSError, ValueError, SyntheticReadinessError) as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        if staged_secrets is not None:
            staged_secrets.cleanup()

    print(
        "\nOK: Docker synthetic readiness passed; "
        f"attestation={attestation_fingerprint} "
        f"observation_digest={observation_digest} "
        f"evidence_mac={'1' if staged_evidence_key is not None else '0'} "
        f"config={config_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
