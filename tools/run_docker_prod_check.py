#!/usr/bin/env python3
"""Run a production-like Dockerfile-only LLPS smoke check."""

from __future__ import annotations

import argparse
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

from verify_pxf_audit_mac import VerificationError, parse_pxf


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_LOG = ROOT / "logs" / "llps-ip-audit.pxf"
AUDIT_KEY_NAME = "llps-audit.key"
EVIDENCE_KEY_NAME = "llps-evidence.key"
AUDIT_KEY_BYTES_MAX = 128
EVIDENCE_KEY_BYTES_MAX = 128
CONTAINER_AUDIT_KEY_PATH = f"/run/llps-secrets/{AUDIT_KEY_NAME}"
CONTAINER_EVIDENCE_KEY_PATH = f"/run/llps-secrets/{EVIDENCE_KEY_NAME}"
HOST_SYNTHETIC_CONFIG = ROOT / "logs" / "llps-prod-synthetic.generated.yml"
CONTAINER_SYNTHETIC_CONFIG = "/var/log/llps/llps-prod-synthetic.generated.yml"


class CheckError(RuntimeError):
    """Raised when a production-like check step fails."""


def run(
    command: list[str],
    *,
    env: dict[str, str],
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
            env=env,
            check=False,
            timeout=timeout,
            text=True,
            capture_output=capture,
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckError(f"timed out after {timeout:.1f}s: {printable}") from exc

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
        raise CheckError(f"command failed with exit code {result.returncode}: {printable}")
    return result


def output(command: list[str], *, env: dict[str, str], timeout: float = 10.0) -> str:
    result = run(command, env=env, timeout=timeout, capture=True, quiet=True)
    return result.stdout


def docker_env(
    args: argparse.Namespace,
    *,
    audit_mac_enabled: bool,
    secrets_dir: pathlib.Path | None,
) -> dict[str, str]:
    suffix = str(os.getpid())
    env = dict(os.environ)
    env.update(
        {
            "LLPS_DOCKER_NETWORK": f"llps-prod-net-{suffix}",
            "LLPS_DOCKER_TARGET": f"llps-chat-target-{suffix}",
            "LLPS_DOCKER_PROXY": f"llps-prod-{suffix}",
            "LLPS_PUBLISHED_PORT": str(args.published_port),
            "LLPS_TARGET_HOST": args.target_host,
            "LLPS_TARGET_PORT": str(args.target_port),
            "LLPS_IP_AUDIT_ENABLED": "1",
            "LLPS_IP_AUDIT_PATH": "/var/log/llps/llps-ip-audit.pxf",
            "LLPS_AUDIT_MAC_ENABLED": "1" if audit_mac_enabled else "0",
            "LLPS_AUDIT_MAC_KEY_PATH": CONTAINER_AUDIT_KEY_PATH,
            "LLPS_LOG": "1",
            "LLPS_LOG_AUDIT": "1",
            "LLPS_LOG_EVIDENCE": "1",
            "LLPS_LOG_IO": "1" if args.io_logs else "0",
        }
    )
    if args.protocol_gate:
        env["LLPS_CLIENT_PREFACE_TIMEOUT_MS"] = str(
            args.protocol_preface_timeout_ms
        )
        env["LLPS_PROTOCOL_HANDSHAKE_GATE_ENABLED"] = "1"
    if args.synthetic_readiness:
        env["LLPS_CONFIG"] = CONTAINER_SYNTHETIC_CONFIG
    if secrets_dir is not None:
        env["LLPS_SECRETS_DIR"] = str(secrets_dir)
    return env


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


def docker_build_target(target: str, image: str, timeout: float) -> None:
    run(
        ["docker", "build", "--target", target, "-t", image, "."],
        env=dict(os.environ),
        timeout=timeout,
        capture=True,
    )


def stage_secret_keys(
    args: argparse.Namespace,
) -> tuple[tempfile.TemporaryDirectory[str] | None, pathlib.Path | None, pathlib.Path | None]:
    needs_audit_key = args.audit_mac or args.audit_key is not None
    needs_evidence_key = args.synthetic_readiness or args.evidence_key is not None
    if not needs_audit_key and not needs_evidence_key:
        return None, None, None
    if args.keep_running:
        raise CheckError("keyed checks use a temporary secret mount; omit --keep-running")

    staged_dir = tempfile.TemporaryDirectory(prefix="llps-prod-check-secrets-")
    staged_audit_path: pathlib.Path | None = None
    staged_evidence_path: pathlib.Path | None = None

    if needs_audit_key:
        staged_audit_path = pathlib.Path(staged_dir.name) / AUDIT_KEY_NAME
        if args.audit_key is not None:
            source_key = args.audit_key
            if not source_key.is_absolute():
                source_key = ROOT / source_key
            key_bytes = source_key.read_bytes()
        else:
            key_bytes = os.urandom(32)

        if (len(key_bytes) == 0) or (len(key_bytes) > AUDIT_KEY_BYTES_MAX):
            staged_dir.cleanup()
            raise CheckError("audit MAC key must be 1..128 bytes")

        staged_audit_path.write_bytes(key_bytes)
        staged_audit_path.chmod(0o444)

    if needs_evidence_key:
        staged_evidence_path = pathlib.Path(staged_dir.name) / EVIDENCE_KEY_NAME
        if args.evidence_key is not None:
            source_key = args.evidence_key
            if not source_key.is_absolute():
                source_key = ROOT / source_key
            key_bytes = source_key.read_bytes()
        else:
            key_bytes = os.urandom(32)

        if (len(key_bytes) == 0) or (len(key_bytes) > EVIDENCE_KEY_BYTES_MAX):
            staged_dir.cleanup()
            raise CheckError("evidence MAC key must be 1..128 bytes")

        staged_evidence_path.write_bytes(key_bytes)
        staged_evidence_path.chmod(0o444)

    pathlib.Path(staged_dir.name).chmod(0o755)
    return staged_dir, staged_audit_path, staged_evidence_path


def parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def require_diagnostic_key(values: dict[str, str], key: str) -> str:
    value = values.get(key)
    if value is None or value == "":
        raise CheckError(f"missing diagnostic key: {key}")
    return value


def parse_int_value(value: str, key: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise CheckError(f"{key} expected an integer, got {value!r}") from exc


def synthetic_fault_mode_value(mode: str) -> str:
    mapping = {
        "off": "0",
        "single": "1",
        "double": "2",
        "full": "3",
    }
    try:
        return mapping[mode]
    except KeyError as exc:
        raise CheckError(f"unsupported synthetic fault mode: {mode}") from exc


def synthetic_fault_mode_text(mode: str) -> str:
    if mode in {"off", "single", "double", "full"}:
        return mode
    raise CheckError(f"unsupported synthetic fault mode: {mode}")


def synthetic_fault_coverage(mode: str) -> str:
    mapping = {
        "off": "0x00000000",
        "single": "0x00000c05",
        "double": "0x0000120a",
        "full": "0x0000ffff",
    }
    try:
        return mapping[mode]
    except KeyError as exc:
        raise CheckError(f"unsupported synthetic fault mode: {mode}") from exc


def write_synthetic_readiness_config(
    path: pathlib.Path,
    args: argparse.Namespace,
    *,
    attestation_fingerprint: int,
    observation_digest: int,
    target_host: str,
    audit_enabled: bool,
    audit_mac_enabled: bool,
    evidence_mac_enabled: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "max_clients: 256",
                "buffer_size: 4096",
                "listen_host: 0.0.0.0",
                "listen_port: 25565",
                f"target_host: {target_host}",
                f"target_port: {args.target_port}",
                "listen_backlog: 256",
                "accept_batch_max: 32",
                "session_idle_timeout_ms: 30000",
                "max_sessions_per_client_ip: 0",
                "max_new_sessions_per_client_ip_per_window: 0",
                "client_ip_rate_window_ms: 1000",
                f"client_preface_timeout_ms: {args.protocol_preface_timeout_ms if args.protocol_gate else 0}",
                f"protocol_handshake_gate_enabled: {1 if args.protocol_gate else 0}",
                "payload_ecc_enabled: 1",
                f"ip_audit_enabled: {1 if audit_enabled else 0}",
                "ip_audit_path: /var/log/llps/llps-ip-audit.pxf",
                f"audit_mac_enabled: {1 if audit_mac_enabled else 0}",
                f"audit_mac_key_path: {CONTAINER_AUDIT_KEY_PATH}",
                "require_readiness: 1",
                "platform_safety_flags: 15",
                f"platform_safety_evidence_id: {args.synthetic_evidence_id}",
                f"platform_attestation_fingerprint: {attestation_fingerprint}",
                f"platform_observation_digest: {observation_digest}",
                "platform_evidence_mode: synthetic",
                "phys_mem_domain0: 11",
                "phys_mem_domain1: 22",
                "phys_mem_domain2: 33",
                "hw_tmr_domain0: 101",
                "hw_tmr_domain1: 202",
                "hw_tmr_domain2: 303",
                "hw_tmr_voter_domain: 404",
                "software_ecc_enabled: 1",
                f"software_ecc_controller_count: {args.synthetic_software_ecc_controllers}",
                f"software_ecc_dimm_count: {args.synthetic_software_ecc_dimms}",
                f"software_ecc_scrub_rate: {args.synthetic_software_ecc_scrub_rate}",
                f"software_ecc_controller_corrected_error_count: {args.synthetic_software_ecc_controller_corrected_errors}",
                f"software_ecc_controller_uncorrected_error_count: {args.synthetic_software_ecc_controller_uncorrected_errors}",
                f"software_ecc_dimm_corrected_error_count: {args.synthetic_software_ecc_dimm_corrected_errors}",
                f"software_ecc_dimm_uncorrected_error_count: {args.synthetic_software_ecc_dimm_uncorrected_errors}",
                "software_numa_enabled: 1",
                f"software_numa_memtotal_kib: {args.synthetic_software_numa_memtotal_kib}",
                f"software_numa_local_distance: {args.synthetic_software_numa_local_distance}",
                f"software_numa_remote_distance: {args.synthetic_software_numa_remote_distance}",
                f"software_fault_injection_mode: {args.synthetic_software_fault_injection_mode}",
                f"evidence_mac_enabled: {1 if evidence_mac_enabled else 0}",
                f"evidence_mac_key_path: {CONTAINER_EVIDENCE_KEY_PATH}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def docker_diag_config(
    config_path: pathlib.Path,
    args: argparse.Namespace,
    diagnostic_arg: str,
    *,
    secrets_dir: pathlib.Path | None,
) -> dict[str, str]:
    command = [
        "docker",
        "run",
        "--rm",
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
        f"{config_path}:/etc/llps/prod-synthetic.yml:ro",
        "-v",
        f"{ROOT / 'logs'}:/var/log/llps:rw",
        "-e",
        "LLPS_CONFIG=/etc/llps/prod-synthetic.yml",
    ]
    if secrets_dir is not None:
        command.extend(["-v", f"{secrets_dir}:/run/llps-secrets:ro"])
    command.extend(["llps:local", diagnostic_arg])

    result = run(command, env=dict(os.environ), timeout=args.timeout, capture=True)
    return parse_key_values(result.stdout)


def prepare_synthetic_readiness_config(
    args: argparse.Namespace,
    *,
    secrets_dir: pathlib.Path | None,
    audit_key: pathlib.Path | None,
    evidence_key: pathlib.Path | None,
) -> pathlib.Path:
    config_path = HOST_SYNTHETIC_CONFIG
    audit_mac_enabled = audit_key is not None
    evidence_mac_enabled = evidence_key is not None

    write_synthetic_readiness_config(
        config_path,
        args,
        attestation_fingerprint=0,
        observation_digest=0,
        target_host="127.0.0.1",
        audit_enabled=False,
        audit_mac_enabled=False,
        evidence_mac_enabled=evidence_mac_enabled,
    )
    attestation_values = docker_diag_config(
        config_path,
        args,
        "--print-platform-attestation-fingerprint",
        secrets_dir=secrets_dir,
    )
    attestation_fingerprint = int(
        require_diagnostic_key(attestation_values, "platform_attestation_fingerprint")
    )
    if attestation_fingerprint == 0:
        raise CheckError("synthetic readiness attestation fingerprint is zero")

    write_synthetic_readiness_config(
        config_path,
        args,
        attestation_fingerprint=attestation_fingerprint,
        observation_digest=0,
        target_host="127.0.0.1",
        audit_enabled=False,
        audit_mac_enabled=False,
        evidence_mac_enabled=evidence_mac_enabled,
    )
    first_report = docker_diag_config(
        config_path,
        args,
        "--print-readiness-report",
        secrets_dir=secrets_dir,
    )
    observation_digest = int(
        require_diagnostic_key(first_report, "platform_evidence_observation_digest")
    )
    if observation_digest == 0:
        raise CheckError("synthetic readiness observation digest is zero")

    write_synthetic_readiness_config(
        config_path,
        args,
        attestation_fingerprint=attestation_fingerprint,
        observation_digest=observation_digest,
        target_host="127.0.0.1",
        audit_enabled=False,
        audit_mac_enabled=False,
        evidence_mac_enabled=evidence_mac_enabled,
    )
    final_report = docker_diag_config(
        config_path,
        args,
        "--print-readiness-report",
        secrets_dir=secrets_dir,
    )
    verify_synthetic_readiness_report(final_report, args, evidence_mac_enabled)
    write_synthetic_readiness_config(
        config_path,
        args,
        attestation_fingerprint=attestation_fingerprint,
        observation_digest=observation_digest,
        target_host=args.target_host,
        audit_enabled=True,
        audit_mac_enabled=audit_mac_enabled,
        evidence_mac_enabled=evidence_mac_enabled,
    )
    return config_path


def verify_synthetic_readiness_report(
    values: dict[str, str],
    args: argparse.Namespace,
    evidence_mac_enabled: bool,
) -> None:
    expected = {
        "diagnostic_init_status": "0",
        "evidence_collection_status": "0",
        "report_status": "0",
        "configured_require_readiness": "1",
        "configured_platform_safety_flags": "15",
        "configured_platform_evidence_mode": "1",
        "configured_platform_evidence_mode_text": "synthetic",
        "configured_platform_evidence_scope": "software-platform-model",
        "configured_synthetic_evidence_active": "1",
        "configured_software_platform_model_active": "1",
        "configured_ecc_evidence_scope": "software-ecc-model",
        "configured_physical_memory_evidence_scope": "software-numa-model",
        "configured_independent_tmr_evidence_scope": "software-domain-model",
        "configured_payload_ecc_enabled": "1",
        "configured_software_ecc_enabled": "1",
        "configured_software_ecc_controller_count":
            str(args.synthetic_software_ecc_controllers),
        "configured_software_ecc_dimm_count": str(args.synthetic_software_ecc_dimms),
        "configured_software_ecc_scrub_rate":
            str(args.synthetic_software_ecc_scrub_rate),
        "configured_software_ecc_controller_corrected_error_count":
            str(args.synthetic_software_ecc_controller_corrected_errors),
        "configured_software_ecc_controller_uncorrected_error_count":
            str(args.synthetic_software_ecc_controller_uncorrected_errors),
        "configured_software_ecc_dimm_corrected_error_count":
            str(args.synthetic_software_ecc_dimm_corrected_errors),
        "configured_software_ecc_dimm_uncorrected_error_count":
            str(args.synthetic_software_ecc_dimm_uncorrected_errors),
        "configured_software_numa_enabled": "1",
        "configured_software_numa_memtotal_kib": str(args.synthetic_software_numa_memtotal_kib),
        "configured_software_numa_local_distance":
            str(args.synthetic_software_numa_local_distance),
        "configured_software_numa_remote_distance":
            str(args.synthetic_software_numa_remote_distance),
        "evidence_software_ecc_controller_count":
            str(args.synthetic_software_ecc_controllers),
        "evidence_software_dimm_bank_count": str(args.synthetic_software_ecc_dimms),
        "evidence_software_ecc_scrub_rate":
            str(args.synthetic_software_ecc_scrub_rate),
        "evidence_edac_corrected_error_count":
            str(args.synthetic_software_ecc_controller_corrected_errors),
        "evidence_edac_uncorrected_error_count":
            str(args.synthetic_software_ecc_controller_uncorrected_errors),
        "evidence_edac_dimm_corrected_error_count":
            str(args.synthetic_software_ecc_dimm_corrected_errors),
        "evidence_edac_dimm_uncorrected_error_count":
            str(args.synthetic_software_ecc_dimm_uncorrected_errors),
        "software_ecc_controller_count":
            str(args.synthetic_software_ecc_controllers),
        "software_dimm_bank_count": str(args.synthetic_software_ecc_dimms),
        "software_ecc_scrub_rate": str(args.synthetic_software_ecc_scrub_rate),
        "edac_corrected_error_count":
            str(args.synthetic_software_ecc_controller_corrected_errors),
        "edac_uncorrected_error_count":
            str(args.synthetic_software_ecc_controller_uncorrected_errors),
        "edac_dimm_corrected_error_count":
            str(args.synthetic_software_ecc_dimm_corrected_errors),
        "edac_dimm_uncorrected_error_count":
            str(args.synthetic_software_ecc_dimm_uncorrected_errors),
        "evidence_software_dimm_fault_injection_coverage":
            synthetic_fault_coverage(args.synthetic_software_fault_injection_mode),
        "software_dimm_fault_injection_coverage":
            synthetic_fault_coverage(args.synthetic_software_fault_injection_mode),
        "configured_software_fault_injection_mode_text":
            synthetic_fault_mode_text(args.synthetic_software_fault_injection_mode),
        "evidence_software_fault_injection_mode_text":
            synthetic_fault_mode_text(args.synthetic_software_fault_injection_mode),
        "software_fault_injection_mode_text":
            synthetic_fault_mode_text(args.synthetic_software_fault_injection_mode),
        "platform_evidence_valid": "1",
        "platform_evidence_mode_text": "synthetic",
        "platform_evidence_scope": "software-platform-model",
        "synthetic_evidence_active": "1",
        "software_platform_model_active": "1",
        "ecc_evidence_scope": "software-ecc-model",
        "physical_memory_evidence_scope": "software-numa-model",
        "independent_tmr_evidence_scope": "software-domain-model",
        "software_tmr_ready": "1",
        "ecc_memory_ready": "1",
        "ecc_counters_clean": "1",
        "physical_memory_separation_ready": "1",
        "independent_hardware_tmr_ready": "1",
        "software_evidence_self_test_ready": "1",
        "payload_ecc_ready": "1",
        "configured_evidence_request_bound": "1",
        "configured_platform_observation_digest_bound": "1",
        "configured_evidence_mac_enabled": "1" if evidence_mac_enabled else "0",
        "evidence_mac_valid": "1",
        "gate_passed": "1",
        "missing_requirements": "0x00000000",
    }
    expected_memtotal_kib = args.synthetic_software_numa_memtotal_kib * 3
    expected_distance_sum = (
        (3 * args.synthetic_software_numa_local_distance)
        + (6 * args.synthetic_software_numa_remote_distance)
    )
    expected.update(
        {
            "physical_domain_memtotal_kib": str(expected_memtotal_kib),
            "physical_domain_distance_sum": str(expected_distance_sum),
            "physical_domain_distance_01":
                str(args.synthetic_software_numa_remote_distance),
            "physical_domain_distance_02":
                str(args.synthetic_software_numa_remote_distance),
            "physical_domain_distance_12":
                str(args.synthetic_software_numa_remote_distance),
        }
    )

    for key, expected_value in expected.items():
        actual = require_diagnostic_key(values, key)
        if actual != expected_value:
            raise CheckError(
                f"synthetic readiness {key} expected {expected_value!r}, got {actual!r}"
            )

    for key in (
        "software_dimm_observation_fingerprint",
        "software_numa_profile_fingerprint",
        "platform_evidence_observation_digest",
    ):
        if int(require_diagnostic_key(values, key)) == 0:
            raise CheckError(f"synthetic readiness {key} is zero")


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
    if args.synthetic_software_fault_injection_mode == "off":
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
            str(args.synthetic_software_ecc_controllers) and
        block["software_ecc_dimm_count"] ==
            str(args.synthetic_software_ecc_dimms) and
        block["software_ecc_scrub_rate"] ==
            str(args.synthetic_software_ecc_scrub_rate) and
        block["software_ecc_controller_corrected_error_count"] ==
            str(args.synthetic_software_ecc_controller_corrected_errors) and
        block["software_ecc_controller_uncorrected_error_count"] ==
            str(args.synthetic_software_ecc_controller_uncorrected_errors) and
        block["software_ecc_dimm_corrected_error_count"] ==
            str(args.synthetic_software_ecc_dimm_corrected_errors) and
        block["software_ecc_dimm_uncorrected_error_count"] ==
            str(args.synthetic_software_ecc_dimm_uncorrected_errors) and
        block["software_numa_enabled"] == "1" and
        block["software_numa_memtotal_kib"] ==
            str(args.synthetic_software_numa_memtotal_kib) and
        block["software_numa_local_distance"] ==
            str(args.synthetic_software_numa_local_distance) and
        block["software_numa_remote_distance"] ==
            str(args.synthetic_software_numa_remote_distance) and
        block["software_fault_injection_mode"] ==
            synthetic_fault_mode_value(args.synthetic_software_fault_injection_mode) and
        block["software_fault_injection_mode_text"] ==
            synthetic_fault_mode_text(args.synthetic_software_fault_injection_mode)
    )


def verify_runtime_synthetic_readiness_log(
    logs: str,
    args: argparse.Namespace,
) -> None:
    if not any(
        runtime_patrol_block_matches(block, args)
        for block in parse_runtime_patrol_blocks(logs)
    ):
        raise CheckError(
            "runtime synthetic readiness log did not contain a verified "
            "patrol pass block"
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
            raise CheckError(
                "runtime LLAM contract log did not contain "
                f"{token!r}"
            )


def read_docker_logs(env: dict[str, str], tail: int) -> str:
    text = ""
    for name in (env["LLPS_DOCKER_PROXY"], env["LLPS_DOCKER_TARGET"]):
        command = ["docker", "logs"]
        if tail > 0:
            command.extend(["--tail", str(tail)])
        command.append(name)
        result = run(command, env=env, timeout=20.0, capture=True, quiet=True)
        text += result.stdout + result.stderr
    return text


def wait_for_runtime_synthetic_readiness_log(
    env: dict[str, str],
    args: argparse.Namespace,
) -> str:
    deadline = time.monotonic() + args.synthetic_runtime_patrol_wait
    last_logs = ""

    while time.monotonic() <= deadline:
        last_logs = read_docker_logs(env, max(args.log_tail, 2000))
        if "readiness_monitor_fail" in last_logs:
            raise CheckError(
                "runtime synthetic readiness monitor reported failure"
            )
        try:
            verify_runtime_synthetic_readiness_log(last_logs, args)
            return last_logs
        except CheckError:
            time.sleep(0.25)

    raise CheckError(
        "runtime synthetic readiness monitor did not report a patrol pass"
    )


def wait_for_container_health(
    container: str,
    *,
    env: dict[str, str],
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    last_status = "unknown"

    while time.monotonic() < deadline:
        container_id = output(
            ["docker", "inspect", "-f", "{{.Id}}", container],
            env=env,
            timeout=10.0,
        ).strip()
        if not container_id:
            last_status = "missing"
            time.sleep(1.0)
            continue

        status = output(
            [
                "docker",
                "inspect",
                "-f",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                container_id,
            ],
            env=env,
            timeout=10.0,
        ).strip()
        last_status = status
        if status in ("healthy", "running"):
            print(f"{container}: {status}", flush=True)
            return
        if status in ("unhealthy", "exited", "dead"):
            raise CheckError(f"{container} entered {status} state")
        time.sleep(1.0)

    raise CheckError(f"{container} did not become healthy; last_status={last_status}")


def wait_for_tcp(host: str, port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None

    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.25)

    raise CheckError(f"TCP endpoint {host}:{port} did not open: {last_error}")


def wait_for_file(path: pathlib.Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(0.25)
    raise CheckError(f"audit log was not written: {path}")


def verify_audit_log(
    audit_log: pathlib.Path,
    *,
    audit_key: pathlib.Path | None,
    timeout: float,
    env: dict[str, str],
    require_sequential_seq: bool,
    require_readiness_evidence: bool,
) -> None:
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    command = [
        sys.executable,
        str(ROOT / "tools" / "verify_pxf_audit_mac.py"),
        "--audit-log",
        str(audit_log),
        "--min-records",
        "3",
        "--require-event",
        "accept",
        "--require-event",
        "backend_connect",
        "--require-event",
        "close",
        "--require-nonzero-request-no",
    ]
    if require_sequential_seq:
        command.append("--require-sequential-seq")
    if require_readiness_evidence:
        command.extend([
            "--min-evidence-records",
            "1",
            "--require-evidence-event",
            "readiness_monitor_pass",
        ])
    if audit_key is not None:
        command.extend(["--key", str(audit_key), "--require-mac"])

    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                check=False,
                timeout=min(10.0, max(1.0, deadline - time.monotonic())),
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                last_error = (result.stderr or result.stdout).strip()
                time.sleep(0.25)
                continue
            if result.stdout:
                print(result.stdout, end="", flush=True)
            return
        except subprocess.TimeoutExpired as exc:
            last_error = f"timed out after {exc.timeout:.1f}s"
            time.sleep(0.25)

    raise CheckError(f"audit log verification did not pass: {last_error}")


def run_host_chat_smoke(args: argparse.Namespace, env: dict[str, str]) -> None:
    token = f"host-smoke-{int(time.time())}"
    run(
        [
            sys.executable,
            str(ROOT / "tools" / "chat_client.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(args.published_port),
            "--message",
            token,
            "--expect",
            token,
            "--timeout",
            str(args.chat_timeout),
        ],
        env=env,
        timeout=args.chat_timeout + 3.0,
        capture=True,
    )


def protocol_varint(value: int) -> bytes:
    out = bytearray()
    if value < 0:
        raise CheckError("Protocol VarInt value must be non-negative")
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)


def protocol_handshake_body(
    *,
    host: str,
    port: int,
    protocol_version: int = 765,
    next_state: int = 2,
    packet_id: int = 0,
) -> bytes:
    host_bytes = host.encode("ascii")
    if not host_bytes or len(host_bytes) > 255:
        raise CheckError("Protocol host length must be 1..255 ASCII bytes")
    if port < 0 or port > 65535:
        raise CheckError("Protocol port must fit u16")

    body = bytearray()
    body.extend(protocol_varint(packet_id))
    body.extend(protocol_varint(protocol_version))
    body.extend(protocol_varint(len(host_bytes)))
    body.extend(host_bytes)
    body.extend(port.to_bytes(2, "big"))
    body.extend(protocol_varint(next_state))
    return bytes(body)


def protocol_packet(body: bytes) -> bytes:
    return protocol_varint(len(body)) + body


def protocol_noncanonical_varint(value: int) -> bytes:
    canonical = protocol_varint(value)
    if len(canonical) >= 5:
        raise CheckError("cannot make a longer bounded Protocol VarInt")
    return canonical[:-1] + bytes([canonical[-1] | 0x80, 0x00])


def protocol_handshake(
    *,
    host: str,
    port: int,
    protocol_version: int = 765,
    next_state: int = 2,
    packet_id: int = 0,
) -> bytes:
    body = protocol_handshake_body(
        host=host,
        port=port,
        protocol_version=protocol_version,
        next_state=next_state,
        packet_id=packet_id,
    )
    return protocol_packet(body)


def protocol_invalid_preface_cases(
    *,
    host: str,
    port: int,
) -> tuple[tuple[str, bytes], ...]:
    valid_body = protocol_handshake_body(host=host, port=port)
    noncanonical_packet_id_body = (
        protocol_noncanonical_varint(0) +
        protocol_varint(765) +
        protocol_varint(len(host)) +
        host.encode("ascii") +
        port.to_bytes(2, "big") +
        protocol_varint(2)
    )
    oversized_addr = b"a" * 256
    oversized_addr_body = (
        protocol_varint(0) +
        protocol_varint(765) +
        protocol_varint(len(oversized_addr)) +
        oversized_addr +
        port.to_bytes(2, "big") +
        protocol_varint(2)
    )
    return (
        (
            "bad_packet_id",
            protocol_handshake(host=host, port=port, packet_id=1),
        ),
        ("zero_port", protocol_handshake(host=host, port=0)),
        ("zero_protocol", protocol_handshake(host=host, port=port, protocol_version=0)),
        ("bad_next_state", protocol_handshake(host=host, port=port, next_state=3)),
        ("overwide_varint", b"\x80\x80\x80\x80\x80"),
        (
            "noncanonical_packet_length",
            protocol_noncanonical_varint(len(valid_body)) + valid_body,
        ),
        (
            "noncanonical_packet_id",
            protocol_packet(noncanonical_packet_id_body),
        ),
        ("oversized_address", protocol_packet(oversized_addr_body)),
    )


def recv_until(sock: socket.socket, token: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    data = bytearray()
    token_bytes = token.encode("utf-8")

    while time.monotonic() < deadline:
        sock.settimeout(max(0.05, min(0.25, deadline - time.monotonic())))
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
    raise CheckError(f"did not receive {token!r} through Protocol gate; got {text!r}")


def send_invalid_protocol_preface(host: str, port: int, payload: bytes, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
            while time.monotonic() < deadline:
                sock.settimeout(max(0.05, min(0.25, deadline - time.monotonic())))
                try:
                    chunk = sock.recv(64)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    return
                if chunk == b"":
                    return
    except ConnectionResetError:
        return
    raise CheckError("invalid Protocol preface was not closed by LLPS")


def open_idle_protocol_preface(host: str, port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            while time.monotonic() < deadline:
                sock.settimeout(max(0.05, min(0.25, deadline - time.monotonic())))
                try:
                    chunk = sock.recv(64)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    return
                if chunk == b"":
                    return
    except ConnectionResetError:
        return
    raise CheckError("idle Protocol preface was not closed by LLPS")


def run_host_protocol_gate_smoke(args: argparse.Namespace, env: dict[str, str]) -> None:
    del env
    idle_timeout = max(
        args.chat_timeout,
        (float(args.protocol_preface_timeout_ms) / 1000.0) + 3.0,
    )
    open_idle_protocol_preface(
        "127.0.0.1",
        args.published_port,
        idle_timeout,
    )

    invalid_cases = protocol_invalid_preface_cases(
        host=args.protocol_host,
        port=args.target_port,
    )
    for case_name, payload in invalid_cases:
        print(f"protocol_gate_invalid_case name={case_name}", flush=True)
        send_invalid_protocol_preface(
            "127.0.0.1",
            args.published_port,
            payload,
            args.chat_timeout,
        )

    token = f"protocol-gate-smoke-{int(time.time())}"
    payload = (
        protocol_handshake(host=args.protocol_host, port=args.target_port) +
        (token + "\n").encode("utf-8")
    )
    with socket.create_connection(
        ("127.0.0.1", args.published_port),
        timeout=args.chat_timeout,
    ) as sock:
        sock.sendall(payload)
        text = recv_until(sock, token, args.chat_timeout)
        print(text, end="" if text.endswith("\n") else "\n", flush=True)


def verify_protocol_gate_audit(
    audit_log: pathlib.Path,
    *,
    timeout: float,
    expected_invalid_count: int,
) -> None:
    deadline = time.monotonic() + timeout
    last_error: str | None = None

    while time.monotonic() < deadline:
        try:
            entries, _evidence_entries = parse_pxf(
                audit_log.read_text(encoding="utf-8", errors="strict")
            )
            events_by_request: dict[str, set[str]] = {}
            invalid_requests: set[str] = set()
            idle_timeout_requests: set[str] = set()
            for entry in entries:
                record = entry["record"]
                if not isinstance(record, dict):
                    raise CheckError("invalid parsed audit record")
                request_no = str(record["request_no"])
                event = str(record["event"])
                reason = str(record["reason"])
                events_by_request.setdefault(request_no, set()).add(event)
                if event == "backend_fail" and reason == "protocol_handshake_invalid":
                    invalid_requests.add(request_no)
                if event == "backend_fail" and reason == "client_preface_timeout":
                    idle_timeout_requests.add(request_no)

            if len(invalid_requests) < expected_invalid_count:
                last_error = (
                    "protocol_handshake_invalid backend_fail count "
                    f"{len(invalid_requests)} < expected {expected_invalid_count}"
                )
                time.sleep(0.25)
                continue
            if not idle_timeout_requests:
                last_error = "no client_preface_timeout backend_fail record yet"
                time.sleep(0.25)
                continue

            blocked_requests = invalid_requests | idle_timeout_requests
            connected_invalid = sorted(
                request_no
                for request_no in blocked_requests
                if "backend_connect" in events_by_request.get(request_no, set())
            )
            if connected_invalid:
                raise CheckError(
                    "blocked Protocol preface reached backend_connect for "
                    f"request_no={connected_invalid!r}"
                )
            if not any("backend_connect" in events for events in events_by_request.values()):
                last_error = "valid Protocol handshake has no backend_connect yet"
                time.sleep(0.25)
                continue
            print(
                "OK: verified Protocol gate audit "
                f"invalid={len(invalid_requests)} "
                f"idle_timeout={len(idle_timeout_requests)}",
                flush=True,
            )
            return
        except (OSError, UnicodeDecodeError, VerificationError) as exc:
            last_error = str(exc)
            time.sleep(0.25)

    raise CheckError(f"Protocol gate audit verification did not pass: {last_error}")


def show_logs(env: dict[str, str], tail: int) -> str:
    print(f"\nRecent Docker logs (tail={tail})", flush=True)
    logs = read_docker_logs(env, tail)
    print(logs, end="", flush=True)
    return logs


def verify_runtime_audit_log_detail(
    logs: str,
    *,
    audit_mac_enabled: bool,
) -> None:
    required_tokens = (
        "audit_event",
        "request_no=",
        "event_no=",
        "total_events=",
        "endpoints:",
    )

    for token in required_tokens:
        if token not in logs:
            raise CheckError(
                "runtime audit detail log did not contain "
                f"{token!r}"
            )

    if audit_mac_enabled:
        if "mac=enabled" not in logs:
            raise CheckError(
                "runtime audit detail log did not report mac=enabled"
            )
        if "mac_key_fingerprint=0x00000000" in logs:
            raise CheckError(
                "runtime audit detail log reported a zero MAC key fingerprint"
            )
    elif "mac=disabled" not in logs:
        raise CheckError(
            "runtime audit detail log did not report mac=disabled"
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--published-port", type=int, default=25565)
    parser.add_argument("--target-host", default="chat-target")
    parser.add_argument("--target-port", type=int, default=25566)
    parser.add_argument("--audit-log", type=pathlib.Path, default=DEFAULT_AUDIT_LOG)
    parser.add_argument(
        "--audit-key",
        type=pathlib.Path,
        help="enable audit HMAC using this host key, staged into a temporary read-only mount",
    )
    parser.add_argument(
        "--audit-mac",
        action="store_true",
        help="enable audit HMAC with a generated temporary read-only key",
    )
    parser.add_argument(
        "--evidence-key",
        type=pathlib.Path,
        help="use this evidence HMAC key when --synthetic-readiness is enabled",
    )
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--chat-timeout", type=float, default=8.0)
    parser.add_argument("--log-tail", type=int, default=120)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--keep-existing-log", action="store_true")
    parser.add_argument("--io-logs", action="store_true")
    parser.add_argument(
        "--protocol-gate",
        action="store_true",
        help="enable the Protocol handshake gate and verify valid/invalid handshakes",
    )
    parser.add_argument(
        "--protocol-host",
        default="mc.example",
        help="server-address field to place in the synthetic Protocol handshake",
    )
    parser.add_argument(
        "--protocol-preface-timeout-ms",
        type=int,
        default=1000,
        help="preface timeout used when --protocol-gate is enabled",
    )
    parser.add_argument(
        "--synthetic-readiness",
        action="store_true",
        help="run Dockerfile-only traffic with synthetic software ECC/NUMA readiness enabled",
    )
    parser.add_argument("--synthetic-evidence-id", type=int, default=42424242)
    parser.add_argument("--synthetic-software-ecc-dimms", type=int, default=8)
    parser.add_argument("--synthetic-software-ecc-controllers",
                        type=int,
                        default=1)
    parser.add_argument("--synthetic-software-ecc-scrub-rate",
                        type=int,
                        default=4096)
    parser.add_argument("--synthetic-software-ecc-controller-corrected-errors",
                        type=int,
                        default=0)
    parser.add_argument("--synthetic-software-ecc-controller-uncorrected-errors",
                        type=int,
                        default=0)
    parser.add_argument("--synthetic-software-ecc-dimm-corrected-errors",
                        type=int,
                        default=0)
    parser.add_argument("--synthetic-software-ecc-dimm-uncorrected-errors",
                        type=int,
                        default=0)
    parser.add_argument(
        "--synthetic-software-numa-memtotal-kib",
        type=int,
        default=65536,
    )
    parser.add_argument(
        "--synthetic-software-numa-local-distance",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--synthetic-software-numa-remote-distance",
        type=int,
        default=20,
    )
    parser.add_argument(
        "--synthetic-software-fault-injection-mode",
        choices=("off", "single", "double", "full"),
        default="full",
    )
    parser.add_argument("--synthetic-runtime-patrol-wait", type=float, default=20.0)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    env: dict[str, str] | None = None
    staged_secrets: tempfile.TemporaryDirectory[str] | None = None
    staged_audit_key: pathlib.Path | None = None
    staged_evidence_key: pathlib.Path | None = None
    audit_log = args.audit_log if args.audit_log.is_absolute() else ROOT / args.audit_log
    audit_log.parent.mkdir(parents=True, exist_ok=True)

    try:
        staged_secrets, staged_audit_key, staged_evidence_key = stage_secret_keys(args)
        secrets_dir = (
            pathlib.Path(staged_secrets.name)
            if staged_secrets is not None
            else None
        )
        env = docker_env(
            args,
            audit_mac_enabled=staged_audit_key is not None,
            secrets_dir=secrets_dir,
        )
        if not args.keep_existing_log and audit_log.exists():
            audit_log.unlink()
        if not args.skip_build:
            docker_build_target("runtime", "llps:local", args.timeout)
            docker_build_target("chat-target", "llps-chat-target:local", args.timeout)
            if not args.protocol_gate:
                docker_build_target("smoke-client", "llps-smoke-client:local", args.timeout)
        if args.synthetic_readiness:
            prepare_synthetic_readiness_config(
                args,
                secrets_dir=secrets_dir,
                audit_key=staged_audit_key,
                evidence_key=staged_evidence_key,
            )
        if not args.keep_existing_log and audit_log.exists():
            audit_log.unlink()

        docker_rm(env["LLPS_DOCKER_PROXY"])
        docker_rm(env["LLPS_DOCKER_TARGET"])
        docker_network_rm(env["LLPS_DOCKER_NETWORK"])
        run(
            ["docker", "network", "create", env["LLPS_DOCKER_NETWORK"]],
            env=env,
            timeout=20.0,
            capture=True,
        )

        target_run = [
            "docker",
            "run",
            "-d",
            "--name",
            env["LLPS_DOCKER_TARGET"],
            "--network",
            env["LLPS_DOCKER_NETWORK"],
            "--network-alias",
            "chat-target",
        ]
        if args.target_host != "chat-target":
            target_run.extend(["--network-alias", args.target_host])
        target_run.extend(
            [
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "llps-chat-target:local",
            ]
        )
        run(target_run, env=env, timeout=20.0, capture=True)

        logs_dir = ROOT / "logs"
        logs_dir.mkdir(exist_ok=True)
        proxy_run = [
            "docker",
            "run",
            "-d",
            "--name",
            env["LLPS_DOCKER_PROXY"],
            "--network",
            env["LLPS_DOCKER_NETWORK"],
            "--network-alias",
            "llps",
            "-p",
            f"{args.published_port}:25565",
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
        ]
        if secrets_dir is not None:
            proxy_run.extend(["-v", f"{secrets_dir}:/run/llps-secrets:ro"])
        for key in (
            "LLPS_CONFIG",
            "LLPS_LISTEN_HOST",
            "LLPS_LISTEN_PORT",
            "LLPS_TARGET_HOST",
            "LLPS_TARGET_PORT",
            "LLPS_IP_AUDIT_ENABLED",
            "LLPS_IP_AUDIT_PATH",
            "LLPS_AUDIT_MAC_ENABLED",
            "LLPS_AUDIT_MAC_KEY_PATH",
            "LLPS_CLIENT_PREFACE_TIMEOUT_MS",
            "LLPS_PROTOCOL_HANDSHAKE_GATE_ENABLED",
            "LLPS_LOG",
            "LLPS_LOG_AUDIT",
            "LLPS_LOG_EVIDENCE",
            "LLPS_LOG_IO",
            "LLPS_SECRETS_DIR",
        ):
            if key in env:
                proxy_run.extend(["-e", f"{key}={env[key]}"])
        proxy_run.append("llps:local")
        run(proxy_run, env=env, timeout=20.0, capture=True)

        wait_for_container_health(env["LLPS_DOCKER_TARGET"], env=env, timeout=args.timeout)
        wait_for_container_health(env["LLPS_DOCKER_PROXY"], env=env, timeout=args.timeout)
        wait_for_tcp("127.0.0.1", args.published_port, args.timeout)
        startup_logs = read_docker_logs(env, 0)
        verify_runtime_llam_contract_log(startup_logs)

        if args.protocol_gate:
            run_host_protocol_gate_smoke(args, env)
        else:
            run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    env["LLPS_DOCKER_NETWORK"],
                    "llps-smoke-client:local",
                    "--host",
                    "llps",
                    "--port",
                    "25565",
                    "--message",
                    "dockerfile-smoke-through-llps",
                    "--expect",
                    "dockerfile-smoke-through-llps",
                    "--timeout",
                    str(args.chat_timeout),
                ],
                env=env,
                timeout=args.timeout,
                capture=True,
            )
            run_host_chat_smoke(args, env)

        wait_for_file(audit_log, args.timeout)
        verify_audit_log(
            audit_log,
            audit_key=staged_audit_key,
            timeout=args.timeout,
            env=env,
            require_sequential_seq=not args.keep_existing_log,
            require_readiness_evidence=args.synthetic_readiness,
        )
        if args.protocol_gate:
            verify_protocol_gate_audit(
                audit_log,
                timeout=args.timeout,
                expected_invalid_count=len(
                    protocol_invalid_preface_cases(
                        host=args.protocol_host,
                        port=args.target_port,
                    )
                ),
            )
        synthetic_logs = ""
        if args.synthetic_readiness:
            synthetic_logs = wait_for_runtime_synthetic_readiness_log(env, args)
        logs = show_logs(env, args.log_tail)
        verify_runtime_audit_log_detail(
            logs,
            audit_mac_enabled=staged_audit_key is not None,
        )
        if args.synthetic_readiness:
            verify_runtime_synthetic_readiness_log(synthetic_logs + logs, args)
    except CheckError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr, flush=True)
        if env is not None:
            try:
                show_logs(env, args.log_tail)
            except CheckError:
                pass
        return 1
    finally:
        if (env is not None) and not args.keep_running:
            try:
                docker_rm(env["LLPS_DOCKER_PROXY"])
                docker_rm(env["LLPS_DOCKER_TARGET"])
                docker_network_rm(env["LLPS_DOCKER_NETWORK"])
            except CheckError as exc:
                print(f"WARN: cleanup failed: {exc}", file=sys.stderr, flush=True)
        if staged_secrets is not None:
            staged_secrets.cleanup()

    print(
        "\nOK: Docker production-like LLPS check passed; "
        f"audit_log={audit_log} "
        f"audit_mac={'1' if staged_audit_key is not None else '0'} "
        f"synthetic_readiness={'1' if args.synthetic_readiness else '0'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
