#!/usr/bin/env python3
"""Verify LLPS does not call LLAM primitives outside checked wrappers."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "src"

LLAM_CALL_RE = re.compile(r"\b(llam_[A-Za-z0-9_]+)\s*\(")
FUNCTION_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{")

ALLOWED_CALLS = {
    "src/app/main.c": {
        "llps_dump_llam_runtime_state": {"llam_dump_runtime_state"},
        "llps_shutdown_llam_runtime": {"llam_runtime_shutdown"},
        "llps_spawn_checked": {"llam_spawn_ex"},
        "llps_run_llam_runtime_checked": {"llam_run"},
        "llps_prepare_llam_spawn_opts": {"llam_spawn_opts_init"},
        "llps_init_checked_llam_runtime": {
            "llam_runtime_opts_init",
            "llam_runtime_init_ex",
            "llam_runtime_collect_stats_ex",
        },
    },
    "src/audit/llps_ip_audit.c": {
        "llps_ip_audit_call_blocking_checked": {"llam_call_blocking_result"},
        "llps_ip_audit_writer_mutex_create_checked": {"llam_mutex_create"},
        "llps_ip_audit_writer_mutex_destroy_checked": {"llam_mutex_destroy"},
        "llps_ip_audit_writer_lock_checked": {"llam_mutex_lock"},
        "llps_ip_audit_writer_unlock_checked": {"llam_mutex_unlock"},
    },
    "src/core/llps_state.c": {
        "llps_llam_contract_failure": {"llam_dump_runtime_state"},
        "llps_llam_spawn_opts_prepare": {"llam_spawn_opts_init"},
        "llps_llam_poll_fd_checked": {"llam_poll_fd"},
        "llps_llam_read_when_ready_checked": {"llam_read_when_ready"},
        "llps_llam_yield_checked": {"llam_yield"},
        "llps_llam_sleep_ms_checked": {"llam_sleep_ns"},
        "llps_llam_spawn_checked": {"llam_spawn"},
        "llps_llam_detach_checked": {"llam_detach"},
        "llps_llam_task_group_create_checked": {"llam_task_group_create"},
        "llps_llam_task_group_join_checked": {"llam_task_group_join"},
        "llps_llam_task_group_spawn_checked": {"llam_task_group_spawn"},
        "llps_llam_task_group_destroy_checked": {"llam_task_group_destroy"},
        "llps_llam_now_ns_checked": {"llam_now_ns"},
        "llps_llam_runtime_contract_check": {"llam_runtime_collect_stats_ex"},
    },
    "src/readiness/llps_readiness_monitor_worker.c": {
        "llps_readiness_monitor_channel_destroy_checked": {
            "llam_channel_destroy",
        },
        "llps_readiness_monitor_channel_create_checked": {
            "llam_channel_create",
        },
        "llps_readiness_monitor_spawn_opts_init_checked": {
            "llam_spawn_opts_init",
        },
        "llps_readiness_monitor_spawn_checked": {"llam_spawn_ex"},
        "llps_readiness_monitor_detach_checked": {"llam_detach"},
        "llps_readiness_monitor_call_blocking_checked": {
            "llam_call_blocking_result",
        },
        "llps_readiness_monitor_channel_send_checked": {"llam_channel_send"},
        "llps_readiness_monitor_channel_recv_checked": {
            "llam_channel_recv_result",
        },
        "llps_readiness_monitor_channel_close_checked": {"llam_channel_close"},
    },
}


def strip_line_comments(line: str) -> str:
    """Remove simple C line comments; LLPS sources avoid raw URLs in code."""
    return line.split("//", 1)[0]


def update_function_context(
    raw_line: str,
    brace_depth: int,
    pending_signature: list[str],
    current_function: str | None,
) -> tuple[int, str | None]:
    line = strip_line_comments(raw_line)
    if brace_depth == 0:
        stripped = line.strip()
        if (not pending_signature and
                (not stripped or stripped.startswith("#") or
                 stripped.startswith("/*") or stripped.startswith("*"))):
            return brace_depth, current_function

        pending_signature.append(stripped)
        if "{" in line:
            signature = " ".join(pending_signature)
            pending_signature.clear()
            matches = list(FUNCTION_RE.finditer(signature))
            current_function = matches[-1].group(1) if matches else None
        elif ";" in line:
            pending_signature.clear()
    opens = line.count("{")
    closes = line.count("}")
    brace_depth += opens - closes
    if brace_depth <= 0:
        brace_depth = 0
        if closes > opens:
            current_function = None
    return brace_depth, current_function


def scan_file(path: Path) -> list[str]:
    rel = path.relative_to(REPO_ROOT).as_posix()
    allowed_for_file = ALLOWED_CALLS.get(rel, {})
    problems: list[str] = []
    brace_depth = 0
    current_function: str | None = None
    pending_signature: list[str] = []

    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        brace_depth, current_function = update_function_context(
            raw_line,
            brace_depth,
            pending_signature,
            current_function,
        )
        line = strip_line_comments(raw_line)
        for match in LLAM_CALL_RE.finditer(line):
            call = match.group(1)
            allowed_calls = allowed_for_file.get(current_function or "", set())
            if call not in allowed_calls:
                problems.append(
                    f"{rel}:{line_no}: {call} outside allowed LLAM contract "
                    f"wrapper function {current_function or '<global>'}"
                )

    return problems


def function_body(source: str, function_name: str) -> str:
    marker = f"{function_name}("
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing function {function_name}")
    brace_start = source.find("{", start)
    if brace_start < 0:
        raise AssertionError(f"missing body for function {function_name}")

    depth = 0
    for index in range(brace_start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace_start:index + 1]
    raise AssertionError(f"unterminated body for function {function_name}")


def verify_blocking_wrappers_require_operation_label() -> list[str]:
    checks = {
        "src/audit/llps_ip_audit.c": "llps_ip_audit_call_blocking_checked",
        "src/readiness/llps_readiness_monitor_worker.c":
            "llps_readiness_monitor_call_blocking_checked",
    }
    problems: list[str] = []

    for rel, function_name in checks.items():
        source = (REPO_ROOT / rel).read_text(encoding="utf-8")
        body = function_body(source, function_name)
        if "operation == NULL" not in body:
            problems.append(
                f"{rel}: {function_name} does not reject NULL operation labels"
            )
        if "llam_call_blocking_result" not in body:
            problems.append(
                f"{rel}: {function_name} does not wrap llam_call_blocking_result"
            )

    return problems


def verify_free_list_mutators_guard_scheduler_contract() -> list[str]:
    rel = "src/core/llps_state.c"
    source = (REPO_ROOT / rel).read_text(encoding="utf-8")
    problems: list[str] = []

    helper_body = function_body(
        source,
        "llps_free_list_scheduler_contract_is_valid",
    )
    if "llps_llam_runtime_contract_check()" not in helper_body:
        problems.append(
            f"{rel}: free-list scheduler guard does not check LLAM runtime "
            "contract"
        )
    if "LLPS_TEST_HOOKS" not in helper_body:
        problems.append(
            f"{rel}: free-list scheduler guard does not preserve test hooks"
        )

    for function_name in (
        "llps_free_list_contains",
        "llps_return_session_to_freelist",
        "llps_find_free_session",
    ):
        body = function_body(source, function_name)
        if "llps_free_list_scheduler_contract_is_valid()" not in body:
            problems.append(
                f"{rel}: {function_name} does not guard the single-worker "
                "free-list contract"
            )

    return problems


def main() -> int:
    problems: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.c")):
        problems.extend(scan_file(path))
    problems.extend(verify_blocking_wrappers_require_operation_label())
    problems.extend(verify_free_list_mutators_guard_scheduler_contract())

    if problems:
        for problem in problems:
            print(problem)
        return 1

    print("OK: LLAM calls are confined to checked LLPS wrapper functions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
