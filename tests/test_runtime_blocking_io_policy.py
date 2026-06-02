#!/usr/bin/env python3
"""Verify runtime watchdog readiness checks stay off the cooperative I/O path."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

BLOCKING_FILE_IO_TOKENS = (
    "fopen(",
    "fgets(",
    "opendir(",
    "readdir(",
    "closedir(",
    "mincore(",
    "move_pages(",
)


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


def strip_test_hook_branch(body: str) -> str:
    pattern = re.compile(
        r"#if\s+defined\(LLPS_TEST_HOOKS\).*?#else\s*(.*?)#endif",
        re.DOTALL,
    )
    return pattern.sub(lambda match: match.group(1), body)


def assert_tokens_absent(name: str, body: str, tokens: tuple[str, ...]) -> list[str]:
    return [f"{name}: contains blocking token {token}" for token in tokens if token in body]


def main() -> int:
    problems: list[str] = []
    core = (REPO_ROOT / "src" / "core" / "llps_state.c").read_text(
        encoding="utf-8"
    )
    worker = (
        REPO_ROOT
        / "src"
        / "readiness"
        / "llps_readiness_monitor_worker.c"
    ).read_text(encoding="utf-8")

    watchdog_body = function_body(core, "llps_task_watchdog")
    monitor_body = function_body(core, "llps_readiness_runtime_monitor_tick")
    monitor_runtime_body = strip_test_hook_branch(monitor_body)
    worker_task_body = function_body(
        worker,
        "llps_readiness_runtime_monitor_worker_task",
    )
    blocking_wrapper_body = function_body(
        worker,
        "llps_readiness_monitor_call_blocking_checked",
    )

    problems.extend(
        assert_tokens_absent(
            "llps_task_watchdog",
            watchdog_body,
            BLOCKING_FILE_IO_TOKENS
            + (
                "llps_collect_platform_safety_evidence",
                "llps_check_configured_readiness_platform_snapshot",
            ),
        )
    )
    if "llps_readiness_runtime_monitor_tick()" not in watchdog_body:
        problems.append("llps_task_watchdog does not delegate readiness monitoring")

    problems.extend(
        assert_tokens_absent(
            "llps_readiness_runtime_monitor_tick runtime branch",
            monitor_runtime_body,
            BLOCKING_FILE_IO_TOKENS
            + (
                "llps_collect_platform_safety_evidence",
                "llps_check_configured_readiness_platform_snapshot",
            ),
        )
    )
    if "llps_readiness_runtime_monitor_worker_poll" not in monitor_runtime_body:
        problems.append(
            "runtime readiness monitor does not poll the offloaded worker"
        )

    if "llps_readiness_monitor_call_blocking_checked" not in worker_task_body:
        problems.append("readiness worker task does not use the checked blocking wrapper")
    if "llam_call_blocking_result" not in blocking_wrapper_body:
        problems.append("checked readiness blocking wrapper does not call LLAM offload")

    if problems:
        for problem in problems:
            print(problem)
        return 1

    print("OK: runtime readiness file I/O remains off the cooperative watchdog path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
