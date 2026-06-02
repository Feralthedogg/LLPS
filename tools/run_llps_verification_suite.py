#!/usr/bin/env python3
"""Run the LLPS local and Docker verification suite."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_BUILD_DIR = ROOT / "build-test"
FORBIDDEN_TOKENS = (
    "SI" + "L4",
    "Safety Integrity Level " + "4",
    "SPDX-" + "License-Identifier",
    "Copy" + "right",
)
FORBIDDEN_SCAN_PATHS = (
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


class VerificationSuiteError(RuntimeError):
    """Raised when a verification step fails."""


def run(command: list[str], *, timeout: float, quiet: bool) -> subprocess.CompletedProcess[str]:
    if not quiet:
        print(f"\n$ {' '.join(command)}", flush=True)
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            timeout=timeout,
            text=True,
            capture_output=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerificationSuiteError(
            f"timed out after {timeout:.1f}s: {' '.join(command)}"
        ) from exc

    if not quiet:
        if result.stdout:
            print(result.stdout, end="", flush=True)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr, flush=True)

    if result.returncode != 0:
        raise VerificationSuiteError(
            f"command failed with exit code {result.returncode}: "
            f"{' '.join(command)}\n{result.stdout}{result.stderr}"
        )
    return result


def iter_scan_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for name in FORBIDDEN_SCAN_PATHS:
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


def scan_forbidden_tokens() -> None:
    hits: list[str] = []
    for path in iter_scan_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(ROOT).as_posix()
        for token in FORBIDDEN_TOKENS:
            if token in text:
                hits.append(f"{rel}: contains {token!r}")
    if hits:
        raise VerificationSuiteError(
            "forbidden text found:\n" + "\n".join(hits)
        )


def docker_container_leaks() -> str:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "name=llps",
            "--format",
            "{{.Names}} {{.Status}}",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return result.stdout + result.stderr
    return result.stdout.strip()


def benchmark_summary_line(output: str) -> str:
    summary = ""
    for line in output.splitlines():
        if line.startswith("OK: Docker LLPS benchmark passed;"):
            summary = line
    return summary


def step_commands(args: argparse.Namespace) -> list[tuple[str, list[str], float]]:
    python = sys.executable
    commands: list[tuple[str, list[str], float]] = [
        (
            "completion_audit",
            [python, "tools/run_llps_completion_audit.py"],
            args.local_timeout,
        ),
        (
            "cmake_configure",
            ["cmake", "-S", ".", "-B", str(args.build_dir)],
            args.local_timeout,
        ),
        (
            "cmake_build",
            ["cmake", "--build", str(args.build_dir)],
            args.local_timeout,
        ),
        (
            "ctest",
            ["ctest", "--test-dir", str(args.build_dir), "--output-on-failure"],
            args.local_timeout,
        ),
    ]

    if not args.skip_docker:
        commands.extend(
            [
                (
                    "docker_prod_synthetic_readiness",
                    [
                        python,
                        "tools/run_docker_prod_check.py",
                        "--skip-build",
                        "--audit-mac",
                        "--synthetic-readiness",
                        "--timeout",
                        str(args.docker_timeout),
                        "--chat-timeout",
                        str(args.chat_timeout),
                        "--log-tail",
                        "120",
                    ],
                    args.docker_timeout + 30.0,
                ),
                (
                    "docker_protocol_gate",
                    [
                        python,
                        "tools/run_docker_prod_check.py",
                        "--skip-build",
                        "--audit-mac",
                        "--protocol-gate",
                        "--timeout",
                        str(args.docker_timeout),
                        "--chat-timeout",
                        str(args.chat_timeout),
                        "--log-tail",
                        "80",
                    ],
                    args.docker_timeout + 30.0,
                ),
                (
                    "docker_synthetic_soak",
                    [
                        python,
                        "tools/run_docker_synthetic_soak.py",
                        "--skip-build",
                        "--iterations",
                        str(args.soak_iterations),
                        "--profile-timeout",
                        str(args.soak_profile_timeout),
                        "--runtime-patrol-wait",
                        str(args.runtime_patrol_wait),
                        "--quiet",
                    ],
                    (args.soak_profile_timeout * 3.0 * args.soak_iterations) + 30.0,
                ),
            ]
        )

    if args.with_bench and not args.skip_docker:
        benchmark_base = [
            python,
            "tools/run_docker_bench.py",
            "--skip-build",
            "--quiet-llps-logs",
            "--clients",
            str(args.bench_clients),
            "--duration",
            str(args.bench_duration),
        ]
        commands.extend(
            [
                (
                    "docker_benchmark_baseline",
                    benchmark_base,
                    args.bench_timeout,
                ),
                (
                    "docker_benchmark_payload_ecc",
                    benchmark_base + ["--payload-ecc"],
                    args.bench_timeout,
                ),
            ]
        )

    return commands


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=pathlib.Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--local-timeout", type=float, default=120.0)
    parser.add_argument("--docker-timeout", type=float, default=60.0)
    parser.add_argument("--chat-timeout", type=float, default=12.0)
    parser.add_argument("--skip-docker", action="store_true")
    parser.add_argument("--soak-iterations", type=int, default=1)
    parser.add_argument("--soak-profile-timeout", type=float, default=180.0)
    parser.add_argument("--runtime-patrol-wait", type=float, default=6.0)
    parser.add_argument("--with-bench", action="store_true")
    parser.add_argument("--bench-clients", type=int, default=100)
    parser.add_argument("--bench-duration", type=int, default=5)
    parser.add_argument("--bench-timeout", type=float, default=120.0)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.soak_iterations <= 0:
        raise VerificationSuiteError("--soak-iterations must be positive")
    if args.bench_clients <= 0:
        raise VerificationSuiteError("--bench-clients must be positive")
    if args.bench_duration <= 0:
        raise VerificationSuiteError("--bench-duration must be positive")
    if not args.build_dir.is_absolute():
        args.build_dir = ROOT / args.build_dir
    return args


def main(argv: list[str]) -> int:
    started_at = time.monotonic()
    try:
        args = parse_args(argv)
        print("verification_suite_start", flush=True)

        print("\nverification_step_start name=forbidden_text_scan", flush=True)
        scan_forbidden_tokens()
        print("verification_step_ok name=forbidden_text_scan", flush=True)

        for name, command, timeout in step_commands(args):
            print(f"\nverification_step_start name={name}", flush=True)
            result = run(command, timeout=timeout, quiet=args.quiet)
            if name.startswith("docker_benchmark_"):
                summary = benchmark_summary_line(result.stdout + result.stderr)
                if not summary:
                    raise VerificationSuiteError(
                        f"{name} did not print benchmark summary"
                    )
                print(
                    f"verification_benchmark_result name={name} {summary}",
                    flush=True,
                )
            print(f"verification_step_ok name={name}", flush=True)

        leaks = docker_container_leaks()
        if leaks:
            raise VerificationSuiteError(
                "LLPS Docker containers remain after verification:\n" + leaks
            )

        elapsed = time.monotonic() - started_at
        print(
            "\nOK: LLPS verification suite passed; "
            f"docker={'0' if args.skip_docker else '1'} "
            f"bench={'1' if (args.with_bench and not args.skip_docker) else '0'} "
            f"elapsed_sec={elapsed:.2f}",
            flush=True,
        )
        return 0
    except (OSError, VerificationSuiteError) as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
