#!/usr/bin/env python3
"""Run repeated Docker synthetic ECC/NUMA readiness profiles."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
READINESS_TOOL = ROOT / "tools" / "run_docker_synthetic_readiness_check.py"
DEFAULT_CONFIG_DIR = ROOT / "logs" / "synthetic-soak"


class SyntheticSoakError(RuntimeError):
    """Raised when a synthetic soak profile fails."""


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
        raise SyntheticSoakError(
            f"timed out after {timeout:.1f}s: {' '.join(command)}"
        ) from exc

    if not quiet:
        if result.stdout:
            print(result.stdout, end="", flush=True)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr, flush=True)

    return result


def profile_matrix() -> tuple[dict[str, str], ...]:
    return (
        {
            "name": "minimal-single-fault",
            "software_ecc_dimms": "3",
            "software_ecc_controllers": "1",
            "software_ecc_scrub_rate": "2048",
            "software_numa_memtotal_kib": "32768",
            "software_numa_local_distance": "10",
            "software_numa_remote_distance": "20",
            "software_fault_injection_mode": "single",
        },
        {
            "name": "split-controller-double-fault",
            "software_ecc_dimms": "6",
            "software_ecc_controllers": "2",
            "software_ecc_scrub_rate": "4096",
            "software_numa_memtotal_kib": "65536",
            "software_numa_local_distance": "12",
            "software_numa_remote_distance": "28",
            "software_fault_injection_mode": "double",
        },
        {
            "name": "wide-full-fault",
            "software_ecc_dimms": "8",
            "software_ecc_controllers": "1",
            "software_ecc_scrub_rate": "8192",
            "software_numa_memtotal_kib": "131072",
            "software_numa_local_distance": "14",
            "software_numa_remote_distance": "32",
            "software_fault_injection_mode": "full",
        },
    )


def readiness_command(
    profile: dict[str, str],
    *,
    args: argparse.Namespace,
    iteration: int,
) -> list[str]:
    config_path = args.config_dir / f"{iteration:03d}-{profile['name']}.yml"
    command = [
        sys.executable,
        str(READINESS_TOOL),
        "--image",
        args.image,
        "--config",
        str(config_path),
        "--evidence-mac",
        "--software-ecc-dimms",
        profile["software_ecc_dimms"],
        "--software-ecc-controllers",
        profile["software_ecc_controllers"],
        "--software-ecc-scrub-rate",
        profile["software_ecc_scrub_rate"],
        "--software-numa-memtotal-kib",
        profile["software_numa_memtotal_kib"],
        "--software-numa-local-distance",
        profile["software_numa_local_distance"],
        "--software-numa-remote-distance",
        profile["software_numa_remote_distance"],
        "--software-fault-injection-mode",
        profile["software_fault_injection_mode"],
        "--timeout",
        f"{args.profile_timeout:.1f}",
        "--startup-wait",
        f"{args.startup_wait:.1f}",
        "--runtime-patrol-wait",
        f"{args.runtime_patrol_wait:.1f}",
    ]
    if args.skip_build or iteration > 1:
        command.append("--skip-build")
    if args.skip_mode_binding_check:
        command.append("--skip-mode-binding-check")
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="llps:local")
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--profile-timeout", type=float, default=120.0)
    parser.add_argument("--startup-wait", type=float, default=2.0)
    parser.add_argument("--runtime-patrol-wait", type=float, default=6.0)
    parser.add_argument("--config-dir", type=pathlib.Path, default=DEFAULT_CONFIG_DIR)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-mode-binding-check", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.iterations <= 0:
        raise SyntheticSoakError("--iterations must be positive")
    if args.profile_timeout <= 0:
        raise SyntheticSoakError("--profile-timeout must be positive")
    if args.runtime_patrol_wait <= 0:
        raise SyntheticSoakError("--runtime-patrol-wait must be positive")

    if not args.config_dir.is_absolute():
        args.config_dir = ROOT / args.config_dir
    return args


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        args.config_dir.mkdir(parents=True, exist_ok=True)
        profiles = profile_matrix()
        total_runs = args.iterations * len(profiles)
        completed = 0
        started_at = time.monotonic()

        print(
            "synthetic_soak_start "
            f"iterations={args.iterations} profiles={len(profiles)} "
            f"total_runs={total_runs} evidence_mac=1",
            flush=True,
        )

        for iteration in range(1, args.iterations + 1):
            for profile in profiles:
                run_name = f"{iteration}/{args.iterations}:{profile['name']}"
                print(
                    "\nsynthetic_soak_profile_start "
                    f"name={run_name} "
                    f"dimms={profile['software_ecc_dimms']} "
                    f"controllers={profile['software_ecc_controllers']} "
                    f"scrub_rate={profile['software_ecc_scrub_rate']} "
                    f"numa_memtotal_kib={profile['software_numa_memtotal_kib']} "
                    f"local_distance={profile['software_numa_local_distance']} "
                    f"remote_distance={profile['software_numa_remote_distance']} "
                    f"fault_mode={profile['software_fault_injection_mode']}",
                    flush=True,
                )
                command = readiness_command(profile, args=args, iteration=completed + 1)
                result = run(
                    command,
                    timeout=args.profile_timeout,
                    quiet=args.quiet,
                )
                if result.returncode != 0:
                    raise SyntheticSoakError(
                        f"profile {run_name} failed with exit code "
                        f"{result.returncode}\n{result.stdout}{result.stderr}"
                    )
                completed += 1
                print(
                    "synthetic_soak_profile_ok "
                    f"name={run_name} completed={completed}/{total_runs}",
                    flush=True,
                )

        elapsed = time.monotonic() - started_at
        print(
            "\nOK: Docker synthetic soak passed; "
            f"runs={completed} iterations={args.iterations} "
            f"profiles={len(profiles)} elapsed_sec={elapsed:.2f} "
            f"config_dir={args.config_dir}",
            flush=True,
        )
        return 0
    except (OSError, SyntheticSoakError) as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
