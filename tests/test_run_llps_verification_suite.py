#!/usr/bin/env python3

from __future__ import annotations

import argparse
import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_suite_module():
    module_path = ROOT / "tools" / "run_llps_verification_suite.py"
    spec = importlib.util.spec_from_file_location("run_llps_verification_suite", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("failed to load run_llps_verification_suite.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    suite = load_suite_module()
    args = argparse.Namespace(
        build_dir=ROOT / "build-test",
        local_timeout=10.0,
        docker_timeout=20.0,
        chat_timeout=5.0,
        skip_docker=False,
        soak_iterations=1,
        soak_profile_timeout=30.0,
        runtime_patrol_wait=3.0,
        with_bench=True,
        bench_clients=10,
        bench_duration=1,
        bench_timeout=40.0,
    )
    commands = suite.step_commands(args)
    names = [name for name, _command, _timeout in commands]

    assert names == [
        "completion_audit",
        "cmake_configure",
        "cmake_build",
        "ctest",
        "docker_prod_synthetic_readiness",
        "docker_protocol_gate",
        "docker_synthetic_soak",
        "docker_benchmark_baseline",
        "docker_benchmark_payload_ecc",
    ]

    by_name = {name: command for name, command, _timeout in commands}
    assert "--synthetic-readiness" in by_name["docker_prod_synthetic_readiness"]
    assert "--protocol-gate" in by_name["docker_protocol_gate"]
    assert "--audit-mac" in by_name["docker_protocol_gate"]
    assert "--iterations" in by_name["docker_synthetic_soak"]
    assert "--clients" in by_name["docker_benchmark_baseline"]
    assert "--quiet-llps-logs" in by_name["docker_benchmark_baseline"]
    assert "--payload-ecc" not in by_name["docker_benchmark_baseline"]
    assert "--payload-ecc" in by_name["docker_benchmark_payload_ecc"]
    assert suite.benchmark_summary_line(
        "noise\nOK: Docker LLPS benchmark passed; payload_ecc=0; "
        "backend_active_mib_per_sec=1.23; native_load x; native_sink y\n"
    ).startswith("OK: Docker LLPS benchmark passed; payload_ecc=0;")

    args.skip_docker = True
    args.with_bench = True
    local_only = suite.step_commands(args)
    assert [name for name, _command, _timeout in local_only] == [
        "completion_audit",
        "cmake_configure",
        "cmake_build",
        "ctest",
    ]

    print("test_run_llps_verification_suite passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
