#!/usr/bin/env python3

from __future__ import annotations

import argparse
import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_soak_module():
    module_path = ROOT / "tools" / "run_docker_synthetic_soak.py"
    spec = importlib.util.spec_from_file_location("run_docker_synthetic_soak", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("failed to load run_docker_synthetic_soak.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    soak = load_soak_module()
    profiles = soak.profile_matrix()
    names = {profile["name"] for profile in profiles}
    modes = {profile["software_fault_injection_mode"] for profile in profiles}

    assert len(profiles) == 3
    assert names == {
        "minimal-single-fault",
        "split-controller-double-fault",
        "wide-full-fault",
    }
    assert modes == {"single", "double", "full"}

    for profile in profiles:
        assert int(profile["software_ecc_dimms"]) >= 3
        assert int(profile["software_ecc_controllers"]) >= 1
        assert int(profile["software_ecc_scrub_rate"]) > 0
        assert int(profile["software_numa_memtotal_kib"]) > 0
        assert int(profile["software_numa_remote_distance"]) > int(
            profile["software_numa_local_distance"]
        )

    args = argparse.Namespace(
        image="llps:test",
        config_dir=ROOT / "logs" / "synthetic-soak-test",
        profile_timeout=10.0,
        startup_wait=1.0,
        runtime_patrol_wait=2.0,
        skip_build=True,
        skip_mode_binding_check=True,
    )
    command = soak.readiness_command(profiles[0], args=args, iteration=1)
    assert str(soak.READINESS_TOOL) in command
    assert "--evidence-mac" in command
    assert "--skip-build" in command
    assert "--skip-mode-binding-check" in command
    assert "--software-fault-injection-mode" in command
    assert profiles[0]["software_fault_injection_mode"] in command

    print("test_run_docker_synthetic_soak passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
