#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_audit_module():
    module_path = ROOT / "tools" / "run_llps_completion_audit.py"
    spec = importlib.util.spec_from_file_location("run_llps_completion_audit", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("failed to load run_llps_completion_audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    audit = load_audit_module()
    checks = audit.requirement_checks()
    names = [name for name, _evidence in checks]

    assert "linux_and_llam_kept_with_runtime_contract" in names
    assert "software_ecc_numa_dimm_model" in names
    assert "protocol_remote_input_gate_verified" in names
    assert "integrated_verification_and_benchmarking" in names
    assert "verification_temp_paths_process_isolated" in names
    assert "truthful_software_only_hardware_boundary" in names
    assert len(checks) >= 11
    assert audit.public_header_layout_ok()

    print("test_run_llps_completion_audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
