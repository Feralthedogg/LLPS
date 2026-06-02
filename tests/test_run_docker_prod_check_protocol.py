#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import types
import tempfile
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"


def load_prod_check_module():
    module_path = ROOT / "tools" / "run_docker_prod_check.py"
    sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location("run_docker_prod_check", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("failed to load run_docker_prod_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    prod = load_prod_check_module()
    cases = prod.protocol_invalid_preface_cases(host="mc.example", port=25566)
    names = {name for name, _payload in cases}

    assert names == {
        "bad_packet_id",
        "zero_port",
        "zero_protocol",
        "bad_next_state",
        "overwide_varint",
        "noncanonical_packet_length",
        "noncanonical_packet_id",
        "oversized_address",
    }
    assert len(cases) == 8
    assert all(payload for _name, payload in cases)

    body = prod.protocol_handshake_body(host="mc.example", port=25566)
    canonical = prod.protocol_varint(len(body))
    noncanonical = prod.protocol_noncanonical_varint(len(body))
    assert noncanonical != canonical
    assert noncanonical.endswith(b"\x00")
    assert noncanonical[-2] & 0x80

    packet = prod.protocol_packet(body)
    assert packet.startswith(canonical)

    args = types.SimpleNamespace(
        audit_mac=True,
        audit_key=None,
        synthetic_readiness=True,
        evidence_key=None,
        keep_running=False,
    )
    staged_dir, audit_key, evidence_key = prod.stage_secret_keys(args)
    assert staged_dir is not None
    try:
        secret_dir = pathlib.Path(staged_dir.name)
        assert audit_key is not None
        assert evidence_key is not None
        assert secret_dir.stat().st_mode & 0o777 == 0o755
        assert audit_key.stat().st_mode & 0o777 == 0o444
        assert evidence_key.stat().st_mode & 0o777 == 0o444
    finally:
        staged_dir.cleanup()

    with tempfile.TemporaryDirectory(prefix="llps-log-mount-test-") as tmp:
        writable_dir = pathlib.Path(tmp) / "logs"
        prod.prepare_container_writable_dir(writable_dir)
        assert writable_dir.stat().st_mode & 0o777 == 0o777

    print("test_run_docker_prod_check_protocol passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
