#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"


def run_entrypoint(env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="llps-entrypoint-test-") as tmp:
        tmp_path = pathlib.Path(tmp)
        opt_llps = tmp_path / "opt" / "llps"
        opt_llps.mkdir(parents=True)
        stub = opt_llps / "llps"
        stub.write_text(
            "#!/bin/sh\n"
            "printf 'stub argv:'\n"
            "for arg in \"$@\"; do printf ' [%s]' \"$arg\"; done\n"
            "printf '\\n'\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        test_entrypoint = tmp_path / "entrypoint.sh"
        test_entrypoint.write_text(
            ENTRYPOINT.read_text(encoding="utf-8").replace(
                'exec /opt/llps/llps -c "$CONFIG_PATH" "$@"',
                'exec "$LLPS_TEST_LLPS_BIN" -c "$CONFIG_PATH" "$@"',
            ),
            encoding="utf-8",
        )

        env = dict(os.environ)
        env.update(env_overrides)
        env["LLPS_TEST_LLPS_BIN"] = str(stub)
        return subprocess.run(
            ["sh", str(test_entrypoint)],
            cwd=tmp_path,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10.0,
        )


def test_rejects_multiline_generated_config_value() -> None:
    result = run_entrypoint(
        {
            "LLPS_TARGET_HOST": "chat-target\nrequire_readiness: 1",
        }
    )

    assert result.returncode == 64, result
    assert "LLPS_TARGET_HOST must be a single-line value" in result.stderr
    assert "stub argv:" not in result.stdout


def test_allows_safe_single_line_generated_config_values() -> None:
    result = run_entrypoint(
        {
            "LLPS_TARGET_HOST": "chat-target",
            "LLPS_SOFTWARE_ECC_ENABLED": "1",
            "LLPS_SOFTWARE_ECC_CONTROLLER_COUNT": "2",
            "LLPS_SOFTWARE_ECC_DIMM_COUNT": "8",
            "LLPS_SOFTWARE_ECC_SCRUB_RATE": "4096",
            "LLPS_SOFTWARE_ECC_CONTROLLER_CORRECTED_ERROR_COUNT": "0",
            "LLPS_SOFTWARE_ECC_CONTROLLER_UNCORRECTED_ERROR_COUNT": "0",
            "LLPS_SOFTWARE_ECC_DIMM_CORRECTED_ERROR_COUNT": "0",
            "LLPS_SOFTWARE_ECC_DIMM_UNCORRECTED_ERROR_COUNT": "0",
        }
    )

    assert result.returncode == 0, result
    assert "stub argv: [-c] [/tmp/llps.yml]" in result.stdout
    config_path = pathlib.Path("/tmp/llps.yml")
    config_text = config_path.read_text(encoding="utf-8")
    assert "target_host: chat-target\n" in config_text
    assert "software_ecc_controller_count: 2\n" in config_text
    assert "software_ecc_dimm_count: 8\n" in config_text
    assert "software_ecc_scrub_rate: 4096\n" in config_text
    config_path.unlink(missing_ok=True)


def main() -> int:
    test_rejects_multiline_generated_config_value()
    test_allows_safe_single_line_generated_config_values()
    print("test_docker_entrypoint_policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
