#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_bench_module():
    module_path = ROOT / "tools" / "run_docker_bench.py"
    spec = importlib.util.spec_from_file_location("run_docker_bench", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("failed to load run_docker_bench.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    bench = load_bench_module()
    log_text = "\n".join(
        [
            "llps-bench-1 | unrelated log",
            "bench-target-1 | native_sink port=25566 duration=10.000 "
            "accepted=1 closed=0 errors=0 bytes=1024 active_mib_per_sec=1.00",
            "bench-target-1 | native_sink port=25566 duration=11.000 "
            "accepted=2 closed=1 errors=0 bytes=2048 active_mib_per_sec=2.00",
        ]
    )

    summary = bench.find_summary_line(log_text, "native_sink ")
    assert summary.startswith("native_sink ")
    assert "accepted=2" in summary
    assert "bytes=2048" in summary

    fields = bench.parse_native_summary(summary)
    assert fields["port"] == "25566"
    assert fields["active_mib_per_sec"] == "2.00"
    assert bench.parse_int_field(fields, "accepted", "native_sink") == 2
    assert bench.parse_int_field(fields, "bytes", "native_sink") == 2048

    try:
        bench.parse_int_field({"bytes": "not-an-int"}, "bytes", "native_sink")
    except bench.BenchError as exc:
        assert "native_sink field bytes is not an integer" in str(exc)
    else:
        raise AssertionError("malformed integer field was accepted")

    assert bench.find_summary_line(log_text, "missing_summary ") == ""
    print("test_run_docker_bench_parser passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
