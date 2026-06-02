#!/usr/bin/env python3
"""Audit LLPS production C sources against a strict Power-of-Ten subset."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


PRODUCTION_ROOTS = ("src", "include")
FUNCTION_LENGTH_LIMIT = 60
SOURCE_SUFFIXES = {".c", ".h"}


@dataclass(frozen=True)
class Finding:
    rule: str
    path: Path
    line: int
    detail: str


def iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirname in PRODUCTION_ROOTS:
        base = root / dirname
        if not base.exists():
            continue
        files.extend(
            sorted(
                path
                for path in base.rglob("*")
                if path.is_file() and path.suffix in SOURCE_SUFFIXES
            )
        )
    return sorted(files)


def strip_line_comment(line: str) -> str:
    index = line.find("//")
    if index >= 0:
        return line[:index]
    return line


def scan_forbidden_flow(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    patterns = (
        ("rule1-goto", re.compile(r"\bgoto\b")),
        ("rule1-setjmp", re.compile(r"\bsetjmp\s*\(")),
        ("rule1-longjmp", re.compile(r"\blongjmp\s*\(")),
    )
    for line_no, line in enumerate(text.splitlines(), 1):
        clean = strip_line_comment(line)
        for rule, pattern in patterns:
            if pattern.search(clean):
                findings.append(Finding(rule, path, line_no, clean.strip()))
    return findings


def scan_function_pointers(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    patterns = (
        re.compile(r"typedef\s+[^;]*\(\s*\*\s*\w+\s*\)"),
        re.compile(r"\(\s*\*\s*\w+\s*\)\s*\("),
    )
    for line_no, line in enumerate(text.splitlines(), 1):
        clean = strip_line_comment(line)
        if any(pattern.search(clean) for pattern in patterns):
            findings.append(
                Finding("rule9-function-pointer", path, line_no, clean.strip())
            )
    return findings


def scan_while_loops(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    while_pattern = re.compile(r"\bwhile\s*\(")
    unbounded_for_pattern = re.compile(r"\bfor\s*\(\s*;\s*;\s*\)")
    do_while_macro = re.compile(r"}\s*while\s*\(\s*(?:0|false)\s*\)")
    for line_no, line in enumerate(text.splitlines(), 1):
        clean = strip_line_comment(line)
        if while_pattern.search(clean) and do_while_macro.search(clean) is None:
            findings.append(Finding("rule2-while-loop", path, line_no, clean.strip()))
        if unbounded_for_pattern.search(clean):
            findings.append(
                Finding("rule2-unbounded-for", path, line_no, clean.strip())
            )
    return findings


def function_name_from_candidate(candidate: str) -> str | None:
    match = re.search(
        r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{\s*$",
        candidate,
        re.DOTALL,
    )
    if match is None:
        return None
    name = match.group(1)
    if name in {"if", "for", "while", "switch"}:
        return None
    return name


def scan_long_functions(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    pending: list[tuple[int, str]] = []
    depth = 0
    function_start = 0
    function_name: str | None = None

    for line_no, line in enumerate(lines, 1):
        if depth == 0:
            pending.append((line_no, line))
            if len(pending) > 8:
                pending.pop(0)
            if "{" in line:
                candidate = "\n".join(item[1] for item in pending)
                name = function_name_from_candidate(candidate)
                if name is not None:
                    function_start = pending[0][0]
                    function_name = name
                pending = []

        depth += line.count("{") - line.count("}")
        if depth == 0 and function_name is not None:
            length = line_no - function_start + 1
            if length > FUNCTION_LENGTH_LIMIT:
                findings.append(
                    Finding(
                        "rule4-function-length",
                        path,
                        function_start,
                        f"{function_name} length={length}",
                    )
                )
            function_start = 0
            function_name = None

    return findings


def run_audit(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(root):
        text = path.read_text(errors="ignore")
        findings.extend(scan_forbidden_flow(path, text))
        findings.extend(scan_function_pointers(path, text))
        findings.extend(scan_while_loops(path, text))
        findings.extend(scan_long_functions(path, text))
    return findings


def print_findings(root: Path, findings: list[Finding], limit: int) -> None:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule] = counts.get(finding.rule, 0) + 1

    for rule in sorted(counts):
        print(f"power10_count rule={rule} count={counts[rule]}")

    for finding in findings[:limit]:
        rel = finding.path.relative_to(root)
        print(
            f"power10_violation rule={finding.rule} "
            f"file={rel}:{finding.line} detail={finding.detail}"
        )

    if len(findings) > limit:
        print(f"power10_violation_truncated remaining={len(findings) - limit}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Print findings but exit successfully.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    findings = run_audit(root)
    print_findings(root, findings, args.limit)
    if findings:
        print(f"power10_status=fail findings={len(findings)}")
        return 0 if args.report_only else 1
    print("power10_status=ok findings=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
