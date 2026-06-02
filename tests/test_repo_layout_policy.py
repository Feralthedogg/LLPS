#!/usr/bin/env python3
from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]

SCANNED_PATHS = (
    "README.md",
    "CMakeLists.txt",
    "Dockerfile",
    "config.yml",
    "include",
    "src",
    "tests",
    "tools",
    "docker",
)

SKIPPED_DIRS = {
    ".git",
    "__pycache__",
    "build",
    "build-test",
    "build-debug",
    "cmake-build-debug",
    "LLAM",
}

TEXT_SUFFIXES = {
    "",
    ".c",
    ".h",
    ".cmake",
    ".md",
    ".py",
    ".sh",
    ".txt",
    ".yml",
    ".yaml",
    ".dockerfile",
}

FORBIDDEN_HEADER_MARKERS = (
    "SPDX-" + "Lic" + "ense-Identifier",
    "Copy" + "right",
    "Lic" + "ensed under",
    "@copy" + "right",
)

PRODUCTION_ENV_KEYS = (
    "LLPS_SOFTWARE_ECC_ENABLED",
    "LLPS_SOFTWARE_ECC_CONTROLLER_COUNT",
    "LLPS_SOFTWARE_ECC_DIMM_COUNT",
    "LLPS_SOFTWARE_ECC_SCRUB_RATE",
    "LLPS_SOFTWARE_ECC_CONTROLLER_CORRECTED_ERROR_COUNT",
    "LLPS_SOFTWARE_ECC_CONTROLLER_UNCORRECTED_ERROR_COUNT",
    "LLPS_SOFTWARE_ECC_DIMM_CORRECTED_ERROR_COUNT",
    "LLPS_SOFTWARE_ECC_DIMM_UNCORRECTED_ERROR_COUNT",
    "LLPS_SOFTWARE_NUMA_ENABLED",
    "LLPS_SOFTWARE_NUMA_MEMTOTAL_KIB",
    "LLPS_SOFTWARE_NUMA_LOCAL_DISTANCE",
    "LLPS_SOFTWARE_NUMA_REMOTE_DISTANCE",
    "LLPS_SOFTWARE_FAULT_INJECTION_MODE",
)


def relative(path):
    return path.relative_to(REPO_ROOT).as_posix()


def iter_repo_text_files():
    for name in SCANNED_PATHS:
        root = REPO_ROOT / name
        if not root.exists():
            continue
        if root.is_file():
            yield root
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIPPED_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            yield path


def check_no_forbidden_header_markers():
    hits = []
    for path in iter_repo_text_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in FORBIDDEN_HEADER_MARKERS:
            if marker in text:
                hits.append((relative(path), marker))
    assert not hits, "forbidden header metadata found: " + repr(hits)


def check_header_layout():
    public_headers = sorted((REPO_ROOT / "include").rglob("*.h"))
    expected_public = [REPO_ROOT / "include" / "llps" / "llps.h"]
    assert public_headers == expected_public, (
        "only include/llps/llps.h may live under include/: "
        + repr([relative(path) for path in public_headers])
    )

    src_headers = sorted((REPO_ROOT / "src").rglob("*.h"))
    misplaced = [
        relative(path)
        for path in src_headers
        if not relative(path).startswith("src/internal/")
    ]
    assert not misplaced, "private headers must live under src/internal/: " + repr(misplaced)


def check_cmake_header_export_policy():
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "target_include_directories(llps PRIVATE ${LLPS_PRIVATE_INCLUDE_DIRS})" in cmake
    assert "target_include_directories(llps PUBLIC" not in cmake
    assert "PUBLIC_HEADER" not in cmake
    assert "install(" not in cmake


def check_docker_entrypoint_exposes_production_env_synthetic_evidence_keys():
    example = (REPO_ROOT / "docker" / "production.env.example").read_text(
        encoding="utf-8"
    )
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text(
        encoding="utf-8"
    )

    missing_in_example = [
        key for key in PRODUCTION_ENV_KEYS if f"{key}=" not in example
    ]
    assert not missing_in_example, (
        "production env example is missing synthetic evidence keys: "
        + repr(missing_in_example)
    )

    missing_in_entrypoint = [
        key for key in PRODUCTION_ENV_KEYS if key not in entrypoint
    ]
    assert not missing_in_entrypoint, (
        "entrypoint does not expose synthetic evidence keys: "
        + repr(missing_in_entrypoint)
    )


def check_docker_entrypoint_policy():
    entrypoint_path = REPO_ROOT / "docker" / "entrypoint.sh"
    entrypoint = entrypoint_path.read_text(encoding="utf-8")

    subprocess.run(
        ["sh", "-n", str(entrypoint_path)],
        cwd=REPO_ROOT,
        check=True,
    )
    assert "llps_reject_multiline_env" in entrypoint
    assert "must be a single-line value" in entrypoint
    for key in PRODUCTION_ENV_KEYS:
        assert key in entrypoint, f"entrypoint does not validate {key}"
    for key in ("LLPS_TARGET_HOST", "LLPS_IP_AUDIT_PATH", "LLPS_CONFIG"):
        assert key in entrypoint, f"entrypoint does not validate {key}"


def main():
    check_no_forbidden_header_markers()
    check_header_layout()
    check_cmake_header_export_policy()
    check_docker_entrypoint_exposes_production_env_synthetic_evidence_keys()
    check_docker_entrypoint_policy()
    print("repo layout policy ok")


if __name__ == "__main__":
    main()
