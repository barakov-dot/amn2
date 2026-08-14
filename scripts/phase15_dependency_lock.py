from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import venv
from pathlib import Path
from typing import NamedTuple, Sequence
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INDEX_URL = "https://pypi.org/simple"
GENERATION_COMMAND = (
    "py -3.12 scripts/phase15_dependency_lock.py "
    "--runtime requirements/phase15-runtime-py312.lock "
    "--test requirements/phase15-test-py312.lock"
)
PLATFORM_POLICY = "CPython 3.12 on Windows AMD64; binary wheels only"
PIN_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?==[^\s<>=!~@]+$"
)
HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")


class ResolvedPackage(NamedTuple):
    name: str
    version: str
    hashes: tuple[str, ...]


def canonicalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def ensure_python_312(version: Sequence[int] = sys.version_info) -> None:
    if tuple(version[:2]) != (3, 12):
        raise RuntimeError(
            "phase15 dependency locks must be generated with Python 3.12; "
            f"received {version[0]}.{version[1]}"
        )


def _logical_requirements(text: str) -> list[str]:
    requirements: list[str] = []
    current: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        current.append(line.removesuffix("\\").strip())
        if not line.endswith("\\"):
            requirements.append(" ".join(current))
            current = []
    if current:
        raise ValueError("lock ends with an incomplete continued requirement")
    return requirements


def validate_lock_text(text: str) -> None:
    if "\r" in text or text.startswith("\ufeff") or not text.endswith("\n"):
        raise ValueError("lock must be BOM-free UTF-8 text with LF newlines")
    requirements = _logical_requirements(text)
    if not requirements:
        raise ValueError("lock contains no requirements")
    seen: set[str] = set()
    for requirement in requirements:
        tokens = requirement.split()
        pin = tokens[0]
        if not PIN_RE.fullmatch(pin):
            raise ValueError(f"requirement is not exactly pinned: {pin}")
        if "http://" in requirement or "https://" in requirement or " @ " in requirement:
            raise ValueError(f"URL requirement is forbidden: {pin}")
        hashes = [HASH_RE.fullmatch(token) for token in tokens[1:]]
        if not hashes or any(match is None for match in hashes):
            raise ValueError(f"requirement lacks an exact sha256 hash: {pin}")
        name = canonicalize_name(re.split(r"\[|==", pin, maxsplit=1)[0])
        if name in seen:
            raise ValueError(f"duplicate distribution: {name}")
        seen.add(name)


def render_lock(packages: Sequence[ResolvedPackage], kind: str) -> bytes:
    lines = [
        "# Generated file; do not edit.",
        f"# Lock set: {kind}",
        "# Python: 3.12",
        f"# Platform policy: {PLATFORM_POLICY}",
        f"# Index: {INDEX_URL}",
        f"# Generation command: {GENERATION_COMMAND}",
        "",
    ]
    ordered = sorted(packages, key=lambda package: canonicalize_name(package.name))
    for package in ordered:
        name = canonicalize_name(package.name)
        hashes = sorted(set(package.hashes))
        if not hashes:
            raise ValueError(f"resolved artifact has no sha256 hash: {name}=={package.version}")
        if any(not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in hashes):
            raise ValueError(f"resolved artifact has an invalid sha256 hash: {name}=={package.version}")
        lines.append(f"{name}=={package.version} \\")
        for index, digest in enumerate(hashes):
            continuation = " \\" if index < len(hashes) - 1 else ""
            lines.append(f"    --hash=sha256:{digest}{continuation}")
        lines.append("")
    output = ("\n".join(lines).rstrip("\n") + "\n").encode("utf-8")
    validate_lock_text(output.decode("utf-8"))
    return output


def _venv_python(directory: Path) -> Path:
    return directory / "Scripts" / "python.exe"


def _resolver_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PIP_")
    }
    environment["PIP_INDEX_URL"] = INDEX_URL
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return environment


def resolve(requirements: Sequence[str]) -> list[ResolvedPackage]:
    with tempfile.TemporaryDirectory(prefix="phase15-lock-") as raw_directory:
        directory = Path(raw_directory)
        venv.EnvBuilder(with_pip=True, clear=True).create(directory)
        report = directory / "report.json"
        command = [
            str(_venv_python(directory)),
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--dry-run",
            "--ignore-installed",
            "--only-binary=:all:",
            "--index-url",
            INDEX_URL,
            "--report",
            str(report),
            *requirements,
        ]
        subprocess.run(
            command,
            cwd=ROOT,
            env=_resolver_environment(),
            check=True,
            text=True,
        )
        payload = json.loads(report.read_text(encoding="utf-8"))

    resolved: list[ResolvedPackage] = []
    for item in payload["install"]:
        metadata = item["metadata"]
        download = item.get("download_info", {})
        artifact_url = download.get("url", "")
        if urlparse(artifact_url).hostname != "files.pythonhosted.org":
            raise RuntimeError(
                f"resolver returned an artifact outside the approved PyPI index: {artifact_url}"
            )
        digest = download.get("archive_info", {}).get("hashes", {}).get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError(
                f"exact artifact hash unavailable for {metadata['name']}=={metadata['version']}"
            )
        resolved.append(
            ResolvedPackage(metadata["name"], metadata["version"], (digest,))
        )
    return resolved


def _project_requirements() -> tuple[list[str], list[str]]:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    runtime = list(project["dependencies"])
    test = [*runtime, *project["optional-dependencies"]["dev"]]
    return runtime, test


def _write_lock(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Phase 15 Python 3.12 locks")
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    args = parser.parse_args(argv)

    ensure_python_312()
    runtime_requirements, test_requirements = _project_requirements()
    _write_lock(args.runtime, render_lock(resolve(runtime_requirements), "runtime"))
    _write_lock(args.test, render_lock(resolve(test_requirements), "test"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
