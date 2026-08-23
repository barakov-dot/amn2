from __future__ import annotations

import argparse
import json
import os
import platform
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
ARTIFACT_ORIGIN = "files.pythonhosted.org"
GENERATION_COMMAND = (
    "py -3.12 scripts/phase15_dependency_lock.py "
    "--runtime requirements/phase15-runtime-py312.lock "
    "--test requirements/phase15-test-py312.lock"
)
PLATFORM_POLICY = (
    "CPython 3.12 on Windows AMD64 and Linux x86_64 (glibc 2.39); "
    "binary wheels only"
)
PIN_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?==[^\s<>=!~@]+$"
)
HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
SOURCE_REQUIREMENT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\[[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)*\])?"
    r"(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9][A-Za-z0-9.*+!_-]*"
    r"(?:,(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9][A-Za-z0-9.*+!_-]*)*$"
)
UNSAFE_RESOLVER_ENVIRONMENT = frozenset(
    {
        "ALL_PROXY",
        "CURL_CA_BUNDLE",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "PYTHONHOME",
        "PYTHONPATH",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    }
)


class ResolvedPackage(NamedTuple):
    name: str
    version: str
    hashes: tuple[str, ...]


class ResolverTarget(NamedTuple):
    name: str
    platforms: tuple[str, ...]
    implementation: str
    python_version: str
    abi: str


WINDOWS_AMD64_TARGET = ResolverTarget(
    "windows-amd64", ("win_amd64",), "cp", "3.12", "cp312"
)
LINUX_X86_64_GLIBC_239_TARGET = ResolverTarget(
    "linux-x86-64-glibc-2.39",
    (
        "manylinux_2_39_x86_64",
        "manylinux_2_38_x86_64",
        "manylinux_2_37_x86_64",
        "manylinux_2_36_x86_64",
        "manylinux_2_35_x86_64",
        "manylinux_2_34_x86_64",
        "manylinux_2_33_x86_64",
        "manylinux_2_32_x86_64",
        "manylinux_2_31_x86_64",
        "manylinux_2_30_x86_64",
        "manylinux_2_29_x86_64",
        "manylinux_2_28_x86_64",
        "manylinux_2_27_x86_64",
        "manylinux_2_26_x86_64",
        "manylinux_2_25_x86_64",
        "manylinux_2_24_x86_64",
        "manylinux_2_23_x86_64",
        "manylinux_2_22_x86_64",
        "manylinux_2_21_x86_64",
        "manylinux_2_20_x86_64",
        "manylinux_2_19_x86_64",
        "manylinux_2_18_x86_64",
        "manylinux_2_17_x86_64",
        "manylinux2014_x86_64",
        "manylinux_2_16_x86_64",
        "manylinux_2_15_x86_64",
        "manylinux_2_14_x86_64",
        "manylinux_2_13_x86_64",
        "manylinux_2_12_x86_64",
        "manylinux2010_x86_64",
        "manylinux_2_11_x86_64",
        "manylinux_2_10_x86_64",
        "manylinux_2_9_x86_64",
        "manylinux_2_8_x86_64",
        "manylinux_2_7_x86_64",
        "manylinux_2_6_x86_64",
        "manylinux_2_5_x86_64",
        "manylinux1_x86_64",
    ),
    "cp",
    "3.12",
    "cp312",
)
RESOLVER_TARGETS = (
    WINDOWS_AMD64_TARGET,
    LINUX_X86_64_GLIBC_239_TARGET,
)


def canonicalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def ensure_python_312(
    version: Sequence[int] = sys.version_info,
    *,
    implementation: str | None = None,
    system: str | None = None,
    machine: str | None = None,
) -> None:
    implementation = implementation or platform.python_implementation()
    system = system or platform.system()
    machine = machine or platform.machine()
    if (
        tuple(version[:2]) != (3, 12)
        or implementation != "CPython"
        or system != "Windows"
        or machine.lower() != "amd64"
    ):
        raise RuntimeError(
            "phase15 dependency locks must be generated with CPython 3.12 on "
            "Windows AMD64; received "
            f"{implementation} {version[0]}.{version[1]} on {system} {machine}"
        )


def validate_source_requirements(requirements: Sequence[str]) -> None:
    if not requirements:
        raise ValueError("unsafe requirement set: no requirements supplied")
    for requirement in requirements:
        if not isinstance(requirement, str) or not SOURCE_REQUIREMENT_RE.fullmatch(
            requirement
        ):
            raise ValueError(f"unsafe requirement rejected before resolution: {requirement!r}")


def validate_artifact_url(artifact_url: str) -> None:
    parsed = urlparse(artifact_url)
    try:
        port = parsed.port
    except ValueError as error:
        raise RuntimeError(
            f"resolver returned an artifact outside the approved PyPI artifact origin: {artifact_url}"
        ) from error
    if (
        parsed.scheme != "https"
        or parsed.netloc != ARTIFACT_ORIGIN
        or parsed.hostname != ARTIFACT_ORIGIN
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
    ):
        raise RuntimeError(
            f"resolver returned an artifact outside the approved PyPI artifact origin: {artifact_url}"
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
    ensure_python_312()
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
        and key.upper() not in UNSAFE_RESOLVER_ENVIRONMENT
    }
    environment["PIP_INDEX_URL"] = INDEX_URL
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return environment


def _resolver_target_args(target: ResolverTarget) -> list[str]:
    if target not in RESOLVER_TARGETS:
        raise RuntimeError(f"unapproved resolver target declaration: {target!r}")
    return [
        *(
            item
            for platform_name in target.platforms
            for item in ("--platform", platform_name)
        ),
        "--implementation",
        target.implementation,
        "--python-version",
        target.python_version,
        "--abi",
        target.abi,
    ]


def resolve(
    requirements: Sequence[str],
    target: ResolverTarget,
) -> list[ResolvedPackage]:
    target_args = _resolver_target_args(target)
    ensure_python_312()
    validate_source_requirements(requirements)
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
            *target_args,
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
        validate_artifact_url(artifact_url)
        digest = download.get("archive_info", {}).get("hashes", {}).get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError(
                f"exact artifact hash unavailable for {metadata['name']}=={metadata['version']}"
            )
        resolved.append(
            ResolvedPackage(metadata["name"], metadata["version"], (digest,))
        )
    return resolved


def merge_resolved_packages(
    *target_packages: Sequence[ResolvedPackage],
) -> list[ResolvedPackage]:
    merged: dict[str, tuple[str, set[str]]] = {}
    for packages in target_packages:
        for package in packages:
            name = canonicalize_name(package.name)
            current = merged.get(name)
            if current is None:
                merged[name] = (package.version, set(package.hashes))
                continue
            version, hashes = current
            if package.version != version:
                raise RuntimeError(
                    f"resolver targets selected different versions for {name}: "
                    f"{version} != {package.version}"
                )
            hashes.update(package.hashes)
    return [
        ResolvedPackage(name, version, tuple(sorted(hashes)))
        for name, (version, hashes) in sorted(merged.items())
    ]


def resolve_for_targets(requirements: Sequence[str]) -> list[ResolvedPackage]:
    return merge_resolved_packages(
        *(resolve(requirements, target) for target in RESOLVER_TARGETS)
    )


def _project_requirements() -> tuple[list[str], list[str]]:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    runtime = list(project["dependencies"])
    test = [*runtime, *project["optional-dependencies"]["dev"]]
    return runtime, test


def _normalized_destination(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _ensure_distinct_destinations(runtime: Path, test: Path) -> None:
    if _normalized_destination(runtime) == _normalized_destination(test):
        raise ValueError("runtime and test lock destinations must be distinct")


def _validate_lock_bytes(content: bytes) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("lock must be valid UTF-8") from error
    validate_lock_text(text)


def _stage_bytes(destination: Path, content: bytes) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_path = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    staged = Path(raw_path)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def _restore_destination(destination: Path, original: bytes | None) -> None:
    if original is None:
        destination.unlink(missing_ok=True)
        return
    staged = _stage_bytes(destination, original)
    try:
        os.replace(staged, destination)
    finally:
        staged.unlink(missing_ok=True)


def publish_lock_pair(
    runtime: Path,
    test: Path,
    runtime_content: bytes,
    test_content: bytes,
) -> None:
    _ensure_distinct_destinations(runtime, test)
    _validate_lock_bytes(runtime_content)
    _validate_lock_bytes(test_content)
    original_runtime = runtime.read_bytes() if runtime.exists() else None
    original_test = test.read_bytes() if test.exists() else None
    staged_runtime = _stage_bytes(runtime, runtime_content)
    try:
        staged_test = _stage_bytes(test, test_content)
    except BaseException:
        staged_runtime.unlink(missing_ok=True)
        raise
    try:
        os.replace(staged_runtime, runtime)
        os.replace(staged_test, test)
    except BaseException:
        _restore_destination(runtime, original_runtime)
        _restore_destination(test, original_test)
        raise
    finally:
        staged_runtime.unlink(missing_ok=True)
        staged_test.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Phase 15 Python 3.12 locks")
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    args = parser.parse_args(argv)

    ensure_python_312()
    _ensure_distinct_destinations(args.runtime, args.test)
    runtime_requirements, test_requirements = _project_requirements()
    runtime_packages = resolve_for_targets(runtime_requirements)
    test_packages = resolve_for_targets(test_requirements)
    runtime_content = render_lock(runtime_packages, "runtime")
    test_content = render_lock(test_packages, "test")
    publish_lock_pair(args.runtime, args.test, runtime_content, test_content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
