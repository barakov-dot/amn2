from __future__ import annotations

import importlib.util
import re
import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
RUNTIME_LOCK = ROOT / "requirements" / "phase15-runtime-py312.lock"
TEST_LOCK = ROOT / "requirements" / "phase15-test-py312.lock"
GENERATOR = ROOT / "scripts" / "phase15_dependency_lock.py"
INDEX_URL = "https://pypi.org/simple"
GENERATION_COMMAND = (
    "py -3.12 scripts/phase15_dependency_lock.py "
    "--runtime requirements/phase15-runtime-py312.lock "
    "--test requirements/phase15-test-py312.lock"
)
SHA256_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)")


def _load_generator():
    spec = importlib.util.spec_from_file_location("phase15_dependency_lock", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _valid_lock_bytes(generator, kind: str) -> bytes:
    return generator.render_lock(
        [generator.ResolvedPackage("demo", "1.0", ("a" * 64,))],
        kind,
    )


def _logical_requirements(text: str) -> list[str]:
    logical: list[str] = []
    current: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        current.append(line.removesuffix("\\").strip())
        if not line.endswith("\\"):
            logical.append(" ".join(current))
            current = []
    assert not current, "lock ends with an incomplete continued requirement"
    return logical


def _assert_lock_contract(path: Path) -> None:
    raw = path.read_bytes()
    assert raw.decode("utf-8").encode("utf-8") == raw
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
    assert raw.endswith(b"\n")

    text = raw.decode("utf-8")
    assert "# Python: 3.12" in text
    assert "# Platform policy:" in text
    assert f"# Index: {INDEX_URL}" in text
    assert f"# Generation command: {GENERATION_COMMAND}" in text

    requirements = _logical_requirements(text)
    assert requirements
    names: list[str] = []
    for requirement in requirements:
        first_token = requirement.split()[0]
        assert "==" in first_token, f"requirement is not exactly pinned: {first_token}"
        assert not any(marker in first_token for marker in (">", "<", "~=", "!=", "@"))
        assert "http://" not in requirement and "https://" not in requirement
        hashes = SHA256_RE.findall(requirement)
        assert hashes, f"requirement has no sha256 hash: {first_token}"
        assert len(hashes) == len(set(hashes)), f"duplicate hashes for {first_token}"
        names.append(re.split(r"\[|==", first_token, maxsplit=1)[0].lower().replace("_", "-"))
    assert names == sorted(names), "requirements must have deterministic name ordering"
    assert len(names) == len(set(names)), "each distribution must appear exactly once"


def test_project_targets_only_python_312_and_httpx2() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]

    assert project["requires-python"] == ">=3.12,<3.13"
    dev = project["optional-dependencies"]["dev"]
    assert "httpx2==2.10.0" in dev
    direct_names = {
        re.split(r"[<>=!~\[]", requirement, maxsplit=1)[0].lower().replace("_", "-")
        for requirement in dev
    }
    assert "httpx" not in direct_names


@pytest.mark.parametrize("path", [RUNTIME_LOCK, TEST_LOCK])
def test_lock_is_exact_hashed_deterministic_utf8_lf(path: Path) -> None:
    _assert_lock_contract(path)


def test_test_lock_contains_runtime_and_exact_httpx2() -> None:
    runtime_requirements = set(_logical_requirements(RUNTIME_LOCK.read_text(encoding="utf-8")))
    test_requirements = set(_logical_requirements(TEST_LOCK.read_text(encoding="utf-8")))

    assert runtime_requirements < test_requirements
    assert any(requirement.startswith("httpx2==2.10.0 ") for requirement in test_requirements)
    assert not any(requirement.startswith("httpx==") for requirement in test_requirements)


def test_renderer_is_deterministic_utf8_lf() -> None:
    generator = _load_generator()
    packages = [
        generator.ResolvedPackage("Zulu_Package", "2.0.0", ("b" * 64, "a" * 64)),
        generator.ResolvedPackage("alpha-package", "1.0.0", ("d" * 64, "c" * 64)),
    ]

    first = generator.render_lock(packages, "test")
    second = generator.render_lock(list(reversed(packages)), "test")

    assert first == second
    assert isinstance(first, bytes)
    assert first.decode("utf-8").encode("utf-8") == first
    assert b"\r" not in first
    assert first.endswith(b"\n")
    assert first.index(b"alpha-package==1.0.0") < first.index(b"zulu-package==2.0.0")
    assert first.index(("a" * 64).encode()) < first.index(("b" * 64).encode())


def test_generator_rejects_python_other_than_312() -> None:
    generator = _load_generator()

    generator.ensure_python_312((3, 12))
    for version in ((3, 11), (3, 13), (3, 14)):
        with pytest.raises(RuntimeError, match="Python 3\\.12"):
            generator.ensure_python_312(version)


@pytest.mark.parametrize(
    ("implementation", "system", "machine"),
    [
        ("PyPy", "Windows", "AMD64"),
        ("CPython", "Linux", "AMD64"),
        ("CPython", "Windows", "ARM64"),
        ("CPython", "Windows", "x86"),
    ],
)
def test_generator_rejects_non_cpython_windows_amd64_targets(
    implementation: str,
    system: str,
    machine: str,
) -> None:
    generator = _load_generator()

    generator.ensure_python_312(
        (3, 12),
        implementation="CPython",
        system="Windows",
        machine="AMD64",
    )
    with pytest.raises(RuntimeError, match="CPython 3\\.12 on Windows AMD64"):
        generator.ensure_python_312(
            (3, 12),
            implementation=implementation,
            system=system,
            machine=machine,
        )


@pytest.mark.parametrize(
    "invalid_lock",
    [
        "demo>=1.0 --hash=sha256:" + "a" * 64 + "\n",
        "demo==1.0\n",
        "demo @ https://example.invalid/demo.whl --hash=sha256:" + "a" * 64 + "\n",
        "demo==1.0 --hash=sha256:not-a-hash\n",
    ],
)
def test_lock_validator_rejects_floating_urls_and_unhashed_requirements(
    invalid_lock: str,
) -> None:
    generator = _load_generator()

    with pytest.raises(ValueError):
        generator.validate_lock_text(invalid_lock)


@pytest.mark.parametrize(
    "unsafe_requirement",
    [
        "demo @ https://example.invalid/demo.whl",
        "https://example.invalid/demo.whl",
        "file:///tmp/demo.whl",
        "../demo",
        ".\\demo.whl",
        "C:\\tmp\\demo.whl",
        "demo>=1; python_version >= '3.12'",
    ],
)
def test_resolver_rejects_unsafe_requirements_before_environment_or_pip(
    monkeypatch: pytest.MonkeyPatch,
    unsafe_requirement: str,
) -> None:
    generator = _load_generator()
    boundary_calls: list[str] = []

    def forbidden_boundary(*args, **kwargs):
        boundary_calls.append("called")
        raise AssertionError("resolver boundary must not run")

    monkeypatch.setattr(generator.venv.EnvBuilder, "create", forbidden_boundary)
    monkeypatch.setattr(generator.subprocess, "run", forbidden_boundary)

    with pytest.raises(ValueError, match="unsafe requirement"):
        generator.resolve([unsafe_requirement])
    assert boundary_calls == []


def test_source_requirement_validator_accepts_project_constraint_shape() -> None:
    generator = _load_generator()

    generator.validate_source_requirements(
        ["fastapi>=0.115,<1", "qrcode[pil]>=7,<9", "httpx2==2.10.0"]
    )


@pytest.mark.parametrize(
    "artifact_url",
    [
        "http://files.pythonhosted.org/packages/demo.whl",
        "https://user@files.pythonhosted.org/packages/demo.whl",
        "https://files.pythonhosted.org:444/packages/demo.whl",
        "https://files.pythonhosted.org.example.com/packages/demo.whl",
        "https://evil-files.pythonhosted.org/packages/demo.whl",
    ],
)
def test_artifact_origin_requires_exact_pypi_https_origin(artifact_url: str) -> None:
    generator = _load_generator()

    with pytest.raises(RuntimeError, match="outside the approved PyPI artifact origin"):
        generator.validate_artifact_url(artifact_url)


def test_artifact_origin_accepts_exact_pypi_https_origin() -> None:
    generator = _load_generator()

    generator.validate_artifact_url(
        "https://files.pythonhosted.org/packages/aa/bb/demo-1.0-py3-none-any.whl"
    )


def test_lock_destinations_must_be_distinct(tmp_path: Path) -> None:
    generator = _load_generator()
    destination = tmp_path / "phase15.lock"

    with pytest.raises(ValueError, match="distinct"):
        generator.publish_lock_pair(
            destination,
            destination,
            _valid_lock_bytes(generator, "runtime"),
            _valid_lock_bytes(generator, "test"),
        )
    assert not destination.exists()


def test_main_rejects_same_destination_before_resolver(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    generator = _load_generator()
    destination = tmp_path / "phase15.lock"

    def forbidden_resolve(requirements):
        raise AssertionError("resolver must not run for identical destinations")

    monkeypatch.setattr(generator, "resolve", forbidden_resolve)

    with pytest.raises(ValueError, match="distinct"):
        generator.main(
            ["--runtime", str(destination), "--test", str(destination)]
        )
    assert not destination.exists()


@pytest.mark.parametrize("preexisting", [False, True])
def test_pair_publication_rolls_back_if_second_replace_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    preexisting: bool,
) -> None:
    generator = _load_generator()
    runtime = tmp_path / "runtime.lock"
    test = tmp_path / "test.lock"
    if preexisting:
        runtime.write_bytes(b"old-runtime\n")
        test.write_bytes(b"old-test\n")
    expected_runtime = runtime.read_bytes() if runtime.exists() else None
    expected_test = test.read_bytes() if test.exists() else None
    real_replace = generator.os.replace
    replace_calls = 0

    def fail_second_replace(source, destination):
        nonlocal replace_calls
        replace_calls += 1
        if replace_calls == 2:
            raise OSError("injected second replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(generator.os, "replace", fail_second_replace)

    with pytest.raises(OSError, match="injected second replace failure"):
        generator.publish_lock_pair(
            runtime,
            test,
            _valid_lock_bytes(generator, "runtime"),
            _valid_lock_bytes(generator, "test"),
        )
    assert (runtime.read_bytes() if runtime.exists() else None) == expected_runtime
    assert (test.read_bytes() if test.exists() else None) == expected_test


def test_main_resolves_and_renders_both_locks_before_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    generator = _load_generator()
    runtime = tmp_path / "runtime.lock"
    test = tmp_path / "test.lock"
    runtime.write_bytes(b"old-runtime\n")
    test.write_bytes(b"old-test\n")
    package = generator.ResolvedPackage("demo", "1.0", ("a" * 64,))
    resolve_calls = 0

    def fail_second_resolve(requirements):
        nonlocal resolve_calls
        resolve_calls += 1
        if resolve_calls == 2:
            raise RuntimeError("injected test-lock resolution failure")
        return [package]

    monkeypatch.setattr(generator, "resolve", fail_second_resolve)

    with pytest.raises(RuntimeError, match="injected test-lock resolution failure"):
        generator.main(["--runtime", str(runtime), "--test", str(test)])
    assert runtime.read_bytes() == b"old-runtime\n"
    assert test.read_bytes() == b"old-test\n"


def test_resolver_environment_removes_python_proxy_and_custom_cert_influence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator = _load_generator()
    unsafe_names = [
        "PYTHONPATH",
        "PYTHONHOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "PIP_EXTRA_INDEX_URL",
        "PIP_CERT",
    ]
    for name in unsafe_names:
        monkeypatch.setenv(name, "untrusted")
    monkeypatch.setenv("PHASE15_SAFE_MARKER", "preserved")

    environment = generator._resolver_environment()

    assert environment["PHASE15_SAFE_MARKER"] == "preserved"
    assert environment["PIP_INDEX_URL"] == INDEX_URL
    assert environment["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
    assert not ({name.upper() for name in environment} & set(unsafe_names))
