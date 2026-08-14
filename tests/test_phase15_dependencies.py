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
