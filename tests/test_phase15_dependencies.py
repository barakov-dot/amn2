from __future__ import annotations

import importlib.util
import json
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
COMPILED_TARGET_HASHES = {
    "aiohttp==3.14.3": (
        "33a2d7c28d33797a2e99923dffa63f83d908a19b6bf26cfe80fa790aa5e1a75a",
        "543906c127fb1d929b95076db19b83fa2d46751006ff1e23b093aa5ac4d8db42",
    ),
    "cffi==2.1.1": (
        "f53e442b08449d42821fa4a4fba000095af9f62742a500f978a9f557ec44339a",
        "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf",
    ),
    "cryptography==45.0.7": (
        "3808e6b2e5f0b46d981c24d79648e5c25c35e59902ea4391a0dcb3e667bf7443",
        "b6a0e535baec27b528cb07a119f321ac024592388c5681a5ced167ae98e9fff3",
    ),
    "frozenlist==1.8.0": (
        "34187385b08f866104f0c0617404c8eb08165ab1272e884abc89c112e9c00746",
        "494a5952b1c597ba44e0e78113a7266e656b9794eec897b19ead706bd7074383",
    ),
    "markupsafe==3.0.3": (
        "26a5784ded40c9e318cfc2bdb30fe164bdb8665ded9cd64d500a34fb42067b1c",
        "d6dd0be5b5b189d31db7cda48b91d7e0a9795f31430b7f271219ab30f1d3ac9d",
    ),
    "multidict==6.7.1": (
        "fcee94dfbd638784645b066074b338bc9cc155d4b4bffa4adce1615c5a426c19",
        "bfde23ef6ed9db7eaee6c37dcec08524cb43903c60b285b172b6c094711b3961",
    ),
    "pillow==12.3.0": (
        "a2b55dd6b2a4c4b7d87ffa56bdb33fdc5fdb9a462173861a7bc097f17d91cb09",
        "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91",
    ),
    "propcache==0.5.2": (
        "d9ee8826a7d47863a08ac44e1a5f611a462eefc3a194b492da242128bec75b42",
        "6f328175a2cde1f0ff2c4ed8ce968b9dcfb55f3a7153f39e2957ed994da13476",
    ),
    "pydantic-core==2.46.4": (
        "e9c26f834c65f5752f3f06cb08cb86a913ceb7274d0db6e267808a708b46bc89",
        "926c9541b14b12b1681dca8a0b75feb510b06c6341b70a8e500c2fdcff837cce",
    ),
    "pyyaml==6.0.3": (
        "5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b",
        "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",
    ),
    "yarl==1.24.5": (
        "a929d878fec099030c292803b31e5d5540a7b6a31e6a3cc76cb4685fc2a2f51b",
        "f08c7513ecef5aad65687bfdf6bc601ae9fccd04a42904501f8f7141abad9eb9",
    ),
}


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


@pytest.mark.parametrize("path", [RUNTIME_LOCK, TEST_LOCK])
def test_lock_covers_windows_and_linux_compiled_artifacts(path: Path) -> None:
    requirements = _logical_requirements(path.read_text(encoding="utf-8"))
    by_pin = {requirement.split()[0]: requirement for requirement in requirements}

    for pin, expected_hashes in COMPILED_TARGET_HASHES.items():
        assert set(SHA256_RE.findall(by_pin[pin])) == set(expected_hashes)
    assert (
        "# Platform policy: CPython 3.12 on Windows AMD64 and Linux x86_64 "
        "(glibc 2.39); binary wheels only"
    ) in path.read_text(encoding="utf-8")


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
        generator.resolve([unsafe_requirement], generator.WINDOWS_AMD64_TARGET)
    assert boundary_calls == []


def test_resolver_runs_explicit_windows_and_linux_targets_and_merges_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator = _load_generator()
    commands: list[list[str]] = []
    target_hashes = {
        "win_amd64": "a" * 64,
        "manylinux_2_39_x86_64": "b" * 64,
    }

    def fake_create(_builder, directory: Path) -> None:
        (directory / "Scripts").mkdir(parents=True)

    def fake_run(command, **kwargs) -> None:
        commands.append(command)
        platform_name = command[command.index("--platform") + 1]
        report_path = Path(command[command.index("--report") + 1])
        report_path.write_text(
            json.dumps(
                {
                    "install": [
                        {
                            "metadata": {"name": "Demo_Package", "version": "1.0"},
                            "download_info": {
                                "url": (
                                    "https://files.pythonhosted.org/packages/"
                                    f"demo-{platform_name}.whl"
                                ),
                                "archive_info": {
                                    "hashes": {"sha256": target_hashes[platform_name]}
                                },
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(generator.venv.EnvBuilder, "create", fake_create)
    monkeypatch.setattr(generator.subprocess, "run", fake_run)

    resolved = generator.resolve_for_targets(["demo-package==1.0"])

    assert resolved == [
        generator.ResolvedPackage("demo-package", "1.0", ("a" * 64, "b" * 64))
    ]
    assert len(commands) == 2
    for command, platform_name in zip(
        commands,
        ("win_amd64", "manylinux_2_39_x86_64"),
        strict=True,
    ):
        assert command[command.index("--platform") + 1] == platform_name
        assert command[command.index("--implementation") + 1] == "cp"
        assert command[command.index("--python-version") + 1] == "3.12"
        assert command[command.index("--abi") + 1] == "cp312"
        assert "--only-binary=:all:" in command


def test_cross_target_version_disagreement_fails_closed() -> None:
    generator = _load_generator()

    with pytest.raises(RuntimeError, match="different versions"):
        generator.merge_resolved_packages(
            [generator.ResolvedPackage("Demo_Package", "1.0", ("a" * 64,))],
            [generator.ResolvedPackage("demo-package", "2.0", ("b" * 64,))],
        )


@pytest.mark.parametrize(
    ("platform_name", "python_version", "abi"),
    [
        ("win32", "3.12", "cp312"),
        ("manylinux_2_39_aarch64", "3.12", "cp312"),
        ("win_amd64", "3.11", "cp311"),
        ("win_amd64", "3.12", "abi3"),
    ],
)
def test_resolver_rejects_incompatible_target_declarations_before_pip(
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
    python_version: str,
    abi: str,
) -> None:
    generator = _load_generator()
    boundary_calls: list[str] = []

    def forbidden_boundary(*args, **kwargs):
        boundary_calls.append("called")
        raise AssertionError("resolver boundary must not run")

    monkeypatch.setattr(generator.venv.EnvBuilder, "create", forbidden_boundary)
    monkeypatch.setattr(generator.subprocess, "run", forbidden_boundary)
    target = generator.ResolverTarget(
        "unapproved",
        platform_name,
        "cp",
        python_version,
        abi,
    )

    with pytest.raises(RuntimeError, match="approved resolver target"):
        generator.resolve(["demo==1.0"], target)
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

    monkeypatch.setattr(generator, "resolve_for_targets", fail_second_resolve)

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
