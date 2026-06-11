from __future__ import annotations

import tomllib
from pathlib import Path

from app.toolchain import (
    SUPPORTED_PYTHON_MAJOR_MINOR,
    check_python_version,
    format_supported_python,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_pins_supported_python_minor():
    config = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert config["project"]["requires-python"] == ">=3.12,<3.13"


def test_toolchain_contract_accepts_only_python_3_12_minor():
    assert SUPPORTED_PYTHON_MAJOR_MINOR == (3, 12)
    assert check_python_version((3, 12, 13)) == []

    errors = check_python_version((3, 14, 0))

    assert errors == [
        "AMN2 supports CPython 3.12.x for this gate; got 3.14.0."
    ]


def test_toolchain_contract_has_human_readable_supported_runtime():
    assert format_supported_python() == "CPython 3.12.x"


def test_runtime_toolchain_docs_include_reproducible_local_commands():
    text = (PROJECT_ROOT / "docs" / "RUNTIME_TOOLCHAIN.ru.md").read_text(
        encoding="utf-8"
    )

    assert "CPython 3.12.x" in text
    assert "Python 3.14" in text
    assert "py -3.12 -m venv .venv" in text
    assert '.venv\\Scripts\\python.exe -m pip install -e ".[dev]"' in text
    assert ".venv\\Scripts\\python.exe -m pytest tests -v" in text
    assert "не использовать `.venv` из соседнего worktree" in text
    assert "python -m app.toolchain check" in text
