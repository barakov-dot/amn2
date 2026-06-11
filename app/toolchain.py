from __future__ import annotations

import sys
from collections.abc import Sequence


SUPPORTED_PYTHON_MAJOR_MINOR = (3, 12)


def format_supported_python() -> str:
    major, minor = SUPPORTED_PYTHON_MAJOR_MINOR
    return f"CPython {major}.{minor}.x"


def _format_version(version_info: Sequence[object]) -> str:
    parts = [str(part) for part in version_info[:3]]
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts)


def check_python_version(version_info: Sequence[object] = sys.version_info) -> list[str]:
    major = int(version_info[0])
    minor = int(version_info[1])
    if (major, minor) == SUPPORTED_PYTHON_MAJOR_MINOR:
        return []

    return [
        "AMN2 supports "
        f"{format_supported_python()} for this gate; got {_format_version(version_info)}."
    ]


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args in ([], ["check"]):
        errors = check_python_version()
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1

        print(f"AMN2 toolchain ok: {format_supported_python()}.")
        return 0

    if args in (["-h"], ["--help"], ["help"]):
        print("Usage: python -m app.toolchain check")
        print(f"Supported runtime: {format_supported_python()}")
        return 0

    print("Unknown command. Usage: python -m app.toolchain check", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
