from __future__ import annotations

import os
import secrets
from pathlib import Path


def validate_private_config_artifact_target(output_path: str | Path) -> Path:
    if os.name != "posix":
        raise OSError(
            "Private config artifacts require a POSIX target with enforceable 0600 mode"
        )
    path = Path(output_path)
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite private config artifact: {path}")
    return path


def write_private_config_artifact(output_path: str | Path, config_text: str) -> Path:
    path = validate_private_config_artifact_target(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(config_text)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        temp_path.unlink(missing_ok=True)

    return path
