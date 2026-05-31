import re
from typing import Any


PATTERNS = [
    re.compile(
        r"\[Interface\][\s\S]*?\[Peer\][\s\S]*?(?=\n\s*\n|\Z)",
        re.IGNORECASE,
    ),
    re.compile(r"\[Interface\][\s\S]*?(?=\n\s*\n|\Z)", re.IGNORECASE),
    re.compile(r"(/bot)[^/\s]+", re.IGNORECASE),
    re.compile(r"\bvpn://[A-Za-z0-9_-]+={0,2}", re.IGNORECASE),
    re.compile(r"\botpauth://[^\s\"'<>]+", re.IGNORECASE),
    re.compile(
        r"((?:Authorization|Proxy-Authorization)\s*:\s*Bearer\s+)[^\s,}]+",
        re.IGNORECASE,
    ),
    re.compile(
        r"((?:X-Amneziya-Agent-Token|X-Agent-Token)\s*:\s*)[^\s,}]+",
        re.IGNORECASE,
    ),
    re.compile(
        r"([\"']?(?:(?:[A-Z0-9_]*"
        r"(?:PASSWORD_HASH|PASSWORD|TOKEN|SECRET|PRIVATE_KEY|BACKUP_CODE|RECOVERY_CODE|OTP|TOTP|MFA)"
        r"[A-Z0-9_]*)|TELEGRAM_PROXY_URL|SMTP_USERNAME|external_payment_id)"
        r"[\"']?\s*[:=]\s*)(?:"
        r"([\"'])[\s\S]*?\2"
        r"|[^\s,}]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"((?:PrivateKey|PresharedKey)\s*[:=]\s*)[^\s]+",
        re.IGNORECASE,
    ),
]

CONFIG_BLOCK_REDACTION = "[CONFIG REDACTED]"


def redact(value: Any) -> str:
    text = str(value)
    for pattern in PATTERNS:
        text = pattern.sub(_replacement, text)
    return text


def _replacement(match: re.Match[str]) -> str:
    if match.group(0).lstrip().lower().startswith("[interface]"):
        return CONFIG_BLOCK_REDACTION
    prefix = match.group(1) if match.lastindex else ""
    return f"{prefix}[REDACTED]"
