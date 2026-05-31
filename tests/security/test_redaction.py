from app.security.redaction import redact


def test_redaction_removes_tokens_keys_and_config_markers():
    unsafe = """
    TELEGRAM_BOT_TOKEN=123:abc
    TELEGRAM_PROXY_URL=socks5://user:password@example.com:1080
    PrivateKey = secret-private
    PresharedKey = secret-psk
    [Interface]
    Address = 10.8.0.2/32
    external_payment_id=pay_123
    """

    safe = redact(unsafe)

    assert "123:abc" not in safe
    assert "user:password@example.com:1080" not in safe
    assert "secret-private" not in safe
    assert "secret-psk" not in safe
    assert "[Interface]" not in safe
    assert "pay_123" not in safe
    assert "[REDACTED" in safe


def test_redaction_handles_realistic_secret_log_formats():
    unsafe = """
    APP_SECRET_KEY = secret-app
    TELEGRAM_PROXY_URL = socks5://proxy-user:proxy-pass@proxy.example:1080
    telegram_bot_token: 123456:ABCdef
    {'TELEGRAM_BOT_TOKEN': '123456:ABCdef'}
    "external_payment_id": "pay_123"
    https://api.telegram.org/bot123456:ABCdef/sendMessage
    external_payment_id = pay_456
    PrivateKey   :   secret-private
    PresharedKey = secret-psk
    [Interface]
    Address = 10.8.0.2/32
    PrivateKey = block-private
    [Peer]
    PublicKey = peer-public
    PresharedKey = block-psk
    AllowedIPs = 0.0.0.0/0
    """

    safe = redact(unsafe)

    for unsafe_value in [
        "secret-app",
        "proxy-user:proxy-pass@proxy.example:1080",
        "123456:ABCdef",
        "pay_123",
        "pay_456",
        "secret-private",
        "secret-psk",
        "[Interface]",
        "10.8.0.2/32",
        "block-private",
        "[Peer]",
        "peer-public",
        "block-psk",
    ]:
        assert unsafe_value not in safe
    assert "[REDACTED" in safe


def test_redaction_removes_web_admin_and_smtp_secret_settings():
    unsafe = """
    VPS_SSH_PASSWORD=vps-password
    CONTROL_PANEL_PASSWORD_HASH=control-hash
    API_PRIVATE_KEY=api-private-key
    CUSTOM_SERVICE_TOKEN=custom-token
    CUSTOM_SERVICE_SECRET=custom-secret
    SMTP_PASSWORD=smtp-secret
    SMTP_USERNAME=smtp-user
    WEB_ADMIN_SESSION_SECRET=session-secret-value
    WEB_ADMIN_PASSWORD_HASH=sha256$hash-value
    {'SMTP_PASSWORD': 'dict-smtp-secret'}
    "WEB_ADMIN_SESSION_SECRET": "json-session-secret"
    """

    safe = redact(unsafe)

    for unsafe_value in [
        "vps-password",
        "control-hash",
        "api-private-key",
        "custom-token",
        "custom-secret",
        "smtp-secret",
        "smtp-user",
        "session-secret-value",
        "sha256$hash-value",
        "dict-smtp-secret",
        "json-session-secret",
    ]:
        assert unsafe_value not in safe
    assert safe.count("[REDACTED]") >= 11


def test_redaction_removes_quoted_secret_values_with_spaces_and_commas():
    unsafe = """
    SMTP_PASSWORD="abc,def ghi"
    WEB_ADMIN_SESSION_SECRET='secret value, with comma'
    {"SMTP_PASSWORD": "json abc,def ghi"}
    {'WEB_ADMIN_SESSION_SECRET': 'dict secret value, with comma'}
    """

    safe = redact(unsafe)

    for unsafe_value in [
        "abc,def ghi",
        "secret value, with comma",
        "json abc,def ghi",
        "dict secret value, with comma",
    ]:
        assert unsafe_value not in safe
    assert safe.count("[REDACTED]") >= 4


def test_redaction_removes_vpn_links_agent_headers_and_bearer_tokens():
    unsafe = """
    Import link: vpn://W0ludGVyZmFjZV0KUHJpdmF0ZUtleSA9IGNsaWVudC1wcml2YXRl
    Authorization: Bearer local-agent-token-value
    Proxy-Authorization: Bearer proxy-token-value
    X-Amneziya-Agent-Token: agent-header-token
    LOCAL_AGENT_TOKEN=agent-env-token
    AGENT_SHARED_SECRET="agent shared secret"
    """

    safe = redact(unsafe)

    for unsafe_value in [
        "vpn://",
        "W0ludGVyZmFjZV0KUHJpdmF0ZUtleSA9IGNsaWVudC1wcml2YXRl",
        "local-agent-token-value",
        "proxy-token-value",
        "agent-header-token",
        "agent-env-token",
        "agent shared secret",
    ]:
        assert unsafe_value not in safe
    assert "[REDACTED]" in safe


def test_redaction_removes_totp_otpauth_and_recovery_codes():
    unsafe = """
    otpauth://totp/Amneziya:root?secret=JBSWY3DPEHPK3PXP&issuer=Amneziya
    TOTP_SECRET=totp-secret-value
    MFA_SECRET='mfa secret value'
    OTP_SECRET="otp secret value"
    BACKUP_CODE=backup-code-value
    RECOVERY_CODE=recovery-code-value
    """

    safe = redact(unsafe)

    for unsafe_value in [
        "otpauth://",
        "JBSWY3DPEHPK3PXP",
        "totp-secret-value",
        "mfa secret value",
        "otp secret value",
        "backup-code-value",
        "recovery-code-value",
    ]:
        assert unsafe_value not in safe
    assert safe.count("[REDACTED]") >= 6
