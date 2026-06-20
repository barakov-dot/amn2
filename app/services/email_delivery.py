from __future__ import annotations

from collections.abc import Callable
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import smtplib
import ssl

from app.bot.delivery import ConfigDeliveryPackage


EmailSender = Callable[[str, bytes], None]


class EmailDeliveryService:
    def __init__(
        self,
        *,
        sender: EmailSender,
        from_address: str,
        base_url: str,
        attach_config: bool,
    ) -> None:
        self._sender = sender
        self._from_address = from_address
        self._base_url = base_url.rstrip("/")
        self._attach_config = attach_config

    def send_config_email(
        self,
        *,
        to_address: str,
        user_id: int,
        device_id: int,
        delivery: ConfigDeliveryPackage,
    ) -> dict[str, str]:
        message = self._base_message(
            to_address=to_address,
            subject=f"VPN config for device #{device_id}",
        )
        message.set_content(
            "\n".join(
                [
                    "Your VPN config is ready.",
                    "",
                    "Open this import link from a VPN app:",
                    delivery.vpn_import_link,
                    "",
                    "You can also import the attached .conf file if your app supports it.",
                    "",
                    "Setup notes:",
                    delivery.message_text,
                ]
            )
        )
        if self._attach_config:
            message.add_attachment(
                delivery.config_bytes,
                maintype="text",
                subtype="plain",
                filename=delivery.config_filename,
            )
        self._send(to_address, message)
        return {"channel": "email", "status": "sent", "purpose": "config_delivery"}

    def send_verification_email(
        self,
        *,
        to_address: str,
        user_id: int,
        token: str,
    ) -> dict[str, str]:
        link = f"{self._base_url}/email/verify"
        message = self._base_message(
            to_address=to_address,
            subject="Verify your VPN email",
        )
        message.set_content(
            "\n".join(
                [
                    "Confirm this email address for VPN config delivery.",
                    "",
                    "Open this page:",
                    link,
                    "",
                    "One-time verification code:",
                    token,
                    "",
                    "If you did not request this, ignore this email.",
                ]
            )
        )
        self._send(to_address, message)
        return {"channel": "email", "status": "sent", "purpose": "verify_email"}

    def send_recovery_start_email(
        self,
        *,
        to_address: str,
        user_id: int,
        device_id: int,
        token: str,
    ) -> dict[str, str]:
        link = f"{self._base_url}/email/recover"
        message = self._base_message(
            to_address=to_address,
            subject=f"Recover VPN config for device #{device_id}",
        )
        message.set_content(
            "\n".join(
                [
                    "Use this page and one-time code to send your VPN config to this email address.",
                    "",
                    "Open this page:",
                    link,
                    "",
                    "One-time recovery code:",
                    token,
                    "",
                    "If you did not request this, ignore this email.",
                ]
            )
        )
        self._send(to_address, message)
        return {"channel": "email", "status": "sent", "purpose": "recover_config"}

    def _base_message(self, *, to_address: str, subject: str) -> EmailMessage:
        message = EmailMessage()
        message["From"] = self._from_address
        message["To"] = to_address
        message["Subject"] = subject
        return message

    def _send(self, to_address: str, message: EmailMessage) -> None:
        self._sender(to_address, message.as_bytes(policy=policy.SMTP))


def build_smtp_sender(
    *,
    host: str,
    port: int,
    username: str = "",
    password: str = "",
    use_tls: bool = True,
    smtp_factory: Callable[[str, int], object] | None = None,
) -> EmailSender:
    factory = smtp_factory or smtplib.SMTP

    def send(to_address: str, message_bytes: bytes) -> None:
        from_address = _message_from_address(message_bytes)
        with factory(host, port) as smtp:
            if use_tls:
                smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password)
            smtp.sendmail(from_address, to_address, message_bytes)

    return send


def _message_from_address(message_bytes: bytes) -> str:
    message = BytesParser(policy=policy.default).parsebytes(message_bytes)
    return str(message["From"] or "")
