import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aiogram import Bot
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.exceptions import TelegramNetworkError

from app.bot import create_dispatcher
from app.bot.persistent_runtime import (
    PERSISTENT_ALLOWED_UPDATES,
    PERSISTENT_TASKS_CONCURRENCY_LIMIT,
    PersistentBotAdmissionConfig,
    PersistentBotAdmissionError,
    PersistentBotInstanceLock,
    admit_persistent_bot,
    recheck_persistent_bot_state,
)
from app.bot.workflows import BotWorkflow
from app.config import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.security.redaction import redact
from app.server.peer_apply import ServerConfigPeerApplier
from app.server_config.loader import load_server_config, select_server
from app.server_config.models import ServerConfig
from app.services.access import AccessService
from app.services.phase15_bootstrap import build_phase15_awg3_components
from app.systemd_notify import SystemdNotifier
from app.vpn.amneziawg_v2.config import ClientConfigDefaults


async def run() -> None:
    settings = Settings()
    await run_persistent_bot(settings)


async def run_persistent_bot(
    settings: Settings,
    *,
    bot_factory: Callable[..., Any] | None = None,
    workflow_factory: Callable[[Settings], Any] | None = None,
    dispatcher_factory: Callable[..., Any] | None = None,
    admission_checker: Callable[..., Any] = admit_persistent_bot,
    state_checker: Callable[..., Any] = recheck_persistent_bot_state,
    lock_factory: Callable[..., Any] = PersistentBotInstanceLock,
    notifier: SystemdNotifier | None = None,
    receipt_writer: Callable[[str], Any] = print,
) -> None:
    bot_factory = bot_factory or create_bot
    workflow_factory = workflow_factory or create_workflow_from_settings
    dispatcher_factory = dispatcher_factory or create_dispatcher
    active_notifier = notifier or SystemdNotifier.from_environment()
    with lock_factory(settings.telegram_runtime_lock_path):
        try:
            bot = bot_factory(
                telegram_bot_token=settings.telegram_bot_token,
                telegram_proxy_url=settings.telegram_proxy_url,
            )
        except Exception:
            raise PersistentBotAdmissionError(
                "Telegram bot client creation failed"
            ) from None

        polling_task: asyncio.Task[Any] | None = None
        watchdog_task: asyncio.Task[Any] | None = None
        ready_sent = False
        try:
            config = PersistentBotAdmissionConfig(
                expected_bot_username=settings.telegram_expected_bot_username,
                timeout_seconds=settings.telegram_admission_timeout_seconds,
            )
            startup_timeout = asyncio.timeout(
                settings.telegram_admission_timeout_seconds
            )
            try:
                async with startup_timeout:
                    result = await admission_checker(bot, config)
                    workflow = workflow_factory(settings)
                    dispatcher = dispatcher_factory(workflow=workflow)
                    await state_checker(bot, config)
            except PersistentBotAdmissionError:
                if startup_timeout.expired():
                    raise PersistentBotAdmissionError(
                        "Telegram persistent startup timed out"
                    ) from None
                raise
            except TimeoutError:
                raise PersistentBotAdmissionError(
                    "Telegram persistent startup timed out"
                ) from None

            polling_task = asyncio.create_task(
                dispatcher.start_polling(
                    bot,
                    polling_timeout=settings.telegram_polling_timeout_seconds,
                    allowed_updates=list(PERSISTENT_ALLOWED_UPDATES),
                    close_bot_session=False,
                    handle_as_tasks=True,
                    tasks_concurrency_limit=PERSISTENT_TASKS_CONCURRENCY_LIMIT,
                )
            )
            await asyncio.sleep(0)
            if polling_task.done():
                await polling_task
                return

            receipt_writer(result.render())
            active_notifier.ready("Telegram polling admitted")
            ready_sent = True
            if active_notifier.watchdog_interval_seconds() is not None:
                watchdog_task = asyncio.create_task(active_notifier.run_watchdog())
            await _wait_for_polling_and_watchdog(polling_task, watchdog_task)
        except TelegramNetworkError as exc:
            raise RuntimeError(
                telegram_network_error_message(settings.telegram_proxy_url)
            ) from exc
        finally:
            try:
                if ready_sent:
                    active_notifier.stopping("Telegram polling stopped")
            finally:
                await _cancel_task(watchdog_task)
                await _cancel_task(polling_task)
                await _close_bot_session(bot)


async def _wait_for_polling_and_watchdog(
    polling_task: asyncio.Task[Any],
    watchdog_task: asyncio.Task[Any] | None,
) -> None:
    if watchdog_task is None:
        await polling_task
        return

    done, _ = await asyncio.wait(
        {polling_task, watchdog_task},
        return_when=asyncio.FIRST_COMPLETED,
    )
    if watchdog_task in done:
        await watchdog_task
    if polling_task in done:
        await polling_task


async def _cancel_task(task: asyncio.Task[Any] | None) -> None:
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def _close_bot_session(bot: Any) -> None:
    close = getattr(getattr(bot, "session", None), "close", None)
    if close is None:
        return
    try:
        await close()
    except Exception:
        raise PersistentBotAdmissionError(
            "Telegram bot session close failed"
        ) from None


def create_bot(*, telegram_bot_token: str, telegram_proxy_url: str = "") -> Bot:
    if telegram_proxy_url.strip():
        return Bot(
            token=telegram_bot_token,
            session=AiohttpSession(proxy=telegram_proxy_url.strip()),
        )
    return Bot(token=telegram_bot_token)


async def check_bot_network(
    *,
    telegram_bot_token: str,
    telegram_proxy_url: str = "",
    bot_factory: Callable[..., Any] = create_bot,
) -> str:
    bot = bot_factory(
        telegram_bot_token=telegram_bot_token,
        telegram_proxy_url=telegram_proxy_url,
    )
    try:
        me = await bot.get_me()
    except (OSError, TimeoutError, TelegramNetworkError) as exc:
        raise RuntimeError(telegram_network_error_message(telegram_proxy_url)) from exc
    finally:
        close = getattr(bot.session, "close", None)
        if close is not None:
            await close()

    username = getattr(me, "username", "")
    identity = f"@{username}" if username else f"id={getattr(me, 'id', '<unknown>')}"
    proxy_status = "enabled" if telegram_proxy_url.strip() else "disabled"
    return "\n".join(
        [
            "Telegram API: ok",
            f"Bot: {identity}",
            f"Proxy: {proxy_status}",
        ]
    )


def telegram_network_error_message(telegram_proxy_url: str = "") -> str:
    proxy_url = telegram_proxy_url.strip()
    lines = [
        "Telegram API network check failed.",
        "The VPS cannot reach https://api.telegram.org directly or through the configured proxy.",
        "Check TELEGRAM_PROXY_URL in .env when a proxy is required.",
    ]
    if proxy_url:
        lines.extend(
            [
                f"Configured proxy: {redact(f'TELEGRAM_PROXY_URL={proxy_url}')}",
                f"Verify proxy access: curl --socks5-hostname {_proxy_curl_endpoint(proxy_url)} -I https://api.telegram.org",
            ]
        )
    else:
        lines.extend(
            [
                "Direct check: curl -I https://api.telegram.org",
                "Proxy example: TELEGRAM_PROXY_URL=socks5://127.0.0.1:1080",
            ]
        )
    return "\n".join(lines)


def create_workflow_from_settings(
    settings: Settings,
    *,
    database_path: str | Path | None = None,
) -> BotWorkflow:
    return create_workflow(
        database_path=database_path or settings.database_path,
        app_secret_key=settings.app_secret_key,
        admin_telegram_ids=set(settings.admin_ids),
        default_vpn_network_cidr=settings.default_vpn_network_cidr,
        max_devices_per_user=settings.max_devices_per_user,
        default_plan_days=settings.default_plan_days,
        vps_apply_enabled=settings.vps_apply_enabled,
        server_config_path=settings.server_config_path,
        server_name=settings.server_name,
        vps_ssh_password=settings.vps_ssh_password,
        client_config_template_dir=settings.client_config_template_dir,
        client_config_defaults=settings.client_config_defaults,
        bot_device_name_prefix=settings.bot_device_name_prefix,
        bot_device_name_sequence_seed=settings.bot_device_name_sequence_seed,
        phase15_settings=settings,
    )


def _proxy_curl_endpoint(proxy_url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(proxy_url)
    if not parsed.hostname:
        return "HOST:PORT"
    if parsed.port:
        return f"{parsed.hostname}:{parsed.port}"
    return parsed.hostname


def create_workflow(
    *,
    database_path: str | Path,
    app_secret_key: str,
    admin_telegram_ids: set[int],
    default_vpn_network_cidr: str,
    max_devices_per_user: int,
    default_plan_days: int,
    vps_apply_enabled: bool = False,
    server_config_path: str | Path = "servers.yml",
    server_name: str = "debian-vps-1",
    vps_ssh_password: str = "",
    client_config_template_dir: str | Path | None = None,
    client_config_defaults: ClientConfigDefaults | None = None,
    bot_device_name_prefix: str = "Neobyatnaya-AMNZ",
    bot_device_name_sequence_seed: int = 4,
    phase15_settings: Settings | None = None,
) -> BotWorkflow:
    conn = connect(database_path)
    initialize_schema(conn)
    repo = Repository(conn)
    repo.seed_default_plans()
    peer_applier = None
    if vps_apply_enabled:
        server_config = select_server(load_server_config(server_config_path), server_name)
        default_server_id = _sync_server_config(repo, server_config)
        peer_applier = ServerConfigPeerApplier(
            server_config,
            password=vps_ssh_password,
        )
    else:
        default_server_id = repo.ensure_default_server(
            name="local",
            network_cidr=default_vpn_network_cidr,
        )

    access_service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(app_secret_key),
        max_devices_per_user=max_devices_per_user,
        duration_days=default_plan_days,
        peer_applier=peer_applier,
        client_config_template_dir=client_config_template_dir,
        client_config_defaults=client_config_defaults,
    )
    secret_box = SecretBox.from_app_secret(app_secret_key)
    phase15_components = None
    if phase15_settings is not None:
        phase15_components = build_phase15_awg3_components(
            phase15_settings,
            repo,
            access_service,
            peer_applier,
        )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids=admin_telegram_ids,
        access_service=access_service,
        default_server_id=default_server_id,
        secret_box=secret_box,
        peer_remover=peer_applier,
        client_config_template_dir=str(client_config_template_dir)
        if client_config_template_dir is not None
        else None,
        client_config_defaults=client_config_defaults,
        device_name_prefix=bot_device_name_prefix,
        device_name_sequence_seed=bot_device_name_sequence_seed,
        vps_writes_enabled=vps_apply_enabled,
        admin_config_issuance_factory=(
            phase15_components.admin_config_issuance_factory
            if phase15_components is not None
            else None
        ),
        self_service_issuance_service=(
            phase15_components.self_service_issuance_service
            if phase15_components is not None
            else None
        ),
        callback_state=(
            phase15_components.callback_state
            if phase15_components is not None
            else None
        ),
        awg3_client_choices=(
            phase15_components.awg3_client_choices
            if phase15_components is not None
            else ()
        ),
        awg3_delivery_builder=(
            phase15_components.delivery_builder
            if phase15_components is not None
            else None
        ),
    )
    workflow._phase15_awg3_components = phase15_components
    return workflow


def _sync_server_config(repo: Repository, server: ServerConfig) -> int:
    if server.vpn.port == "auto":
        raise ValueError("VPS_APPLY_ENABLED requires a fixed vpn.port")
    if not server.vpn.server_public_key:
        raise ValueError("VPS_APPLY_ENABLED requires vpn.server_public_key in servers.yml")
    return repo.upsert_server_config(
        name=server.name,
        host=server.ssh.host,
        ssh_port=server.ssh.port,
        endpoint_host=server.vpn.endpoint_host,
        vpn_port=int(server.vpn.port),
        vpn_network_cidr=server.vpn.network_cidr,
        server_address=server.vpn.server_address,
        server_public_key=server.vpn.server_public_key,
        runtime=server.runtime.type,
        firewall=server.firewall.provider,
        max_devices=server.vpn.max_devices,
    )


if __name__ == "__main__":
    asyncio.run(run())
