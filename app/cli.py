import argparse
import asyncio
import getpass
import json
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request
from urllib.request import urlopen

from app import __version__
from app.agent.api import create_agent_app
from app.agent.audit import RepositoryAgentAuditSink
from app.agent.auth import hash_agent_token
from app.agent.config import build_agent_tokens
from app.agent.runtime import LocalCommandRuntimeAdapter
from app.backup.service import BackupService
from app.bot.controlled_smoke import ControlledSmokeError
from app.bot.controlled_smoke import run_controlled_start_smoke_from_settings
from app.config import Settings
from app.db.connection import connect, connect_read_only
from app.db.repositories import Repository
from app.db.repositories import DEVICE_STATUSES
from app.db.schema import initialize_schema
from app.main import check_bot_network
from app.security.crypto import SecretBox
from app.server.checks import planned_check_commands, run_server_checks
from app.server.peer_apply import (
    PeerApplyInput,
    ServerConfigPeerApplier,
    apply_peer,
    build_peer_apply_dry_run,
    build_peer_revoke_dry_run,
    revoke_peer,
)
from app.server.ssh import LocalCommandClient, SshClient, SystemSshClient
from app.server_config.loader import load_server_config, select_server
from app.server_config.models import ServerConfig
from app.services.access import (
    AccessService,
    OperatorDeviceContext,
    OperatorOwnerNotActive,
    OperatorOwnerNotFound,
)
from app.services.admin_config_issuance import (
    AdminConfigIssuanceService,
    validate_admin_config_issuance_manifest,
)
from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
)
from app.services.protocol_admission import ProtocolAdmissionService
from app.services.vpn_runtime_instances import runtime_spec_from_row
from app.vpn.protocol_versions import ProtocolVersion
from app.services.config_identity import (
    build_config_identity,
    build_unassigned_slot_identity,
)
from app.services.access_slot_assignment import assign_access_slot
from app.services.access_slot_lifecycle import (
    build_access_slot_disable_plan,
    disable_access_slot,
    revoke_access_slot,
)
from app.services.device_revoke import build_physical_device_revoke_plan
from app.services.api_tokens import create_route_api_token
from app.services.api_tokens import revoke_api_token
from app.services.api_smoke import validate_api_smoke_responses
from app.services.bot_media import BotMediaRegistry
from app.config_assignment import (
    CONFIG_ASSIGNMENT_MODES,
    DEDICATED_DEVICE,
    config_assignment_policy,
)
from app.services.fresh_install_wizard import (
    build_fresh_install_plan,
    collect_fresh_install_answers,
)
from app.services.peer_inventory import AwgDumpPeerInventoryCollector, PeerInventoryService
from app.services.private_config_artifact import (
    validate_private_config_artifact_target,
    write_private_config_artifact,
)
from app.services.traffic import AwgDumpTrafficCollector, TrafficService
from app.web.auth import create_password_hash
from app.vpn.config_versions import validate_config_version


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amneziya")
    sub = parser.add_subparsers(dest="command", required=True)

    bot = sub.add_parser("bot")
    bot_sub = bot.add_subparsers(dest="bot_command", required=True)
    bot_sub.add_parser("check-network")
    controlled_start_smoke = bot_sub.add_parser("controlled-start-smoke")
    controlled_start_smoke.add_argument("--admin-id", type=int, required=True)
    controlled_start_smoke.add_argument("--expected-bot-username", required=True)
    controlled_start_smoke.add_argument("--database-clone", required=True)
    controlled_start_smoke.add_argument("--timeout-seconds", type=int, default=120)

    bot_media = sub.add_parser("bot-media")
    bot_media_sub = bot_media.add_subparsers(dest="bot_media_command", required=True)

    def add_bot_media_common(media_parser: argparse.ArgumentParser) -> None:
        media_parser.add_argument(
            "--bot-kind",
            choices=["access", "support", "news"],
            required=True,
        )
        media_parser.add_argument(
            "--surface",
            choices=["start_header", "profile_icon"],
            required=True,
        )
        media_parser.add_argument("--registry", default="data/bot-media-registry.json")
        media_parser.add_argument("--media-root", default="data/bot-media")
        media_parser.add_argument("--pretty", action="store_true")

    bot_media_validate = bot_media_sub.add_parser("validate")
    add_bot_media_common(bot_media_validate)
    bot_media_validate.add_argument("--path", required=True)

    bot_media_stage = bot_media_sub.add_parser("stage")
    add_bot_media_common(bot_media_stage)
    bot_media_stage.add_argument("--path", required=True)

    bot_media_select = bot_media_sub.add_parser("select")
    add_bot_media_common(bot_media_select)
    bot_media_select.add_argument("--asset-id", required=True)

    bot_media_manifest = bot_media_sub.add_parser("manifest")
    bot_media_manifest.add_argument("--registry", default="data/bot-media-registry.json")
    bot_media_manifest.add_argument("--media-root", default="data/bot-media")
    bot_media_manifest.add_argument("--pretty", action="store_true")

    backup = sub.add_parser("backup")
    backup_sub = backup.add_subparsers(dest="backup_command", required=True)

    create = backup_sub.add_parser("create")
    create.add_argument("--db", default="data/amneziya.sqlite3")
    create.add_argument("--output", default="backups")

    verify = backup_sub.add_parser("verify")
    verify.add_argument("--file", required=True)

    restore = backup_sub.add_parser("restore")
    restore.add_argument("--file", required=True)
    restore.add_argument("--target-db", required=True)
    restore.add_argument("--force", action="store_true")

    device = sub.add_parser("device")
    device_sub = device.add_subparsers(dest="device_command", required=True)

    import_external = device_sub.add_parser("import-external")
    import_external.add_argument("--db", default="data/amneziya.sqlite3")
    import_external.add_argument("--telegram-id", type=int, required=True)
    import_external.add_argument("--username", default=None)
    import_external.add_argument("--first-name", default=None)
    import_external.add_argument("--last-name", default=None)
    import_external.add_argument("--server-name", default="local")
    import_external.add_argument("--server-network-cidr", default="10.8.0.0/24")
    import_external.add_argument("--name", required=True)
    import_external.add_argument("--duration-days", type=int, default=30)
    import_external.add_argument("--vpn-ip", required=True)
    import_external.add_argument("--peer-public-key", required=True)
    import_external.add_argument("--config-version", default="amneziawg_v2")
    import_external.add_argument("--status", choices=sorted(DEVICE_STATUSES), default="active")
    import_external.add_argument("--expires-at", default=None)
    import_external.add_argument("--revoked-at", default=None)
    import_external.add_argument("--revoke-reason", default=None)
    import_external.add_argument("--pretty", action="store_true")

    backfill_external = device_sub.add_parser("backfill-external")
    backfill_external.add_argument("--db-copy", required=True)
    backfill_external.add_argument("--input", required=True)
    backfill_mode = backfill_external.add_mutually_exclusive_group(required=True)
    backfill_mode.add_argument("--dry-run", action="store_true")
    backfill_mode.add_argument("--apply", action="store_true")
    backfill_external.add_argument("--pretty", action="store_true")

    create_operator = device_sub.add_parser("create-operator")
    create_operator.add_argument("--db", default="data/amneziya.sqlite3")
    create_operator.add_argument("--config", default="servers.yml")
    create_operator.add_argument("--server", required=True)
    create_operator.add_argument("--owner-user-id", type=int, required=True)
    create_operator.add_argument("--name", required=True)
    create_operator.add_argument("--duration-days", type=int, required=True)
    create_operator.add_argument("--config-version", default="amneziawg_v2")
    create_operator.add_argument(
        "--assignment-mode",
        choices=CONFIG_ASSIGNMENT_MODES,
        default=DEDICATED_DEVICE,
    )
    create_operator.add_argument("--output", required=True)
    create_operator.add_argument("--admin-telegram-id", type=int, required=True)
    create_operator.add_argument(
        "--execution-target",
        choices=("local", "remote-ssh"),
        required=True,
    )
    create_operator_mode = create_operator.add_mutually_exclusive_group(required=True)
    create_operator_mode.add_argument("--dry-run", action="store_true")
    create_operator_mode.add_argument("--apply", action="store_true")
    create_operator.add_argument("--pretty", action="store_true")

    admin_config = sub.add_parser("admin-config")
    admin_config_sub = admin_config.add_subparsers(
        dest="admin_config_command", required=True
    )
    issue_manifest = admin_config_sub.add_parser("issue-manifest")
    issue_manifest.add_argument("--manifest", required=True)
    issue_manifest.add_argument("--server", required=True)
    issue_manifest.add_argument("--db", default="data/amneziya.sqlite3")
    issue_manifest.add_argument("--config", default="servers.yml")
    issue_manifest.add_argument("--admin-telegram-id", type=int, default=None)
    issue_manifest.add_argument("--apply", action="store_true")
    issue_manifest.add_argument("--pretty", action="store_true")

    assign_slot = admin_config_sub.add_parser("assign-slot")
    assign_slot.add_argument("--db", default="data/amneziya.sqlite3")
    assign_slot.add_argument("--request-id", required=True)
    assign_slot.add_argument("--device-id", type=int, required=True)
    assign_slot.add_argument("--device-label", required=True)
    assign_slot.add_argument("--platform", required=True)
    assign_slot.add_argument("--admin-telegram-id", type=int)
    assign_slot.add_argument("--apply", action="store_true")
    assign_slot.add_argument("--pretty", action="store_true")

    for command_name in ("disable-slot", "revoke-slot"):
        lifecycle = admin_config_sub.add_parser(command_name)
        lifecycle.add_argument("--db", default="data/amneziya.sqlite3")
        lifecycle.add_argument("--config", default="servers.yml")
        lifecycle.add_argument("--server", required=True)
        lifecycle.add_argument("--device-id", type=int, required=True)
        lifecycle.add_argument("--reason", required=True)
        lifecycle.add_argument("--admin-telegram-id", type=int)
        lifecycle.add_argument("--apply", action="store_true")
        lifecycle.add_argument("--pretty", action="store_true")

    server = sub.add_parser("server")
    server_sub = server.add_subparsers(dest="server_command", required=True)

    check = server_sub.add_parser("check")
    check.add_argument("--config", default="servers.yml")
    check.add_argument("--server", required=True)
    check.add_argument("--dry-run", action="store_true")

    apply_peer = server_sub.add_parser("apply-peer")
    apply_peer.add_argument("--config", default="servers.yml")
    apply_peer.add_argument("--server", required=True)
    apply_peer.add_argument("--public-key", required=True)
    preshared_key_input = apply_peer.add_mutually_exclusive_group(required=True)
    preshared_key_input.add_argument("--preshared-key")
    preshared_key_input.add_argument("--preshared-key-stdin", action="store_true")
    apply_peer.add_argument("--vpn-ip", required=True)
    apply_mode = apply_peer.add_mutually_exclusive_group(required=True)
    apply_mode.add_argument("--dry-run", action="store_true")
    apply_mode.add_argument("--apply", action="store_true")

    revoke_peer_parser = server_sub.add_parser("revoke-peer")
    revoke_peer_parser.add_argument("--config", default="servers.yml")
    revoke_peer_parser.add_argument("--server", required=True)
    revoke_peer_parser.add_argument("--public-key", required=True)
    revoke_mode = revoke_peer_parser.add_mutually_exclusive_group(required=True)
    revoke_mode.add_argument("--dry-run", action="store_true")
    revoke_mode.add_argument("--apply", action="store_true")

    collect_traffic = server_sub.add_parser("collect-traffic")
    collect_traffic.add_argument("--config", default="servers.yml")
    collect_traffic.add_argument("--server", required=True)
    collect_traffic.add_argument("--db", default="data/amneziya.sqlite3")
    collect_traffic.add_argument("--dry-run", action="store_true")

    sync_peers = server_sub.add_parser("sync-peers")
    sync_peers.add_argument("--config", default="servers.yml")
    sync_peers.add_argument("--server", required=True)
    sync_peers.add_argument("--db", default="data/amneziya.sqlite3")

    preflight = server_sub.add_parser("preflight")
    preflight.add_argument("--config", default="servers.yml")
    preflight.add_argument("--server", required=True)
    preflight.add_argument("--db", default="data/amneziya.sqlite3")

    retest_plan = server_sub.add_parser("retest-plan")
    retest_plan.add_argument("--config", default="servers.yml")
    retest_plan.add_argument("--server", required=True)
    retest_plan.add_argument("--db", default="data/amneziya.sqlite3")

    install = sub.add_parser("install")
    install_sub = install.add_subparsers(dest="install_command", required=True)

    install_wizard = install_sub.add_parser("wizard")
    install_wizard.add_argument("--pretty", action="store_true")

    install_plan = install_sub.add_parser("plan")
    install_plan.add_argument("--answers", required=True)
    install_plan.add_argument("--pretty", action="store_true")

    agent = sub.add_parser("agent")
    agent_sub = agent.add_subparsers(dest="agent_command", required=True)

    agent_hash_token = agent_sub.add_parser("hash-token")
    agent_hash_token.add_argument(
        "--token",
        default=None,
        help="Optional; omit to enter the token without shell history.",
    )

    agent_serve = agent_sub.add_parser("serve")
    agent_serve.add_argument("--host", default=None)
    agent_serve.add_argument("--port", type=int, default=None)

    web = sub.add_parser("web")
    web_sub = web.add_subparsers(dest="web_command", required=True)

    serve = web_sub.add_parser("serve")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    hash_password = web_sub.add_parser("hash-password")
    hash_password.add_argument(
        "--password",
        default=None,
        help="Optional; omit to enter the password without shell history.",
    )

    api = sub.add_parser("api")
    api_sub = api.add_subparsers(dest="api_command", required=True)

    api_serve = api_sub.add_parser("serve")
    api_serve.add_argument("--host", default=None)
    api_serve.add_argument("--port", type=int, default=None)

    api_smoke = api_sub.add_parser("smoke-check")
    api_smoke.add_argument("--base-url", default="http://127.0.0.1:3040")
    api_smoke.add_argument("--token", required=True)
    api_smoke.add_argument("--server-name", required=True)
    api_smoke.add_argument("--timeout", type=float, default=5.0)
    api_smoke.add_argument("--pretty", action="store_true")

    api_smoke_cycle = api_sub.add_parser("smoke-cycle")
    api_smoke_cycle.add_argument("--db", default="data/amneziya.sqlite3")
    api_smoke_cycle.add_argument("--base-url", default="http://127.0.0.1:3040")
    api_smoke_cycle.add_argument("--server-name", required=True)
    api_smoke_cycle.add_argument("--name", default="vps-smoke")
    api_smoke_cycle.add_argument("--owner-label", default="ops")
    api_smoke_cycle.add_argument("--expires-at", required=True)
    api_smoke_cycle.add_argument("--timeout", type=float, default=5.0)
    api_smoke_cycle.add_argument("--pretty", action="store_true")

    api_token = api_sub.add_parser("token")
    api_token_sub = api_token.add_subparsers(dest="api_token_command", required=True)

    api_token_issue = api_token_sub.add_parser("issue")
    api_token_issue.add_argument("--db", default="data/amneziya.sqlite3")
    api_token_issue.add_argument("--name", required=True)
    api_token_issue.add_argument("--owner-label", required=True)
    api_token_issue.add_argument("--owner-user-id", type=int, default=None)
    api_token_issue.add_argument("--scope", action="append", dest="scopes", required=True)
    api_token_issue.add_argument("--expires-at", required=True)
    api_token_issue.add_argument("--pretty", action="store_true")

    api_token_revoke = api_token_sub.add_parser("revoke")
    api_token_revoke.add_argument("--db", default="data/amneziya.sqlite3")
    api_token_revoke.add_argument("--token-id", required=True)
    api_token_revoke.add_argument("--reason", required=True)
    api_token_revoke.add_argument("--pretty", action="store_true")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    service = BackupService(app_version=__version__)

    if args.command == "backup" and args.backup_command == "create":
        print(service.create(Path(args.db), Path(args.output)))
    elif args.command == "backup" and args.backup_command == "verify":
        print(service.verify(Path(args.file)))
    elif args.command == "backup" and args.backup_command == "restore":
        print(service.restore(Path(args.file), Path(args.target_db), force=args.force))
    elif args.command == "device" and args.device_command == "import-external":
        print(
            run_device_import_external(
                db_path=Path(args.db),
                telegram_id=args.telegram_id,
                username=args.username,
                first_name=args.first_name,
                last_name=args.last_name,
                server_name=args.server_name,
                server_network_cidr=args.server_network_cidr,
                name=args.name,
                duration_days=args.duration_days,
                vpn_ip=args.vpn_ip,
                peer_public_key=args.peer_public_key,
                config_version=args.config_version,
                status=args.status,
                expires_at=args.expires_at,
                revoked_at=args.revoked_at,
                revoke_reason=args.revoke_reason,
                pretty=args.pretty,
            )
        )
    elif args.command == "device" and args.device_command == "backfill-external":
        print(
            run_device_backfill_external(
                db_copy_path=Path(args.db_copy),
                input_path=Path(args.input),
                apply=args.apply,
                pretty=args.pretty,
            )
        )
    elif args.command == "device" and args.device_command == "create-operator":
        if args.dry_run:
            print(
                build_operator_device_create_plan(
                    owner_user_id=args.owner_user_id,
                    server_name=args.server,
                    device_name=args.name,
                    config_version=args.config_version,
                    assignment_mode=args.assignment_mode,
                    output_path=Path(args.output),
                    admin_telegram_id=args.admin_telegram_id,
                    execution_target=args.execution_target,
                    pretty=args.pretty,
                )
            )
        else:
            require_vps_apply_enabled_for_cli_apply()
            settings = Settings()
            server_config = select_server(
                load_server_config(Path(args.config)), args.server
            )
            print(
                run_operator_device_create(
                    db_path=Path(args.db),
                    server=server_config,
                    owner_user_id=args.owner_user_id,
                    device_name=args.name,
                    duration_days=args.duration_days,
                    config_version=args.config_version,
                    assignment_mode=args.assignment_mode,
                    output_path=Path(args.output),
                    admin_telegram_id=args.admin_telegram_id,
                    authorized_admin_telegram_ids=set(settings.admin_ids),
                    app_secret_key=settings.app_secret_key,
                    max_devices_per_user=settings.max_devices_per_user,
                    vps_ssh_password=settings.vps_ssh_password,
                    client_config_template_dir=settings.client_config_template_dir,
                    client_config_defaults=settings.client_config_defaults,
                    execution_target=args.execution_target,
                    pretty=args.pretty,
                )
            )
    elif (
        args.command == "admin-config"
        and args.admin_config_command == "issue-manifest"
    ):
        if not args.apply:
            print(
                build_admin_config_issuance_plan(
                    manifest_path=Path(args.manifest),
                    server_name=args.server,
                    pretty=args.pretty,
                )
            )
        else:
            require_vps_apply_enabled_for_cli_apply()
            if args.admin_telegram_id is None:
                raise SystemExit("--admin-telegram-id is required with --apply")
            settings = Settings()
            if args.admin_telegram_id not in settings.admin_ids:
                raise SystemExit("--admin-telegram-id must be an explicitly configured admin ID")
            server_config = select_server(load_server_config(Path(args.config)), args.server)
            print(
                run_admin_config_issue_manifest(
                    db_path=Path(args.db),
                    manifest_path=Path(args.manifest),
                    server=server_config,
                    admin_telegram_id=args.admin_telegram_id,
                    authorized_admin_telegram_ids=set(settings.admin_ids),
                    app_secret_key=settings.app_secret_key,
                    max_devices_per_user=settings.max_devices_per_user,
                    vps_ssh_password=settings.vps_ssh_password,
                    client_config_template_dir=settings.client_config_template_dir,
                    client_config_defaults=settings.client_config_defaults,
                    pretty=args.pretty,
                )
            )
    elif args.command == "admin-config" and args.admin_config_command == "assign-slot":
        if not args.apply:
            print(
                _json_dumps(
                    {
                        "action": "access_slot.assign",
                        "mode": "dry-run",
                        "local_device_id": args.device_id,
                        "request_id": args.request_id,
                        "device_label": args.device_label,
                        "platform": args.platform,
                        "database_mutation": False,
                        "remote_mutation": False,
                    },
                    pretty=args.pretty,
                )
            )
        else:
            require_vps_apply_enabled_for_cli_apply()
            if args.admin_telegram_id is None:
                raise SystemExit("--admin-telegram-id is required with --apply")
            settings = Settings()
            if args.admin_telegram_id not in settings.admin_ids:
                raise SystemExit("--admin-telegram-id must be an explicitly configured admin ID")
            print(
                run_admin_config_assign_slot(
                    db_path=Path(args.db),
                    request_id=args.request_id,
                    local_device_id=args.device_id,
                    device_label=args.device_label,
                    platform=args.platform,
                    admin_telegram_id=args.admin_telegram_id,
                    authorized_admin_telegram_ids=set(settings.admin_ids),
                    pretty=args.pretty,
                )
            )
    elif args.command == "admin-config" and args.admin_config_command in {"disable-slot", "revoke-slot"}:
        if not args.apply:
            print(
                build_admin_config_slot_lifecycle_plan(
                    db_path=Path(args.db),
                    local_device_id=args.device_id,
                    action=args.admin_config_command.removesuffix("-slot"),
                    pretty=args.pretty,
                )
            )
        else:
            require_vps_apply_enabled_for_cli_apply()
            if args.admin_telegram_id is None:
                raise SystemExit("--admin-telegram-id is required with --apply")
            settings = Settings()
            if args.admin_telegram_id not in settings.admin_ids:
                raise SystemExit("--admin-telegram-id must be an explicitly configured admin ID")
            server_config = select_server(load_server_config(Path(args.config)), args.server)
            print(
                run_admin_config_slot_lifecycle(
                    db_path=Path(args.db),
                    server=server_config,
                    local_device_id=args.device_id,
                    action=args.admin_config_command.removesuffix("-slot"),
                    reason=args.reason,
                    admin_telegram_id=args.admin_telegram_id,
                    authorized_admin_telegram_ids=set(settings.admin_ids),
                    vps_ssh_password=settings.vps_ssh_password,
                    pretty=args.pretty,
                )
            )
    elif args.command == "server" and args.server_command == "check":
        config = load_server_config(Path(args.config))
        server = select_server(config, args.server)
        print(run_server_check(server, dry_run=args.dry_run))
    elif args.command == "server" and args.server_command == "apply-peer":
        config = load_server_config(Path(args.config))
        server = select_server(config, args.server)
        peer = PeerApplyInput(
            public_key=args.public_key,
            preshared_key=read_preshared_key_arg(args),
            vpn_ip=args.vpn_ip,
        )
        if args.dry_run:
            print(build_peer_apply_dry_run(server, peer))
        else:
            require_vps_apply_enabled_for_cli_apply()
            print(apply_peer(server, peer, ssh_client=SystemSshClient(server)))
    elif args.command == "server" and args.server_command == "revoke-peer":
        config = load_server_config(Path(args.config))
        server = select_server(config, args.server)
        if args.dry_run:
            print(build_peer_revoke_dry_run(server, args.public_key))
        else:
            require_vps_apply_enabled_for_cli_apply()
            print(revoke_peer(server, args.public_key, ssh_client=SystemSshClient(server)))
    elif args.command == "server" and args.server_command == "collect-traffic":
        config = load_server_config(Path(args.config))
        server = select_server(config, args.server)
        if args.dry_run:
            print(run_server_traffic_collection_dry_run(server))
        else:
            print(run_server_traffic_collection(server, db_path=Path(args.db)))
    elif args.command == "server" and args.server_command == "sync-peers":
        config = load_server_config(Path(args.config))
        server = select_server(config, args.server)
        print(run_server_peer_sync(server, db_path=Path(args.db)))
    elif args.command == "server" and args.server_command == "preflight":
        print(
            run_server_preflight(
                config_path=Path(args.config),
                server_name=args.server,
                db_path=Path(args.db),
            )
        )
    elif args.command == "server" and args.server_command == "retest-plan":
        print(
            run_server_retest_plan(
                config_path=Path(args.config),
                server_name=args.server,
                db_path=Path(args.db),
            )
        )
    elif args.command == "install" and args.install_command == "wizard":
        print(run_fresh_install_wizard(pretty=args.pretty))
    elif args.command == "install" and args.install_command == "plan":
        print(run_fresh_install_plan(answers_path=Path(args.answers), pretty=args.pretty))
    elif args.command == "bot" and args.bot_command == "check-network":
        settings = Settings()
        print(
            asyncio.run(
                check_bot_network(
                    telegram_bot_token=settings.telegram_bot_token,
                    telegram_proxy_url=settings.telegram_proxy_url,
                )
            )
        )
    elif args.command == "bot" and args.bot_command == "controlled-start-smoke":
        settings = Settings()
        try:
            result = asyncio.run(
                run_controlled_start_smoke_from_settings(
                    settings,
                    admin_id=args.admin_id,
                    expected_bot_username=args.expected_bot_username,
                    clone_database_path=Path(args.database_clone),
                    timeout_seconds=args.timeout_seconds,
                )
            )
        except ControlledSmokeError as exc:
            raise SystemExit(f"Controlled Telegram smoke: STOP: {exc}") from None
        print(result.render())
    elif args.command == "bot-media" and args.bot_media_command == "validate":
        print(
            run_bot_media_validate(
                bot_kind=args.bot_kind,
                surface=args.surface,
                path=Path(args.path),
                registry_path=Path(args.registry),
                media_root=Path(args.media_root),
                pretty=args.pretty,
            )
        )
    elif args.command == "bot-media" and args.bot_media_command == "stage":
        print(
            run_bot_media_stage(
                bot_kind=args.bot_kind,
                surface=args.surface,
                path=Path(args.path),
                registry_path=Path(args.registry),
                media_root=Path(args.media_root),
                pretty=args.pretty,
            )
        )
    elif args.command == "bot-media" and args.bot_media_command == "select":
        print(
            run_bot_media_select(
                bot_kind=args.bot_kind,
                surface=args.surface,
                asset_id=args.asset_id,
                registry_path=Path(args.registry),
                media_root=Path(args.media_root),
                pretty=args.pretty,
            )
        )
    elif args.command == "bot-media" and args.bot_media_command == "manifest":
        print(
            run_bot_media_manifest(
                registry_path=Path(args.registry),
                media_root=Path(args.media_root),
                pretty=args.pretty,
            )
        )
    elif args.command == "agent" and args.agent_command == "hash-token":
        print(run_agent_token_hash(_read_agent_token(args.token)))
    elif args.command == "agent" and args.agent_command == "serve":
        run_agent_server(host=args.host, port=args.port)
    elif args.command == "web" and args.web_command == "hash-password":
        print(run_web_password_hash(_read_web_password(args.password)))
    elif args.command == "web" and args.web_command == "serve":
        run_web_server(host=args.host, port=args.port)
    elif args.command == "api" and args.api_command == "serve":
        run_api_server(host=args.host, port=args.port)
    elif args.command == "api" and args.api_command == "smoke-check":
        print(
            run_api_smoke_check(
                base_url=args.base_url,
                token=args.token,
                server_name=args.server_name,
                timeout=args.timeout,
                pretty=args.pretty,
            )
        )
    elif args.command == "api" and args.api_command == "smoke-cycle":
        print(
            run_api_smoke_cycle(
                db_path=Path(args.db),
                base_url=args.base_url,
                server_name=args.server_name,
                name=args.name,
                owner_label=args.owner_label,
                expires_at=args.expires_at,
                timeout=args.timeout,
                pretty=args.pretty,
            )
        )
    elif args.command == "api" and args.api_command == "token":
        if args.api_token_command == "issue":
            print(
                run_api_token_issue(
                    db_path=Path(args.db),
                    name=args.name,
                    owner_label=args.owner_label,
                    scopes=args.scopes,
                    expires_at=args.expires_at,
                    owner_user_id=args.owner_user_id,
                    pretty=args.pretty,
                )
            )
        elif args.api_token_command == "revoke":
            print(
                run_api_token_revoke(
                    db_path=Path(args.db),
                    token_id=args.token_id,
                    reason=args.reason,
                    pretty=args.pretty,
                )
            )


def run_device_import_external(
    *,
    db_path: Path,
    telegram_id: int,
    username: str | None,
    first_name: str | None,
    last_name: str | None,
    server_name: str,
    server_network_cidr: str,
    name: str,
    duration_days: int,
    vpn_ip: str,
    peer_public_key: str,
    config_version: str,
    status: str,
    expires_at: str | None,
    revoked_at: str | None,
    revoke_reason: str | None,
    pretty: bool = False,
) -> str:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        user_id = repo.upsert_user(
            telegram_id=telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        server_id = repo.ensure_default_server(
            name=server_name,
            network_cidr=server_network_cidr,
        )
        device_id = repo.create_external_device(
            user_id=user_id,
            server_id=server_id,
            name=name,
            duration_days=duration_days,
            vpn_ip=vpn_ip,
            peer_public_key=peer_public_key,
            config_version=validate_config_version(config_version),
            status=status,
            expires_at=expires_at,
            revoked_at=revoked_at,
            revoke_reason=revoke_reason,
        )
        device = repo.get_device(device_id)
        user = repo.get_user(user_id)
        payload = {
            "user": {
                "id": int(user["id"]),
                "telegram_id": int(user["telegram_id"]),
                "username": user["username"],
            },
            "device": {
                "id": int(device["id"]),
                "name": device["name"],
                "status": device["status"],
                "vpn_ip": device["vpn_ip"],
                "config_version": device["config_version"],
                "config_material_status": device["config_material_status"],
                "server_id": int(device["server_id"]),
                "server_name": server_name,
            },
            "delivery": {
                "config_resend_available": False,
                "reason": "external_only_config_material_unavailable",
            },
        }
        return _json_dumps(payload, pretty=pretty)
    finally:
        conn.close()


def build_admin_config_issuance_plan(
    *,
    manifest_path: Path,
    server_name: str,
    pretty: bool = False,
) -> str:
    manifest = _load_admin_config_issuance_manifest(manifest_path)
    validated = validate_admin_config_issuance_manifest(manifest)
    if validated.server != server_name:
        raise ValueError("manifest server does not match --server")
    slots = []
    for slot in validated.expanded_slots:
        identity = (
            build_unassigned_slot_identity(
                slot.recipient_label,
                slot.slot_sequence,
            )
            if slot.assignment_mode == "recipient_unassigned"
            else build_config_identity(slot.recipient_label, slot.device_label)
        )
        slots.append(
            {
                "recipient_label": slot.recipient_label,
                "assignment_mode": slot.assignment_mode,
                "slot_sequence": slot.slot_sequence,
                "filename": identity.filename,
                "expiry_policy": slot.expiry.policy,
                "quota_delta": 1,
                "client_application": slot.client_application,
                "client_platform": slot.client_platform,
                "client_version": slot.client_version,
                "protocol_version": slot.protocol_version.value,
                "admission_checked": False,
            }
        )
    return _json_dumps(
        {
            "action": "admin_config.issue_manifest",
            "mode": "dry-run",
            "request_id": validated.request_id,
            "server": validated.server,
            "item_count": len(validated.items),
            "expanded_slot_count": len(validated.expanded_slots),
            "slots": slots,
            "remote_mutation": False,
            "database_mutation": False,
        },
        pretty=pretty,
    )


def run_admin_config_issue_manifest(
    *,
    db_path: Path,
    manifest_path: Path,
    server: ServerConfig,
    admin_telegram_id: int,
    authorized_admin_telegram_ids: set[int],
    app_secret_key: str,
    max_devices_per_user: int,
    duration_days: int | None = None,
    vps_ssh_password: str = "",
    client_config_template_dir: str | Path | None = None,
    client_config_defaults=None,
    command_client: SshClient | None = None,
    attachment_builder: Callable[[str, str], object] | None = None,
    admission_service: ProtocolAdmissionService | None = None,
    pretty: bool = False,
) -> str:
    manifest = _load_admin_config_issuance_manifest(manifest_path)
    validated = validate_admin_config_issuance_manifest(manifest)
    if validated.server != server.name:
        raise ValueError("manifest server does not match --server")
    _validate_operator_server_for_apply(server)
    if admin_telegram_id <= 0:
        raise ValueError("admin_telegram_id must be positive")
    if admin_telegram_id not in authorized_admin_telegram_ids:
        raise PermissionError("admin_telegram_id is not a configured admin")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        server_id = _sync_server_row(repo, server)
        actual_admission_service = admission_service or _build_protocol_admission_service(
            repo=repo,
            slots=validated.expanded_slots,
            server_id=server_id,
        )
        actual_command_client = command_client or SystemSshClient(
            server,
            password=vps_ssh_password,
        )
        access_service = AccessService(
            repo=repo,
            secret_box=SecretBox.from_app_secret(app_secret_key),
            max_devices_per_user=max_devices_per_user,
            duration_days=duration_days,
            peer_applier=ServerConfigPeerApplier(
                server,
                ssh_client=actual_command_client,
            ),
            client_config_template_dir=client_config_template_dir,
            client_config_defaults=client_config_defaults,
        )

        if attachment_builder is None:
            def attachment_builder(filename: str, config_text: str) -> object:
                output_path = manifest_path.parent / filename
                return write_private_config_artifact(output_path, config_text)

        result = AdminConfigIssuanceService(
            repo=repo,
            access_service=access_service,
            admission_service=actual_admission_service,
            admin_telegram_id=admin_telegram_id,
            attachment_builder=attachment_builder,
            max_devices_per_recipient=max_devices_per_user,
        ).issue_manifest(manifest)
        payload = result.to_safe_dict()
        payload.update(
            {
                "action": "admin_config.issue_manifest",
                "mode": "apply",
                "server_id": server_id,
                "config_payload_output": False,
            }
        )
        return _json_dumps(payload, pretty=pretty)
    finally:
        conn.close()


def _build_protocol_admission_service(*, repo, slots, server_id: int):
    evidence_by_id: dict[str, ClientCompatibilityEvidence] = {}
    for slot in slots:
        rows = repo.find_client_compatibility_evidence(
            application=slot.client_application,
            platform=slot.client_platform,
            client_version=slot.client_version,
            protocol_version=slot.protocol_version.value,
        )
        for row in rows:
            item = ClientCompatibilityEvidence(
                evidence_id=str(row["evidence_id"]),
                client=ClientIdentity(
                    str(row["application"]),
                    str(row["platform"]),
                    str(row["client_version"]),
                ),
                protocol_version=ProtocolVersion(str(row["protocol_version"])),
                source_kind=str(row["source_kind"]),
                status=CompatibilityEvidenceStatus(str(row["status"])),
                observed_at=_parse_api_datetime(str(row["observed_at"])),
                safe_reference=str(row["safe_reference"]),
                scope=str(row["scope"]),
            )
            evidence_by_id[item.evidence_id] = item
    runtimes = tuple(
        runtime_spec_from_row(row)
        for row in repo.list_vpn_runtime_instances_for_server(server_id)
    )
    return ProtocolAdmissionService(
        evidence=tuple(evidence_by_id.values()),
        runtimes=runtimes,
        now=datetime.now(timezone.utc),
    )


def run_admin_config_assign_slot(
    *,
    db_path: Path,
    request_id: str,
    local_device_id: int,
    device_label: str,
    platform: str,
    admin_telegram_id: int,
    authorized_admin_telegram_ids: set[int],
    pretty: bool = False,
) -> str:
    if admin_telegram_id not in authorized_admin_telegram_ids:
        raise PermissionError("admin_telegram_id is not a configured admin")
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        passport = assign_access_slot(
            Repository(conn),
            request_id=request_id,
            local_device_id=local_device_id,
            device_label=device_label,
            context=OperatorDeviceContext(platform=platform),
            admin_telegram_id=admin_telegram_id,
        )
        return _json_dumps(
            {
                "action": "access_slot.assign",
                "mode": "apply",
                "local_device_id": local_device_id,
                "passport_device_id": passport.device_id,
                "assignment_mode": "dedicated_device",
                "remote_mutation": False,
            },
            pretty=pretty,
        )
    finally:
        conn.close()


def build_admin_config_slot_lifecycle_plan(
    *,
    db_path: Path,
    local_device_id: int,
    action: str,
    pretty: bool = False,
) -> str:
    conn = connect_read_only(db_path)
    try:
        repo = Repository(conn)
        if action == "disable":
            plan = build_access_slot_disable_plan(repo, local_device_id=local_device_id)
        elif action == "revoke":
            plan = build_physical_device_revoke_plan(repo, local_device_id=local_device_id)
        else:
            raise ValueError("unsupported access slot lifecycle action")
        return _json_dumps(
            {
                "action": f"access_slot.{action}",
                "mode": "dry-run",
                "local_device_id": local_device_id,
                "database_mutation": False,
                "remote_mutation": False,
                "operation_plan": plan.to_safe_metadata(),
            },
            pretty=pretty,
        )
    finally:
        conn.close()


def run_admin_config_slot_lifecycle(
    *,
    db_path: Path,
    server: ServerConfig,
    local_device_id: int,
    action: str,
    reason: str,
    admin_telegram_id: int,
    authorized_admin_telegram_ids: set[int],
    vps_ssh_password: str = "",
    command_client: SshClient | None = None,
    pretty: bool = False,
) -> str:
    if admin_telegram_id not in authorized_admin_telegram_ids:
        raise PermissionError("admin_telegram_id is not a configured admin")
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        device = repo.get_device(local_device_id)
        stored_server = repo.get_server(int(device["server_id"]))
        _validate_operator_server_for_apply(server)
        expected_target = (
            server.name,
            server.ssh.host,
            int(server.ssh.port),
            server.vpn.endpoint_host,
            int(server.vpn.port),
        )
        stored_target = (
            str(stored_server["name"]),
            str(stored_server["host"] or ""),
            stored_server["ssh_port"],
            str(stored_server["endpoint_host"] or ""),
            stored_server["vpn_port"],
        )
        if stored_target != expected_target:
            raise ValueError("access slot server target does not match --server")
        actual_client = command_client or SystemSshClient(server, password=vps_ssh_password)
        remover = ServerConfigPeerApplier(server, ssh_client=actual_client)
        kwargs = {
            "local_device_id": local_device_id,
            "reason": reason,
            "changed_at": datetime.now(timezone.utc),
            "peer_remover": remover,
            "apply_remote": True,
            "admin_telegram_id": admin_telegram_id,
        }
        if action == "disable":
            result = disable_access_slot(repo, **kwargs)
        elif action == "revoke":
            result = revoke_access_slot(repo, **kwargs)
        else:
            raise ValueError("unsupported access slot lifecycle action")
        payload = result.safe_metadata()
        payload.update({"action": f"access_slot.{action}", "mode": "apply"})
        return _json_dumps(payload, pretty=pretty)
    finally:
        conn.close()


def _load_admin_config_issuance_manifest(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest must contain a JSON object")
    return payload


def build_operator_device_create_plan(
    *,
    owner_user_id: int,
    server_name: str,
    device_name: str,
    duration_days: int,
    config_version: str,
    output_path: Path,
    admin_telegram_id: int,
    execution_target: str,
    assignment_mode: str = DEDICATED_DEVICE,
    pretty: bool = False,
) -> str:
    _validate_operator_execution_target(execution_target)
    if owner_user_id <= 0:
        raise ValueError("owner_user_id must be positive")
    if admin_telegram_id <= 0:
        raise ValueError("admin_telegram_id must be positive")
    if duration_days <= 0:
        raise ValueError("duration_days must be positive")
    normalized_name = device_name.strip()
    if not normalized_name:
        raise ValueError("device_name must be non-blank")
    version = validate_config_version(config_version)
    assignment_policy = config_assignment_policy(assignment_mode)
    return _json_dumps(
        {
            "action": "device.create_operator",
            "mode": "dry-run",
            "owner_user_id": owner_user_id,
            "server_name": server_name,
            "device_name": normalized_name,
            "duration_days": duration_days,
            "config_version": version,
            "assignment_mode": assignment_policy.mode,
            "physical_device_limit": assignment_policy.physical_device_limit,
            "physical_device_count_enforceable": (
                assignment_policy.physical_device_count_enforceable
            ),
            "output": str(output_path),
            "admin_actor_provided": True,
            "execution_target": execution_target,
            "remote_mutation": False,
            "database_mutation": False,
            "config_artifact_written": False,
            "config_payload_output": False,
            "next": (
                "rerun with --apply only after the exact owner-shared profile gate is open"
                if not assignment_policy.physical_device_count_enforceable
                else "rerun with --apply only after the exact one-device gate is open"
            ),
        },
        pretty=pretty,
    )


def run_operator_device_create(
    *,
    db_path: Path,
    server: ServerConfig,
    owner_user_id: int,
    device_name: str,
    duration_days: int,
    config_version: str,
    output_path: Path,
    admin_telegram_id: int,
    app_secret_key: str,
    authorized_admin_telegram_ids: set[int],
    max_devices_per_user: int,
    vps_ssh_password: str = "",
    client_config_template_dir: str | Path | None = None,
    client_config_defaults=None,
    execution_target: str,
    assignment_mode: str = DEDICATED_DEVICE,
    command_client: SshClient | None = None,
    config_artifact_writer: Callable[[Path, str], Path] | None = None,
    pretty: bool = False,
) -> str:
    _validate_operator_execution_target(execution_target)
    _validate_operator_server_for_apply(server)
    if config_artifact_writer is None:
        validate_private_config_artifact_target(output_path)
        config_artifact_writer = write_private_config_artifact
    elif output_path.exists():
        raise FileExistsError(f"Refusing to overwrite private config artifact: {output_path}")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        if not _is_authorized_operator_admin(
            repo,
            admin_telegram_id=admin_telegram_id,
            configured_admin_ids=authorized_admin_telegram_ids,
        ):
            raise PermissionError("admin_telegram_id is not an authorized operator admin")
        try:
            owner = repo.get_user(owner_user_id)
        except LookupError as exc:
            raise OperatorOwnerNotFound(
                f"Operator device owner {owner_user_id} does not exist"
            ) from exc
        if str(owner["status"]) != "active":
            raise OperatorOwnerNotActive(
                f"Operator device owner {owner_user_id} is not active"
            )
        server_id = _sync_server_row(repo, server)
        if command_client is None:
            if execution_target == "local":
                command_client = LocalCommandClient()
            elif execution_target == "remote-ssh":
                command_client = SystemSshClient(
                    server,
                    password=vps_ssh_password,
                )
            else:
                raise ValueError(f"Unsupported execution_target: {execution_target}")
        service = AccessService(
            repo=repo,
            secret_box=SecretBox.from_app_secret(app_secret_key),
            max_devices_per_user=max_devices_per_user,
            duration_days=duration_days,
            peer_applier=ServerConfigPeerApplier(
                server,
                ssh_client=command_client,
            ),
            client_config_template_dir=client_config_template_dir,
            client_config_defaults=client_config_defaults,
        )
        result = service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name=device_name,
            duration_days=duration_days,
            admin_telegram_id=admin_telegram_id,
            config_version=config_version,
            assignment_mode=assignment_mode,
            config_artifact_writer=lambda config_text: config_artifact_writer(
                output_path, config_text
            ),
        )
        device = repo.get_device(result.device_id)
        return _json_dumps(
            {
                "action": "device.create_operator",
                "mode": "apply",
                "status": "passed",
                "device_id": result.device_id,
                "owner_user_id": owner_user_id,
                "server_name": server.name,
                "execution_target": execution_target,
                "device_name": str(device["name"]),
                "duration_days": int(device["duration_days"]),
                "config_version": str(device["config_version"]),
                "config_material_status": str(device["config_material_status"]),
                "assignment_mode": result.assignment_mode,
                "physical_device_limit": config_assignment_policy(
                    result.assignment_mode
                ).physical_device_limit,
                "physical_device_count_enforceable": config_assignment_policy(
                    result.assignment_mode
                ).physical_device_count_enforceable,
                "output": result.config_artifact_path,
                "remote_peer_apply": True,
                "admin_audit_recorded": True,
                "config_payload_output": False,
            },
            pretty=pretty,
        )
    finally:
        conn.close()


def _validate_operator_execution_target(execution_target: str) -> None:
    if execution_target not in {"local", "remote-ssh"}:
        raise ValueError(f"Unsupported execution_target: {execution_target}")


def _is_authorized_operator_admin(
    repo: Repository,
    *,
    admin_telegram_id: int,
    configured_admin_ids: set[int],
) -> bool:
    if admin_telegram_id in configured_admin_ids:
        return True
    user = repo.get_user_by_telegram_id(admin_telegram_id)
    return bool(
        user is not None
        and str(user["status"]) == "active"
        and bool(user["is_admin"])
    )


def _validate_operator_server_for_apply(server: ServerConfig) -> None:
    if server.vpn.port == "auto":
        raise ValueError("operator device apply requires a fixed vpn.port")
    if not server.vpn.server_public_key:
        raise ValueError("operator device apply requires vpn.server_public_key")


def run_device_backfill_external(
    *,
    db_copy_path: Path,
    input_path: Path,
    apply: bool,
    pretty: bool = False,
) -> str:
    records = _load_external_backfill_records(input_path)
    planned_devices = [
        _safe_external_backfill_device(record, device_id=None)
        for record in records
    ]

    imported_devices: list[dict[str, object]] = []
    if apply:
        db_copy_path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect(db_copy_path)
        try:
            initialize_schema(conn)
            repo = Repository(conn)
            with repo.transaction():
                for record in records:
                    user_id = repo.upsert_user(
                        telegram_id=int(record["telegram_id"]),
                        username=record["username"],
                        first_name=record["first_name"],
                        last_name=record["last_name"],
                    )
                    server_id = repo.ensure_default_server(
                        name=str(record["server_name"]),
                        network_cidr=str(record["server_network_cidr"]),
                    )
                    device_id = repo.create_external_device(
                        user_id=user_id,
                        server_id=server_id,
                        name=str(record["name"]),
                        duration_days=int(record["duration_days"]),
                        vpn_ip=str(record["vpn_ip"]),
                        peer_public_key=str(record["peer_public_key"]),
                        config_version=str(record["config_version"]),
                        status=str(record["status"]),
                        expires_at=record["expires_at"],
                        revoked_at=record["revoked_at"],
                        revoke_reason=record["revoke_reason"],
                    )
                    imported_devices.append(
                        _safe_external_backfill_device(record, device_id=device_id)
                    )
        finally:
            conn.close()

    payload = {
        "action": "device.external_backfill_rehearsal",
        "mode": "apply" if apply else "dry-run",
        "db_copy": str(db_copy_path),
        "input": str(input_path),
        "records_seen": len(records),
        "records_planned": len(planned_devices),
        "records_imported": len(imported_devices),
        "devices": imported_devices if apply else planned_devices,
        "delivery": {
            "config_resend_available": False,
            "reason": "external_only_material_unavailable",
        },
        "safety": {
            "local_only": True,
            "live_vps_commands": False,
            "config_material_resurrected": False,
            "secret_bearing_output": False,
        },
    }
    return _json_dumps(payload, pretty=pretty)


def run_bot_media_validate(
    *,
    bot_kind: str,
    surface: str,
    path: Path,
    registry_path: Path,
    media_root: Path,
    pretty: bool = False,
) -> str:
    registry = BotMediaRegistry(registry_path=registry_path, media_root=media_root)
    return _json_dumps(
        registry.validate(bot_kind=bot_kind, surface=surface, path=path),
        pretty=pretty,
    )


def run_bot_media_stage(
    *,
    bot_kind: str,
    surface: str,
    path: Path,
    registry_path: Path,
    media_root: Path,
    pretty: bool = False,
) -> str:
    registry = BotMediaRegistry(registry_path=registry_path, media_root=media_root)
    return _json_dumps(
        registry.stage(bot_kind=bot_kind, surface=surface, path=path),
        pretty=pretty,
    )


def run_bot_media_select(
    *,
    bot_kind: str,
    surface: str,
    asset_id: str,
    registry_path: Path,
    media_root: Path,
    pretty: bool = False,
) -> str:
    registry = BotMediaRegistry(registry_path=registry_path, media_root=media_root)
    return _json_dumps(
        registry.select(bot_kind=bot_kind, surface=surface, asset_id=asset_id),
        pretty=pretty,
    )


def run_bot_media_manifest(
    *,
    registry_path: Path,
    media_root: Path,
    pretty: bool = False,
) -> str:
    registry = BotMediaRegistry(registry_path=registry_path, media_root=media_root)
    return _json_dumps(registry.manifest(), pretty=pretty)


def _load_external_backfill_records(input_path: Path) -> list[dict[str, object]]:
    try:
        raw = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON input: {input_path}") from exc
    if not isinstance(raw, list):
        raise ValueError("external backfill input must be a JSON array")

    records: list[dict[str, object]] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"record #{index} must be a JSON object")
        _reject_secret_backfill_fields(item, index=index)
        records.append(_normalize_external_backfill_record(item, index=index))
    return records


def _normalize_external_backfill_record(
    item: dict[str, object],
    *,
    index: int,
) -> dict[str, object]:
    required = ("telegram_id", "name", "vpn_ip", "peer_public_key")
    missing = [field for field in required if field not in item]
    if missing:
        raise ValueError(f"record #{index} missing required fields: {', '.join(missing)}")

    telegram_id = item["telegram_id"]
    if not isinstance(telegram_id, int):
        raise ValueError(f"record #{index} telegram_id must be an integer")

    duration_days = int(item.get("duration_days", 30))
    if duration_days <= 0:
        raise ValueError(f"record #{index} duration_days must be positive")

    status = str(item.get("status", "active"))
    if status not in DEVICE_STATUSES:
        raise ValueError(f"record #{index} unsupported status: {status}")

    config_version = validate_config_version(str(item.get("config_version", "amneziawg_v2")))
    return {
        "telegram_id": telegram_id,
        "username": _optional_str(item.get("username")),
        "first_name": _optional_str(item.get("first_name")),
        "last_name": _optional_str(item.get("last_name")),
        "server_name": str(item.get("server_name", "local")),
        "server_network_cidr": str(item.get("server_network_cidr", "10.8.0.0/24")),
        "name": str(item["name"]),
        "duration_days": duration_days,
        "vpn_ip": str(item["vpn_ip"]),
        "peer_public_key": str(item["peer_public_key"]),
        "config_version": config_version,
        "status": status,
        "expires_at": _optional_str(item.get("expires_at")),
        "revoked_at": _optional_str(item.get("revoked_at")),
        "revoke_reason": _optional_str(item.get("revoke_reason")),
    }


def _reject_secret_backfill_fields(item: dict[str, object], *, index: int) -> None:
    forbidden = {
        "client_private_key",
        "peer_private_key",
        "private_key",
        "preshared_key",
        "peer_private_key_encrypted",
        "preshared_key_encrypted",
        "config",
        "config_text",
        "conf",
        "qr",
        "qr_code",
        "vpn_uri",
        "vpn_url",
    }
    found = sorted(forbidden.intersection(item))
    if found:
        raise ValueError(
            f"record #{index} contains secret-bearing fields: {', '.join(found)}"
        )


def _safe_external_backfill_device(
    record: dict[str, object],
    *,
    device_id: int | None,
) -> dict[str, object]:
    device: dict[str, object] = {
        "name": record["name"],
        "status": record["status"],
        "vpn_ip": record["vpn_ip"],
        "config_version": record["config_version"],
        "config_material_status": "external_only",
        "server_name": record["server_name"],
        "telegram_id": record["telegram_id"],
    }
    if device_id is not None:
        device["id"] = device_id
    return device


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def run_web_password_hash(password: str) -> str:
    if not password.strip():
        raise ValueError("password cannot be blank")
    return create_password_hash(password)


def run_web_server(
    *,
    host: str | None,
    port: int | None,
    settings: Settings | None = None,
    uvicorn_run: Callable[..., Any] | None = None,
) -> None:
    import uvicorn

    from app.web.app import create_web_app

    actual_settings = settings or Settings()
    app = create_web_app(actual_settings)
    runner = uvicorn_run or uvicorn.run
    runner(
        app,
        host=host or actual_settings.web_admin_host,
        port=port or actual_settings.web_admin_port,
    )


def run_api_server(
    *,
    host: str | None,
    port: int | None,
    settings: Settings | None = None,
    uvicorn_run: Callable[..., Any] | None = None,
) -> None:
    import uvicorn

    from app.api import create_api_app

    actual_settings = settings or Settings()
    app = create_api_app(actual_settings)
    runner = uvicorn_run or uvicorn.run
    runner(
        app,
        host=host or actual_settings.api_host,
        port=port or actual_settings.api_port,
    )


def run_api_token_issue(
    *,
    db_path: Path,
    name: str,
    owner_label: str,
    scopes: list[str],
    expires_at: str,
    owner_user_id: int | None = None,
    raw_token: str | None = None,
    pretty: bool = False,
) -> str:
    if not name.strip():
        raise ValueError("token name cannot be blank")
    if not owner_label.strip():
        raise ValueError("owner label cannot be blank")

    actual_expires_at = _parse_api_datetime(expires_at)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        issue = create_route_api_token(
            repo,
            name=name.strip(),
            owner_label=owner_label.strip(),
            owner_user_id=owner_user_id,
            scopes=set(scopes),
            expires_at=actual_expires_at,
            raw_token=raw_token,
        )
    finally:
        conn.close()

    payload = {
        "action": "api_token.issued",
        **issue.safe_metadata(),
        "raw_token": issue.raw_token,
    }
    return _json_dumps(payload, pretty=pretty)


def run_api_token_revoke(
    *,
    db_path: Path,
    token_id: str,
    reason: str,
    revoked_at: str | None = None,
    pretty: bool = False,
) -> str:
    if not token_id.strip():
        raise ValueError("token id cannot be blank")
    if not reason.strip():
        raise ValueError("revoke reason cannot be blank")

    actual_revoked_at = (
        _parse_api_datetime(revoked_at)
        if revoked_at is not None
        else datetime.now(timezone.utc)
    )
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        event = revoke_api_token(
            repo,
            token_id=token_id.strip(),
            revoked_at=actual_revoked_at,
            reason=reason.strip(),
        )
    finally:
        conn.close()

    return _json_dumps(event.safe_metadata(), pretty=pretty)


def run_api_smoke_cycle(
    *,
    db_path: Path,
    base_url: str,
    server_name: str,
    name: str,
    owner_label: str,
    expires_at: str,
    timeout: float = 5.0,
    pretty: bool = False,
    raw_token: str | None = None,
    http_get: Callable[[str, dict[str, str], float], tuple[int, str]] | None = None,
) -> str:
    if not name.strip():
        raise ValueError("token name cannot be blank")
    if not owner_label.strip():
        raise ValueError("owner label cannot be blank")

    actual_expires_at = _parse_api_datetime(expires_at)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        issue = create_route_api_token(
            repo,
            name=name.strip(),
            owner_label=owner_label.strip(),
            owner_user_id=None,
            scopes={"server:read", "metrics:read"},
            expires_at=actual_expires_at,
            raw_token=raw_token,
        )
        try:
            smoke = json.loads(
                run_api_smoke_check(
                    base_url=base_url,
                    token=issue.raw_token,
                    server_name=server_name,
                    timeout=timeout,
                    http_get=http_get,
                )
            )
        finally:
            revoked = revoke_api_token(
                repo,
                token_id=issue.token_id,
                revoked_at=datetime.now(timezone.utc),
                reason="smoke-complete",
            )
    finally:
        conn.close()

    token_metadata = issue.safe_metadata()
    token_metadata["raw_token_display"] = "hidden"
    payload = {
        "action": "api_smoke_cycle.completed",
        "status": smoke["status"],
        "token": token_metadata,
        "smoke": smoke,
        "revoke": revoked.safe_metadata(),
    }
    return _json_dumps(payload, pretty=pretty)


def run_api_smoke_check(
    *,
    base_url: str,
    token: str,
    server_name: str,
    timeout: float = 5.0,
    pretty: bool = False,
    http_get: Callable[[str, dict[str, str], float], tuple[int, str]] | None = None,
) -> str:
    if not token.strip():
        raise ValueError("token cannot be blank")
    if not server_name.strip():
        raise ValueError("server name cannot be blank")

    getter = http_get or _api_http_get
    root = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token.strip()}"}
    responses: dict[str, dict[str, object]] = {}
    for name, path in _api_smoke_paths(server_name.strip()).items():
        status_code, body = getter(f"{root}{path}", headers, timeout)
        responses[name] = {
            "status_code": status_code,
            "body": _parse_json_body(body),
        }

    return _json_dumps(validate_api_smoke_responses(responses), pretty=pretty)


def run_agent_token_hash(raw_token: str) -> str:
    if not raw_token.strip():
        raise ValueError("token cannot be blank")
    return hash_agent_token(raw_token.strip())


def run_agent_server(
    *,
    host: str | None,
    port: int | None,
    settings: Settings | None = None,
    uvicorn_run: Callable[..., Any] | None = None,
) -> None:
    import uvicorn

    actual_settings = settings or Settings()
    tokens = build_agent_tokens(actual_settings)
    server_config = select_server(
        load_server_config(actual_settings.server_config_path),
        actual_settings.server_name,
    )
    app = create_agent_app(
        adapter=LocalCommandRuntimeAdapter(server_config),
        tokens=tokens,
        audit_sink=RepositoryAgentAuditSink(actual_settings.database_path),
        build_version=__version__,
    )
    runner = uvicorn_run or uvicorn.run
    runner(
        app,
        host=host or actual_settings.local_agent_host,
        port=port or actual_settings.local_agent_port,
    )


def _read_agent_token(token: str | None) -> str:
    if token is not None:
        return token
    first = getpass.getpass("Local Agent token: ")
    second = getpass.getpass("Repeat Local Agent token: ")
    if first != second:
        raise ValueError("tokens do not match")
    return first


def _read_web_password(password: str | None) -> str:
    if password is not None:
        return password
    first = getpass.getpass("Web admin password: ")
    second = getpass.getpass("Repeat web admin password: ")
    if first != second:
        raise ValueError("passwords do not match")
    return first


def _parse_api_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO datetime: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def require_vps_apply_enabled_for_cli_apply() -> None:
    settings = Settings()
    if not settings.vps_apply_enabled:
        raise SystemExit(
            "VPS_APPLY_ENABLED=true is required for live server peer mutations. "
            "Use --dry-run or open the named live apply gate first."
        )


def read_preshared_key_arg(args: argparse.Namespace) -> str:
    if getattr(args, "preshared_key_stdin", False):
        value = sys.stdin.readline().rstrip("\r\n")
        if not value:
            raise SystemExit("--preshared-key-stdin requires a non-empty preshared key on stdin")
        return value
    return str(args.preshared_key)


def _json_dumps(payload: object, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _api_smoke_paths(server_name: str) -> dict[str, str]:
    return {
        "servers": "/api/servers",
        "integration_status": "/api/integration/status",
        "local_agent_runtime_summary": "/api/local-agent/runtime/summary",
        "server_summary": f"/api/servers/{server_name}/summary",
        "metrics_summary": "/api/metrics/summary",
        "users_summary": "/api/users/summary",
    }


def _api_http_get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, str]:
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", errors="replace")


def _parse_json_body(body: str) -> object:
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def run_server_check(server: ServerConfig, *, dry_run: bool) -> str:
    if dry_run:
        lines = [
            f"Dry-run server check: {server.name}",
            "No changes will be made.",
            f"Target: ssh {server.ssh.user}@{server.ssh.host} -p {server.ssh.port}",
            "Read-only commands:",
        ]
        lines.extend(f"- {command}" for command in planned_check_commands(server))
        return "\n".join(lines)

    report = run_server_checks(server, SystemSshClient(server))
    return report.to_text()


def run_server_traffic_collection_dry_run(server: ServerConfig) -> str:
    if server.runtime.type == "docker":
        container = server.runtime.container_name or "<missing-container>"
        return "\n".join(
            [
                f"Dry-run traffic collection: {server.name}",
                "No changes will be made.",
                f"Target: ssh {server.ssh.user}@{server.ssh.host} -p {server.ssh.port}",
                f"Read-only command: docker exec {container} awg show {server.vpn.interface} dump",
                "Known peers will be stored in the local database as traffic snapshots.",
                "Unknown peers will be reported for manual import/review.",
            ]
        )
    return "\n".join(
        [
            f"Dry-run traffic collection: {server.name}",
            "No changes will be made.",
            f"Target: ssh {server.ssh.user}@{server.ssh.host} -p {server.ssh.port}",
            f"Read-only command: awg show {server.vpn.interface} dump",
        ]
    )


def run_server_traffic_collection(server: ServerConfig, *, db_path: Path) -> str:
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    server_id = _sync_server_row(repo, server)
    report = TrafficService(repo).collect_and_store(
        server_id,
        AwgDumpTrafficCollector(
            interface=server.vpn.interface,
            source=f"awg:{server.name}",
            container_name=server.runtime.container_name
            if server.runtime.type == "docker"
            else None,
            ssh_client=SystemSshClient(server),
        ),
    )
    return (
        f"Traffic collection stored snapshots: {report.stored_count}\n"
        f"Unknown peers: {len(report.unknown_peers)}"
    )


def run_server_peer_sync(server: ServerConfig, *, db_path: Path) -> str:
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    server_id = _sync_server_row(repo, server)
    report = PeerInventoryService(repo).compare(
        server_id,
        AwgDumpPeerInventoryCollector(
            interface=server.vpn.interface,
            container_name=server.runtime.container_name
            if server.runtime.type == "docker"
            else None,
            ssh_client=SystemSshClient(server),
        ),
    )
    lines = [
        f"Peer sync report: {server.name}",
        f"known remote peers: {len(report.known_remote_peers)}",
        f"unknown remote peers: {len(report.unknown_remote_peers)}",
        f"missing local peers: {len(report.missing_local_peers)}",
    ]
    if report.unknown_remote_peers:
        lines.append("Unknown remote peers:")
        lines.extend(
            f"- {peer.peer_public_key} {peer.allowed_ips}"
            for peer in report.unknown_remote_peers
        )
    if report.missing_local_peers:
        lines.append("Missing local peers:")
        lines.extend(
            f"- device #{peer.device_id} {peer.device_name} {peer.peer_public_key} {peer.vpn_ip}/32"
            for peer in report.missing_local_peers
        )
    return "\n".join(lines)


def _sync_server_row(repo: Repository, server: ServerConfig) -> int:
    return repo.upsert_server_config(
        name=server.name,
        host=server.ssh.host,
        ssh_port=server.ssh.port,
        endpoint_host=server.vpn.endpoint_host,
        vpn_port=int(server.vpn.port),
        vpn_network_cidr=server.vpn.network_cidr,
        server_address=server.vpn.server_address,
        server_public_key=server.vpn.server_public_key or "",
        runtime=server.runtime.type,
        firewall=server.firewall.provider,
        max_devices=server.vpn.max_devices,
    )


def run_server_preflight(
    *,
    config_path: Path,
    server_name: str,
    db_path: Path,
) -> str:
    config = load_server_config(config_path)
    server = select_server(config, server_name)
    _validate_preflight_server(server)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    repo.upsert_server_config(
        name=server.name,
        host=server.ssh.host,
        ssh_port=server.ssh.port,
        endpoint_host=server.vpn.endpoint_host,
        vpn_port=int(server.vpn.port),
        vpn_network_cidr=server.vpn.network_cidr,
        server_address=server.vpn.server_address,
        server_public_key=server.vpn.server_public_key or "",
        runtime=server.runtime.type,
        firewall=server.firewall.provider,
        max_devices=server.vpn.max_devices,
    )
    apply_dry_run = build_peer_apply_dry_run(
        server,
        PeerApplyInput(
            public_key="PREFLIGHT_PEER_PUBLIC_KEY",
            preshared_key="PREFLIGHT_PSK",
            vpn_ip=_preflight_peer_ip(server),
        ),
    )
    revoke_dry_run = build_peer_revoke_dry_run(
        server,
        "PREFLIGHT_PEER_PUBLIC_KEY",
    )
    traffic_dry_run = run_server_traffic_collection_dry_run(server)
    return "\n".join(
        [
            f"Preflight report: {server.name}",
            "server config: ok",
            "database sync: ok",
            "server check dry-run: ok",
            _indent(run_server_check(server, dry_run=True)),
            "peer apply dry-run: ok",
            _indent(apply_dry_run),
            "peer revoke dry-run: ok",
            _indent(revoke_dry_run),
            "traffic dry-run: ok",
            _indent(traffic_dry_run),
            "backup target: ok",
            "Next: keep VPS_APPLY_ENABLED=false until live checks pass.",
        ]
    )


def run_server_retest_plan(
    *,
    config_path: Path,
    server_name: str,
    db_path: Path,
) -> str:
    config = load_server_config(config_path)
    server = select_server(config, server_name)
    lines = [
        f"VPS retest plan: {server.name}",
        f"runtime: {server.runtime.type}",
        f"container: {server.runtime.container_name or '-'}",
        f"config_path: {server.runtime.config_path or '-'}",
        "",
        "1. Update code:",
        "cd /home/amn2",
        "git pull origin codex-vps-test-prep",
        "git log -1 --oneline",
        "source venv/bin/activate",
        "python -m pip install -e .",
        "",
        "2. Keep peer writes disabled until read-only checks pass:",
        "VPS_APPLY_ENABLED=false",
        "",
        "3. Run read-only checks:",
        "python -m app.cli bot check-network",
        f"python -m app.cli server preflight --config {config_path} --server {server.name} --db {db_path}",
        f"python -m app.cli server check --config {config_path} --server {server.name} --dry-run",
        f"python -m app.cli server check --config {config_path} --server {server.name}",
        f"python -m app.cli server sync-peers --config {config_path} --server {server.name} --db {db_path}",
        _runtime_check_command(server),
        "",
        "4. Run read-only API smoke:",
        "Terminal A:",
        "python -m app.cli api serve --host 127.0.0.1 --port 3040",
        "Terminal B:",
        f"python -m app.cli api smoke-cycle --db {db_path} --base-url http://127.0.0.1:3040 --server-name {server.name} --name vps-smoke --owner-label ops --expires-at \"$(date -u -d '+7 days' '+%Y-%m-%dT%H:%M:%S+00:00')\" --pretty",
        "Expected safe result: status=passed, checked_routes: 6, raw token is hidden and revoked automatically.",
        "Do not send raw API token, token hash, Authorization header, .conf, QR, vpn://, PrivateKey, or PresharedKey.",
        "",
        "5. Restart or inspect services:",
        "sudo systemctl restart amneziya-web",
        "sudo systemctl restart amneziya-bot",
        "sudo systemctl status amneziya-web --no-pager",
        "sudo systemctl status amneziya-bot --no-pager",
        "curl -i http://127.0.0.1:3030/login",
        "tail -n 200 logs/app.log",
        "",
        "6. Manual checklist:",
        "- open web server detail and run health check",
        "- run peer sync and review Amnezia-created peers",
        "- approve one test order",
        "- verify new peer IP follows live AllowedIPs",
        "- test Disable VPN, then Enable VPN for the same device",
        "- test email config/recovery only after email is verified",
        "",
        "7. If it fails, collect safe logs:",
        _debug_snapshot_command(server),
        "sudo journalctl -u amneziya-web -n 200 --no-pager",
        "sudo journalctl -u amneziya-bot -n 200 --no-pager",
        "Do not send tokens, APP_SECRET_KEY, SSH secrets, PrivateKey, or PresharedKey.",
    ]
    return "\n".join(lines)


def run_fresh_install_wizard(*, pretty: bool = False) -> str:
    answers = collect_fresh_install_answers()
    return _json_dumps(build_fresh_install_plan(answers), pretty=pretty)


def run_fresh_install_plan(*, answers_path: Path, pretty: bool = False) -> str:
    answers = json.loads(answers_path.read_text(encoding="utf-8"))
    if not isinstance(answers, dict):
        raise ValueError("answers file must contain a JSON object")
    return _json_dumps(build_fresh_install_plan(answers), pretty=pretty)


def _runtime_check_command(server: ServerConfig) -> str:
    if server.runtime.type == "docker":
        container = server.runtime.container_name or "<container>"
        return (
            f"AMN_RUNTIME=docker AMN_CONTAINER_NAME={container} "
            f"AMN_INTERFACE={server.vpn.interface} bash deploy/runtime/check_vps.sh"
        )
    return "bash deploy/runtime/check_vps.sh"


def _debug_snapshot_command(server: ServerConfig) -> str:
    if server.runtime.type == "docker":
        container = server.runtime.container_name or "<container>"
        return (
            f"AMN_RUNTIME=docker AMN_CONTAINER_NAME={container} "
            f"AMN_INTERFACE={server.vpn.interface} "
            "bash deploy/runtime/collect_debug_snapshot.sh"
        )
    return "bash deploy/runtime/collect_debug_snapshot.sh"


def _validate_preflight_server(server: ServerConfig) -> None:
    if server.vpn.port == "auto":
        raise ValueError("server preflight requires a fixed vpn.port before live VPS test")
    if not server.vpn.server_public_key:
        raise ValueError("server preflight requires vpn.server_public_key")


def _preflight_peer_ip(server: ServerConfig) -> str:
    import ipaddress

    network = ipaddress.ip_network(server.vpn.network_cidr, strict=False)
    server_ip = ipaddress.ip_interface(server.vpn.server_address).ip
    for address in network.hosts():
        if address != server_ip:
            return str(address)
    raise ValueError("server network has no free preflight peer IP")


def _indent(value: str) -> str:
    return "\n".join(f"  {line}" for line in value.splitlines())


if __name__ == "__main__":
    main()
