# Политика backup/import

Дата: 2026-06-01.

Статус: local-only no-route contract.

Этот slice добавляет только контракт безопасности для будущих backup/import операций. Он не добавляет `/api/*`, web-route, Local Agent `/backup`, Local Agent `/restore`, публичный импорт, автоматический restore apply, live VPS вызовы или копирование upstream-кода.

## Режимы backup

- `metadata-export` - безопасный режим по умолчанию для будущих web/API оболочек. Содержит только schema metadata, table counts и policy manifest. Не содержит строк БД и не может восстановить токены или client config secrets.
- `redacted-backup` - будущий redacted state export. Требует шифрования, но исключает token hashes, peer private keys, PSK, admin password hash, `.conf`, QR payload/PNG и `vpn://` import links. Restore остается только preview-only.
- `encrypted-full-backup` - dangerous full state export. Требует явного dangerous confirmation, не является default web/API режимом и все равно не разрешает restore apply этим slice.

## Secret-bearing state

Контракт явно выделяет и блокирует для safe/redacted режимов:

- `api_tokens.token_hash`;
- `config_share_tokens.token_hash`;
- `email_recovery_tokens.token_hash`;
- `devices.peer_private_key_encrypted`;
- `devices.preshared_key_encrypted`;
- `web_admin_password_hash`;
- generated config artifacts: `.conf`, QR payload, QR PNG, `vpn://` import links.

Safe metadata и preview не должны возвращать raw token, token hash, private key, PSK, `.conf`, QR payload/image или `vpn://`.

## Restore/import preview

`create_restore_preview()` и `create_import_preview()` возвращают только counts, warnings и operation status:

- `status=preview-only`;
- `apply_allowed=false`;
- `side_effects=[]`;
- target state conflicts отображаются как warning;
- restore/import apply остается blocked.

Preview не пишет БД, не создает backup-файл и не меняет VPS/runtime состояние.

## Surface policy

В `SurfacePolicy` добавлены blocked-future записи:

- `backup.metadata_export.blocked`;
- `backup.redacted_create.blocked`;
- `backup.encrypted_full_create.blocked`;
- `restore.preview.blocked`;
- `restore.apply.blocked`;
- `import.existing_state_preview.blocked`;
- `import.existing_state_apply.blocked`.

Эти записи нужны как gate перед будущими route/API/Local Agent решениями. Они не монтируют новые runtime routes и не расширяют текущую поверхность.

## VPS gate

VPS gate для этого slice не нужен: поведение peer apply/revoke/config delivery/sync/runtime не меняется. Реальный VPS понадобится только когда будет отдельный apply-slice, который меняет live state или восстанавливает рабочее окружение после import/restore.
