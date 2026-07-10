# Operator single-device create

Команда `device create-operator` предоставляет поддерживаемый operator-only путь
создания ровно одного peer и приватного `.conf` без выбора первого попавшегося
пользователя и без импорта приватных helper-функций.

## Границы

- owner задаётся явно через `--owner-user-id` и должен существовать в БД со
  статусом `active`;
- server, device name, duration, config version, admin actor и output path
  задаются явно;
- применяется общий `AccessService`: device-limit, IP allocation, encrypted
  config material, peer apply и admin audit не обходятся;
- config payload никогда не печатается в stdout;
- output создаётся без перезаписи существующего файла, атомарно и с режимом
  `0600` на POSIX;
- apply на Windows блокируется, потому что POSIX mode не гарантирует Windows
  DACL;
- `--execution-target local` используется внутри target VPS без self-SSH;
- `--execution-target remote-ssh` используется с отдельного POSIX operator host;
- `--apply` дополнительно требует `VPS_APPLY_ENABLED=true` и отдельный exact
  one-device gate;
- команда не изменяет существующий device `8` и не выполняет Android TV import.

## Dry-run

Dry-run не читает secrets, не пишет БД, не создаёт файл и не применяет peer:

```bash
python -m app.cli device create-operator \
  --db data/amneziya.sqlite3 \
  --config servers.yml \
  --server local \
  --owner-user-id <EXPLICIT_OWNER_USER_ID> \
  --name Neobyatnaya-AMNZ-N-android-tv-02 \
  --duration-days 365 \
  --config-version amneziawg_v2 \
  --output /root/private-configs/Neobyatnaya-AMNZ-N-android-tv-02.conf \
  --admin-telegram-id <EXPLICIT_ADMIN_TELEGRAM_ID> \
  --execution-target local \
  --dry-run \
  --pretty
```

Safe dry-run output содержит только plan metadata и
`config_payload_output=false`.

## Apply

Apply разрешён только после проверки dry-run и отдельного exact gate:

```bash
export VPS_APPLY_ENABLED=true
python -m app.cli device create-operator \
  --db data/amneziya.sqlite3 \
  --config servers.yml \
  --server local \
  --owner-user-id <EXPLICIT_OWNER_USER_ID> \
  --name Neobyatnaya-AMNZ-N-android-tv-02 \
  --duration-days 365 \
  --config-version amneziawg_v2 \
  --output /root/private-configs/Neobyatnaya-AMNZ-N-android-tv-02.conf \
  --admin-telegram-id <EXPLICIT_ADMIN_TELEGRAM_ID> \
  --execution-target local \
  --apply \
  --pretty
```

Команда откажется перезаписывать существующий output. При remote peer success и
последующей local/artifact/audit failure она возвращает
`RemoteOperationPartialFailure`; где audit backend доступен, дополнительно
сохраняется `access.create_operator_device.partial_failure` с safe recovery
metadata.

## Проверка после apply

До client acceptance результат означает только server-side preparation. Статус
`working-config-pass` разрешён после Android import/connect, свежего handshake и
ненулевого traffic evidence для конкретного device.
