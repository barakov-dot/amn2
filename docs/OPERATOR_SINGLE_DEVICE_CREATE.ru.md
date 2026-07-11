# Operator single-device create

Команда `device create-operator` предоставляет поддерживаемый operator-only путь
создания ровно одного peer и приватного `.conf` без выбора первого попавшегося
пользователя и без импорта приватных helper-функций.

## Границы

- owner задаётся явно через `--owner-user-id` и должен существовать в БД со
  статусом `active`;
- режим по умолчанию `dedicated_device`: один peer и один `.conf` для одного
  физического устройства;
- `owner_shared` создаёт один общий peer/`.conf`, разрешён только для active
  admin owner и не позволяет серверу достоверно ограничить число физических
  устройств;
- обычное одобрение клиентской заявки всегда создаёт `dedicated_device`;
- клиентская квота равна меньшему из `MAX_DEVICES_PER_USER` и
  `plans.max_devices`, если лимит задан в тарифе;
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
  --assignment-mode dedicated_device \
  --output /root/private-configs/Neobyatnaya.NET-android-tv-02.conf \
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
  --assignment-mode dedicated_device \
  --output /root/private-configs/Neobyatnaya.NET-android-tv-02.conf \
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

## Приватная web-панель

На странице пользователя доступен тот же operator-only путь через
`POST /users/{user_id}/devices/create-operator`.

Web adapter не реализует создание устройства повторно. Он делегирует общему
`run_operator_device_create(...)` и
`AccessService.create_operator_device(...)`, которые используются CLI.

Dry-run не изменяет БД, peer или artifact. Apply требует одновременно:

```text
authenticated web-admin session
valid CSRF token
active explicit owner
configured authorized ADMIN_TELEGRAM_IDS actor
VPS_APPLY_ENABLED=true
OPERATOR_DEVICE_CREATE_ENABLED=true
explicit exact config-assignment confirmation
```

`OPERATOR_DEVICE_CREATE_ENABLED` по умолчанию равен `false` и не зависит от
общего VPS apply gate. Поэтому разрешение других VPS-операций не открывает
создание operator device автоматически.

Путь приватного config artifact генерируется на сервере под runtime-каталогом
БД. HTML содержит только safe metadata, без config text, private key и PSK.
Remote-applied/local-failed результат возвращает фиксированный `409` и пишет
структурированную redacted metadata без recovery note.

Route зарегистрирован как `web.devices.create_operator` в runtime surface
policy. Он не открывает public или self-service write API.

## Проверка после apply

До client acceptance результат означает только server-side preparation. Статус
`working-config-pass` разрешён после Android import/connect, свежего handshake и
ненулевого traffic evidence для конкретного device.

На реальных устройствах 2026-07-11 один стандартный AmneziaWG `.conf` прошёл
подключение и трафик в AmneziaVPN на Android TV, DefaultVPN на iOS и AmneziaVPN
на Windows 11. Native `.vpn` JSON на Android TV импортировался, но зависал на
подключении, поэтому рекомендуемый кросс-клиентский артефакт остаётся `.conf`.

Одновременная работа нескольких собственных устройств с одним peer наблюдалась,
но не является гарантией стабильной конкуренции endpoint. Для клиента с лимитом
6 устройств нужно создать 6 `dedicated_device` peer и 6 отдельных конфигов.
