# Runtime Registry

Этот документ фиксирует, какие runtime-зависимости нужны проекту Amneziya, где они описаны в репозитории и как быстро проверить VPS перед повторным тестом.

## Что храним в Git

В репозитории храним только легкие и проверяемые артефакты:

- `deploy/runtime/manifest.yml` - единый manifest runtime-требований;
- `deploy/runtime/check_vps.sh` - read-only проверка VPS;
- `deploy/runtime/collect_debug_snapshot.sh` - read-only сбор диагностического snapshot;
- `deploy/examples/servers.host_systemd.example.yml` - пример `servers.yml` для host/systemd;
- `deploy/examples/servers.docker.example.yml` - пример `servers.yml` для Docker runtime;
- `deploy/examples/.env.production.example` - полный production-шаблон `.env` без реальных секретов;
- `deploy/examples/nginx-proxy-manager-notes.ru.md` - памятка по reverse proxy для web-панели.

## SSH auth

Рекомендуемый режим для live health check и будущего apply/revoke - SSH key auth:

```yaml
ssh:
  auth:
    type: key
    private_key_path: /root/.ssh/id_ed25519
```

Password auth тоже поддержан, но требует `sshpass` на сервере, где запущен бот/web-панель:

```bash
sudo apt-get update
sudo apt-get install -y sshpass
```

В `servers.yml`:

```yaml
ssh:
  auth:
    type: password
```

В `.env`:

```env
VPS_SSH_PASSWORD=CHANGE_ME_REAL_SSH_PASSWORD
```

Пароль передается в `sshpass` через переменную `SSHPASS`, не через аргументы командной строки. Если `VPS_SSH_PASSWORD` не задан или `sshpass` не установлен, live health check вернет понятную ошибку до выполнения удаленных команд.

## Не храним в Git

Не храним в Git:

- настоящий `.env`;
- настоящий `servers.yml`;
- SSH private keys;
- Telegram bot token;
- `APP_SECRET_KEY`;
- SQLite database;
- backup archives;
- generated client `.conf`;
- QR images;
- Docker images;
- `.venv`, `.codex_deps`, `node_modules`;
- логи с приватными данными.

### Secret-bearing delivery artifacts

`.conf`, QR payload/PNG и `vpn://` import link считаются `client-config-secret`.
Их нельзя включать в runtime diagnostics, plain backups, audit metadata, logs или error output.
Если такой artifact попадает в текстовый diagnostic output, он должен проходить через `app.security.redaction.redact()`.

Если позже понадобится закреплять тяжелые бинарные артефакты, используем GitHub Releases или отдельное хранилище, а в репозитории держим URL, версию и checksum.

## Runtime modes

### `host_systemd`

AmneziaWG работает на хосте Debian и управляется через `systemd`, `awg`, `awg-quick`.

Минимальный блок:

```yaml
runtime:
  type: host_systemd
  service_name: awg-quick@awg0
```

Read-only проверки:

```bash
command -v systemctl
command -v awg
command -v awg-quick
systemctl is-active awg-quick@awg0
awg show awg0
ss -lun
```

### `docker`

AmneziaWG работает внутри Docker-контейнера. Health check и sync/traffic читают состояние через `docker exec`. Peer apply/revoke для Docker меняют постоянный конфиг внутри контейнера и затем перезапускают контейнер.

Минимальный блок:

```yaml
runtime:
  type: docker
  container_name: amnezia-awg
  config_path: /opt/amnezia/awg/awg0.conf
```

Read-only проверки:

```bash
command -v docker
docker ps --format '{{.Names}}'
docker exec amnezia-awg awg show awg0
ss -lun
```

## Первый slice `RemoteOperationRunner`

Server health checks используют первый slice `RemoteOperationRunner`:

- risk class: `read-only-remote`;
- command policy: существующий read-only allowlist;
- remote side effects: отсутствуют;
- local side effects: health snapshot и admin audit event при запуске из web;
- consistency status: `read-only`.

Этот slice не включает peer apply/revoke, Docker config writes, firewall changes или destructive operations.

Для Docker `apply-peer` и `revoke-peer` доступны только при заполненном `runtime.config_path`: приложение переписывает этот файл внутри контейнера и выполняет `docker restart <container_name>`. `collect-traffic` и `sync-peers` остаются read-only и читают `awg show <interface> dump`.

## Local gate для state-changing remote operations

Перед любым live VPS apply/revoke state-changing операция должна пройти локальный gate:

- `remote-state-write` и `destructive-remote` операции описывают `operation_id`, `risk_class`, `consistency_status`, `local_side_effects`, `remote_side_effects`, `rollback_note` и `idempotency_key`;
- `RemoteOperationRunner.plan()` для state-changing операций возвращает preview со статусом `consistency_status=dry-run`, без выполнения SSH;
- `OperationPlan.to_safe_metadata()` не публикует command strings, а `audit_summary`, `rollback_note` и idempotency metadata пропускает через redaction;
- `apply-peer` и `revoke-peer` dry-run preview показывают operation ID, risk class, side effects и rollback note, но не раскрывают PSK, private key, `.conf` или `vpn://`;
- real VPS gate начинается только после focused tests и полного локального `pytest tests -v`.

Этот gate не заменяет live проверку. Он нужен, чтобы live проверка была узкой, воспроизводимой и заранее имела rollback/recovery context.

## Быстрая проверка VPS

Скопировать или запустить из репозитория:

```bash
cd /opt/amn2
bash deploy/runtime/check_vps.sh
```

Для Docker runtime:

```bash
cd /opt/amn2
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/check_vps.sh
```

Для нестандартного порта web-панели или VPN:

```bash
AMN_WEB_PORT=3030 AMN_VPN_PORT=30001 bash deploy/runtime/check_vps.sh
```

Скрипт не устанавливает пакеты, не меняет firewall, не перезапускает сервисы и не пишет файлы. Он только читает состояние VPS и возвращает код `1`, если есть критические ошибки.

## Диагностический snapshot

Когда нужно прислать полный отчет с VPS:

```bash
cd /opt/amn2
bash deploy/runtime/collect_debug_snapshot.sh
```

Для Docker runtime:

```bash
cd /opt/amn2
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/collect_debug_snapshot.sh
```

Подробный список команд и правила маскировки секретов описаны в `docs/VPS_LOG_COLLECTION.ru.md`.

## Как актуализировать

Когда появляется новая обязательная зависимость:

1. Добавить ее в `deploy/runtime/manifest.yml`.
2. Добавить read-only проверку в `deploy/runtime/check_vps.sh`.
3. Обновить пример в `deploy/examples/`, если меняется конфигурация.
4. Обновить этот документ.
5. Добавить или обновить тест в `tests/deploy/test_runtime_registry.py`.

Так мы сохраняем знания внутри проекта, но не превращаем Git-репозиторий в склад бинарников.
