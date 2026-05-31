# Протокол повторного VPS-теста

Короткий порядок действий перед следующим заходом на живой VPS. Цель - обновить сервер до последней версии ветки, проверить базовые зависимости, выполнить read-only проверки и при ошибке собрать полный snapshot.

## 1. Обновить код на VPS

```bash
cd /opt/amn2
git pull origin codex-vps-test-prep
git log -1 --oneline
source venv/bin/activate
python -m pip install -e .
python -m app.cli server retest-plan --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
```

Сохранить вывод `git log -1 --oneline`: по нему мы понимаем, действительно ли на сервере последняя сборка.
Команда `server retest-plan` печатает короткий порядок повторного прогона для выбранного сервера и не меняет VPS.

Если соседний API/VPS gate должен проверить remote-operation dry-run/audit срез до слияния в `codex-vps-test-prep`, использовать интеграционную ветку:

```bash
cd /opt/amn2
git fetch origin codex/vps-gate-remote-ops-integration
git switch codex/vps-gate-remote-ops-integration
git pull origin codex/vps-gate-remote-ops-integration
git log -1 --oneline
source venv/bin/activate
python -m pip install -e .
```

Эта ветка собрана от актуального API-head и включает remote-operation contract, partial-failure model, dry-run/audit metadata и Runtime Registry local gate. Не смешивать выводы этого gate с обычным `codex-vps-test-prep`: в отчете обязательно указать branch и commit hash.

## 2. Проверить окружение перед запуском

```bash
python -m app.cli bot check-network
python -m app.cli server preflight --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run
bash deploy/runtime/check_vps.sh
```

Если в `servers.yml` стоит `ssh.auth.type: password`, перед live health check проверить:

```bash
command -v sshpass
grep '^VPS_SSH_PASSWORD=' .env
```

Если `sshpass` не установлен:

```bash
sudo apt-get update
sudo apt-get install -y sshpass
```

Для Docker-ноды вместо обычного runtime-check:

```bash
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg bash deploy/runtime/check_vps.sh
```

До успешных проверок держать:

```env
VPS_APPLY_ENABLED=false
```

## 3. Remote-operation dry-run/audit gate

До любого live `apply-peer --apply` или `revoke-peer --apply` выполнить только preview-команды на тестовом peer:

```bash
python -m app.cli server apply-peer --config servers.yml --server debian-vps-1 --public-key TEST_PEER_PUBLIC_KEY --preshared-key TEST_PEER_PSK --vpn-ip TEST_VPN_IP --dry-run
python -m app.cli server revoke-peer --config servers.yml --server debian-vps-1 --public-key TEST_PEER_PUBLIC_KEY --dry-run
```

В выводе `apply-peer --dry-run` должны быть:

```text
Operation ID: server.peer.apply
Risk class: remote-state-write
Consistency status: dry-run
Remote side effects:
Rollback note:
```

В выводе `revoke-peer --dry-run` должны быть:

```text
Operation ID: server.peer.revoke
Risk class: remote-state-write
Consistency status: dry-run
Remote side effects:
Rollback note:
```

В выводе не должно быть `TEST_PEER_PSK`, `PrivateKey`, `PresharedKey`, полного `.conf` или `vpn://`.

Live `apply-peer --apply` и `revoke-peer --apply` запускать только после отдельного подтверждения оператора в соседнем чате. Для Docker runtime перед этим еще раз проверить, что `runtime.config_path` указывает на реальный persistent config внутри контейнера.

## 4. Запустить нужный сценарий теста

Проверить web-панель:

```bash
python -m app.cli web serve --host 0.0.0.0 --port 3030
```

Проверить бота:

```bash
python -m app.main
```

Если сервисы уже запущены через systemd:

```bash
sudo systemctl status amneziya-web --no-pager
sudo systemctl status amneziya-bot --no-pager
```

В Telegram или web-панели записать, что нажимал перед ошибкой: раздел, кнопка, пользователь, устройство, сервер, примерное время.
В карточке сервера web-панель показывает блок `VPS retest bundle` с теми же базовыми командами для `git pull`, `preflight`, `server check` и `sync-peers`.

## 5. При ошибке собрать snapshot

Обычный runtime:

```bash
bash deploy/runtime/collect_debug_snapshot.sh
```

Docker runtime:

```bash
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/collect_debug_snapshot.sh
```

Если нужно сохранить в файл:

```bash
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/collect_debug_snapshot.sh > debug-snapshot.txt 2>&1
```

Перед отправкой файла проверить, что секреты скрыты. Правила маскировки и ручной набор команд описаны в `docs/VPS_LOG_COLLECTION.ru.md`.

## 6. Что прислать для анализа

Прислать:

- branch и commit hash из `git log -1 --oneline`;
- последний commit hash из `git log -1 --oneline`;
- вывод `python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run`;
- вывод `apply-peer --dry-run` и `revoke-peer --dry-run` с проверкой, что секреты скрыты;
- вывод `python -m app.cli server check --config servers.yml --server debian-vps-1`, если запускался;
- вывод `bash deploy/runtime/check_vps.sh` или Docker-варианта;
- debug snapshot из `deploy/runtime/collect_debug_snapshot.sh`;
- последние строки `logs/app.log`, если snapshot не собрался;
- что нажимал перед ошибкой и в какое время.

Не присылать без маскировки:

- `TELEGRAM_BOT_TOKEN`;
- `APP_SECRET_KEY`;
- `WEB_ADMIN_PASSWORD_HASH`;
- `WEB_ADMIN_SESSION_SECRET`;
- `SMTP_PASSWORD`;
- SSH private key;
- `PrivateKey` и `PresharedKey`;
- полный пользовательский `.conf`.

## 7. Когда останавливаемся

Если ошибка относится к Docker `apply-peer` или `revoke-peer`, перед повтором проверить `runtime.config_path` в `servers.yml`: он должен указывать на реальный постоянный конфиг AmneziaWG внутри контейнера. Эти операции переписывают конфиг и выполняют `docker restart <container_name>`, поэтому не включать `VPS_APPLY_ENABLED=true`, пока dry-run и ручной тестовый peer не пройдены.
