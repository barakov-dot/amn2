# Установка и настройка web-панели и Telegram-бота

Документ описывает ручной запуск на VPS для ветки `codex-vps-test-prep`.

Порядок безопасной настройки:

1. Подготовить проект и `.env`.
2. Запустить и проверить web-панель вручную.
3. Запустить и проверить Telegram-бота вручную.
4. Только после ручной проверки включить `systemd`-сервисы.

## 1. Подготовить проект на VPS

Если проект еще не склонирован:

```bash
git clone -b codex-vps-test-prep https://github.com/barakov-dot/amn2.git /opt/amn2
cd /opt/amn2
```

Если проект уже есть:

```bash
cd /opt/amn2
git pull origin codex-vps-test-prep
```

Подготовить Python-окружение:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

Создать рабочие директории:

```bash
mkdir -p data logs backups config_templates
```

Проверить runtime VPS без изменений сервера можно отдельным read-only скриптом:

```bash
bash deploy/runtime/check_vps.sh
```

Для Docker-ноды:

```bash
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg bash deploy/runtime/check_vps.sh
```

Если нужно собрать полный отчет для диагностики:

```bash
bash deploy/runtime/collect_debug_snapshot.sh
```

Для Docker-ноды:

```bash
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg bash deploy/runtime/collect_debug_snapshot.sh
```

Если приложение запускается от пользователя `amneziya`:

```bash
sudo chown -R amneziya:amneziya /opt/amn2/data /opt/amn2/logs /opt/amn2/backups /opt/amn2/config_templates
```

## 2. Подготовить `.env`

Создать файл, если его еще нет:

```bash
cp .env.example .env
```

Файл `.env` не коммитить в GitHub. В нем хранятся токены, пароли, ключи и адреса.

Минимальная база для web-панели и бота:

```env
TELEGRAM_BOT_TOKEN=CHANGE_ME_TOKEN_FROM_BOTFATHER
TELEGRAM_PROXY_URL=
APP_SECRET_KEY=CHANGE_ME_GENERATED_RANDOM_SECRET_32_PLUS_CHARS
ADMIN_TELEGRAM_IDS=CHANGE_ME_ADMIN_TELEGRAM_IDS

DATABASE_PATH=data/amneziya.sqlite3
SERVER_CONFIG_PATH=servers.yml
SERVER_NAME=debian-vps-1
VPS_APPLY_ENABLED=false

WEB_ADMIN_ENABLED=true
WEB_ADMIN_HOST=127.0.0.1
WEB_ADMIN_PORT=3030
WEB_ADMIN_USERNAME=admin
WEB_ADMIN_PASSWORD_HASH=CHANGE_ME_HASH
WEB_ADMIN_SESSION_SECRET=CHANGE_ME_RANDOM_SECRET_32_PLUS_CHARS
WEB_ADMIN_SESSION_COOKIE_SECURE=false

APP_LOG_ENABLED=true
APP_LOG_LEVEL=DEBUG
APP_LOG_MAX_LINES=1000
APP_LOG_PATH=logs/app.log

EMAIL_DELIVERY_ENABLED=false

BOT_DEVICE_NAME_PREFIX=Neobyatnaya-AMNZ
BOT_DEVICE_NAME_SEQUENCE_SEED=4

CLIENT_DNS=8.8.8.8, 8.8.4.4
CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0
CLIENT_PERSISTENT_KEEPALIVE=25
CLIENT_AWG_JC=4
CLIENT_AWG_JMIN=40
CLIENT_AWG_JMAX=70
CLIENT_AWG_S1=0
CLIENT_AWG_S2=0
CLIENT_AWG_S3=0
CLIENT_AWG_S4=0
CLIENT_AWG_H1=1
CLIENT_AWG_H2=2
CLIENT_AWG_H3=3
CLIENT_AWG_H4=4
CLIENT_AWG_I1=
CLIENT_AWG_I2=
CLIENT_AWG_I3=
CLIENT_AWG_I4=
CLIENT_AWG_I5=
```

`CLIENT_AWG_H1`...`CLIENT_AWG_H4` могут быть как числами, так и диапазонами из
`awg show`, например `1622123045-2053868572`.

`APP_SECRET_KEY` должен быть постоянным. Если потерять этот ключ, приложение не сможет расшифровать сохраненные peer-секреты.

Для первой проверки по обычному `http://VPS_IP:3030` нужно оставить:

```env
WEB_ADMIN_SESSION_COOKIE_SECURE=false
```

Если поставить `true` без HTTPS, браузер не сохранит session cookie, и после входа панель будет возвращать на `/login`.

После настройки HTTPS через reverse proxy можно вернуть:

```env
WEB_ADMIN_SESSION_COOKIE_SECURE=true
```

## 3. Сгенерировать пароль для web-панели

Выполнить на VPS из директории проекта:

```bash
cd /opt/amn2
source venv/bin/activate
python -m app.cli web hash-password
```

Команда попросит пароль два раза и выведет строку вида:

```text
pbkdf2_sha256$...$...
```

Вставить всю строку в `.env`:

```env
WEB_ADMIN_PASSWORD_HASH=pbkdf2_sha256$...$...
```

Не вставлять в `WEB_ADMIN_PASSWORD_HASH` обычный пароль. Там должен быть только hash.

## 4. Сгенерировать session secret

```bash
cd /opt/amn2
source venv/bin/activate
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Результат вставить в `.env`:

```env
WEB_ADMIN_SESSION_SECRET=PASTE_GENERATED_VALUE_HERE
```

Значение должно быть не короче 32 символов.

## 5. Запустить web-панель вручную

```bash
cd /opt/amn2
source venv/bin/activate
python -m app.cli web serve --host 127.0.0.1 --port 3030
```

Успешный запуск выглядит примерно так:

```text
Uvicorn running on http://127.0.0.1:3030
```

Если `--host` и `--port` не указаны, команда берет значения из `.env`:

```bash
python -m app.cli web serve
```

## 6. Проверить web-панель на самом VPS

Открыть второе SSH-окно и выполнить:

```bash
curl -i http://127.0.0.1:3030/login
curl -i http://127.0.0.1:3030/
ss -lntp | grep ':3030'
```

Ожидаемый результат:

- `/login` возвращает `HTTP/1.1 200 OK`;
- `/` возвращает redirect на `/login`;
- `ss` показывает, что процесс Python слушает порт `3030`.

## 7. Проверить доступ с компьютера администратора

В approved production режиме доступ с компьютера администратора идет через HTTPS reverse proxy, а backend web-панель остается на `127.0.0.1:3030`. Проверять нужно публичный HTTPS endpoint reverse proxy:

```text
https://<admin-domain>/login
```

На самом VPS backend остается доступен локально:

```bash
curl -i http://127.0.0.1:3030/login
```

Если на VPS `curl http://127.0.0.1:3030/login` работает, а через HTTPS reverse proxy нет, проверить:

- reverse proxy проксирует на `127.0.0.1:3030`;
- TLS/сертификат reverse proxy активен;
- firewall не открывает прямой публичный `3030/tcp`;
- `WEB_ADMIN_SESSION_COOKIE_SECURE=true` при HTTPS.

Открывать `3030/tcp` наружу через `ufw` или панель VPS-провайдера не нужно для approved reverse-proxy режима. Direct public `:3030` - отдельный exposure gate, не текущий production path.

```bash
sudo ufw status
```

Если панель открывается через HTTPS reverse proxy, но выглядит без CSS, проверить:

```bash
curl -I https://DOMAIN/static/admin.css
```

Ожидаемый ответ:

```text
HTTP/1.1 200 OK
content-type: text/css
```

В Nginx Proxy Manager proxy host должен проксировать весь `/` на приложение, а не только `/login`.
Путь `/static/admin.css` должен уходить на тот же upstream `http://127.0.0.1:3030` или
`http://SERVER_LAN_IP:3030`.

## 8. Безопасный доступ через SSH tunnel

Для первого продового теста безопаснее не открывать порт `3030` в интернет, а использовать SSH tunnel.

На VPS в `.env`:

```env
WEB_ADMIN_HOST=127.0.0.1
WEB_ADMIN_PORT=3030
WEB_ADMIN_SESSION_COOKIE_SECURE=false
```

Запуск:

```bash
cd /opt/amn2
source venv/bin/activate
python -m app.cli web serve --host 127.0.0.1 --port 3030
```

На компьютере администратора:

```bash
ssh -L 3030:127.0.0.1:3030 root@VPS_IP
```

Открыть в браузере:

```text
http://127.0.0.1:3030/login
```

## 9. Что проверить внутри web-панели

После входа проверить основные разделы:

- Dashboard открывается без ошибок;
- Users показывает пользователей, созданных ранее через бота;
- Servers показывает серверы из базы;
- Server health показывает состояние серверов и результаты проверок;
- Orders показывает заявки;
- Logs показывает последние строки `logs/app.log`, если `APP_LOG_ENABLED=true`;
- Settings показывает текущую конфигурацию с маскировкой секретов;
- Config templates показывает и редактирует шаблоны клиентских конфигов, а также `vpn://` preview.

Если ранее созданные пользователи не видны, проверить, что web-панель и бот используют один и тот же `DATABASE_PATH`.

Если до перехода на AMN2 уже были выданы тестовые peer/config вне бота, их можно завести в локальную базу как `external_only`, чтобы они отображались в web-панели и в боте. Это только локальный backfill: команда не подключается к VPS, не меняет AmneziaWG и не восстанавливает client private key. Для таких устройств повторная отправка конфига будет недоступна, пока не найден исходный `.conf` или устройство не перевыпущено.

Для нескольких старых тестовых устройств сначала сделать репетицию на JSON-файле и копии базы. Входной JSON должен содержать только metadata: `telegram_id`, `name`, `vpn_ip`, `peer_public_key`, `status`, `server_name`, `config_version` и необязательные даты. Не добавлять в файл client private key, preshared key, полный `.conf`, QR или `vpn://`.

```json
[
  {
    "telegram_id": 1001,
    "username": "alice",
    "server_name": "debian-vps-1",
    "server_network_cidr": "10.8.0.0/24",
    "name": "Neobyatnaya-AMNZ-1",
    "duration_days": 30,
    "vpn_ip": "10.8.0.41",
    "peer_public_key": "PEER_PUBLIC_KEY",
    "config_version": "amneziawg_v2",
    "status": "active"
  }
]
```

Dry-run не создает и не меняет `--db-copy`:

```bash
python -m app.cli device backfill-external \
  --db-copy data/amneziya-copy.sqlite3 \
  --input external-devices.json \
  --dry-run \
  --pretty
```

Если вывод безопасен и ожидаем, применить только к копии базы:

```bash
python -m app.cli device backfill-external \
  --db-copy data/amneziya-copy.sqlite3 \
  --input external-devices.json \
  --apply \
  --pretty
```

Ожидаемый безопасный итог: `config_material_status=external_only`, `config_resend_available=false`, `live_vps_commands=false`. Команда не выводит peer public key, private/preshared key, `.conf`, QR или `vpn://`.

Пример для ранее выданного активного тестового устройства:

```bash
python -m app.cli device import-external \
  --db data/amneziya.sqlite3 \
  --telegram-id TELEGRAM_ID \
  --username USERNAME \
  --server-name debian-vps-1 \
  --name Neobyatnaya-AMNZ-1 \
  --vpn-ip 10.8.0.X \
  --peer-public-key PEER_PUBLIC_KEY \
  --config-version amneziawg_v2 \
  --status active \
  --pretty
```

Пример для ранее отозванного тестового устройства:

```bash
python -m app.cli device import-external \
  --db data/amneziya.sqlite3 \
  --telegram-id TELEGRAM_ID \
  --server-name debian-vps-1 \
  --name Neobyatnaya-AMNZ-4 \
  --vpn-ip 10.8.0.X \
  --peer-public-key PEER_PUBLIC_KEY \
  --config-version amneziawg_v2 \
  --status revoked \
  --revoked-at 2026-06-09T10:00:00Z \
  --revoke-reason phase3_test_revoked \
  --pretty
```

Для текущего тестового ряда дефолтная нумерация новых устройств начинается после уже выданных `Neobyatnaya-AMNZ-1`...`Neobyatnaya-AMNZ-4`: `BOT_DEVICE_NAME_SEQUENCE_SEED=4`. Новое одобрение через бота получит следующий свободный номер, например `Neobyatnaya-AMNZ-5`, а если в базе уже есть больший номер, будет продолжение от него.

В разделе `Config templates` можно редактировать клиентские `.conf.tpl` шаблоны для `amneziawg_v1_5` и `amneziawg_v2`. Сохранение пишет override-файл в `CLIENT_CONFIG_TEMPLATE_DIR`, не меняя встроенные шаблоны приложения. Перед сохранением шаблон валидируется: неизвестные placeholders отклоняются, а старый файл остается без изменений. Кнопка `Сбросить к встроенному шаблону` удаляет override-файл и возвращает дефолтный шаблон из пакета. После правки preview и `vpn://` на этой же странице должны отражать новые параметры.

Постоянные параметры клиентского AmneziaWG-конфига берутся из `.env`: `CLIENT_DNS`, `CLIENT_ALLOWED_IPS`, `CLIENT_PERSISTENT_KEEPALIVE`, `CLIENT_AWG_JC`, `CLIENT_AWG_JMIN`, `CLIENT_AWG_JMAX`, `CLIENT_AWG_S1`...`CLIENT_AWG_S4`, `CLIENT_AWG_H1`...`CLIENT_AWG_H4`, `CLIENT_AWG_I1`...`CLIENT_AWG_I5`. `H1-H4` можно переносить из `awg show` как диапазоны `число-число`. Уникальные значения `PrivateKey`, `PresharedKey`, `Address`, имя устройства и имя файла формируются при создании устройства. `PublicKey` сервера и `Endpoint` берутся из `servers.yml`.

В карточке сервера доступна `Синхронизация peer`: read-only проверка сравнивает live peer из AmneziaWG с локальными устройствами в базе. В отчете:

- `Известные peer панели` — peer есть и на ноде, и в базе;
- `Peer из Amnezia` — peer есть на ноде, но не создан панелью и не привязан к локальному устройству;
- `Созданы в Amnezia` — peer, которые админ пометил как правильные внешние peer из приложения Amnezia;
- `Локальное устройство без peer на сервере` — устройство есть в базе, но peer отсутствует на ноде.

Для peer из Amnezia доступно действие `Пометить как созданный в Amnezia`. Оно только сохраняет пометку в базе, не удаляет peer и не меняет конфиг AmneziaWG. В группе `Созданы в Amnezia` доступно действие `Снять пометку`, если peer был помечен ошибочно. Для локального устройства без peer доступно действие `Добавить в Amnezia`: оно расшифровывает сохраненный preshared key, добавляет peer с прежним IP/public key в AmneziaWG, требует `VPS_APPLY_ENABLED=true` и перед отправкой формы показывает browser confirm.

В карточке пользователя действия разделены по смыслу:

- `Block` — локально блокирует пользователя, но не удаляет peer из AmneziaWG;
- `Soft delete` — помечает пользователя как `deleted`, строка остается в базе для истории;
- `Disable VPN` — удаляет активные/pending peer пользователя из AmneziaWG, затем переводит его устройства в `disabled` и блокирует пользователя. IP, public key, encrypted private key и preshared key остаются в базе, чтобы можно было включить того же клиента повторно;
- `Enable VPN` — добавляет `disabled` peer обратно в AmneziaWG с тем же public key, preshared key и IP, затем переводит устройства в `active` и разблокирует пользователя;
- `Delete permanently` — сначала удаляет активные/pending peer из AmneziaWG, затем удаляет пользователя, его устройства, заявки, email-токены, traffic snapshots и связанные audit-записи из базы.

В таблице устройств секреты показываются замаскированными. Кнопка `Show secrets` расшифровывает private key и preshared key только для выбранного устройства и пишет audit-событие. Кнопка `Удалить устройство` выборочно удаляет один аккаунт устройства у пользователя: для active/pending устройства сначала удаляет peer из AmneziaWG, затем чистит устройство и связанные ссылки в базе; для disabled/revoked устройства удаляет только локальные данные. Без постоянного `APP_SECRET_KEY` восстановить сохраненные секреты нельзя.

Устройства с `config_material_status=external_only` отображаются в таблице, но не показывают `Show secrets`, `Email config` и повторную отправку конфига в боте. Это означает, что AMN2 знает peer public key/IP/status, но не хранит исходный client private key и поэтому не может честно пересобрать рабочий клиентский конфиг.

Для `Disable VPN`, `Enable VPN` и `Delete permanently` при наличии активных или отключенных устройств требуется `VPS_APPLY_ENABLED=true` и корректный `SERVER_CONFIG_PATH`. Если изменение peer на ноде не прошло, база не меняется. Опасные web-действия (`Disable VPN`, `Enable VPN`, `Soft delete`, `Delete permanently`, `Удалить устройство`, отключение сервера и `Добавить в Amnezia`) требуют browser confirm, чтобы случайный клик не отправил боевую операцию.

Кнопки `Disable VPN` и `Enable VPN` в карточке пользователя показывают применимость по текущим устройствам. `Disable VPN` доступна, когда есть active/pending устройства; `Enable VPN` доступна, когда есть disabled устройства. Если действие неприменимо, кнопка остается на экране, но отключена и рядом показана короткая причина.

На странице `Users` есть переход `Disabled devices`. Он открывает `/devices/disabled` со списком отключенных устройств, владельцем, сервером, IP и причиной/временем отключения. Для повторного включения открыть пользователя через `Open user` и нажать `Enable VPN`.

В карточке пользователя блок `Admin actions` показывает не только action/admin/date, но и `target_device_id` с `metadata_json`. Это нужно для разбора failed VPS-событий: в metadata видны `operation`, `error_type` и `redacted_error`, если операция была записана как `*_failed`.

Email-доставка конфигов и recovery доступны только после подтверждения email. Кнопка `Send verification` отправляет одноразовый код подтверждения; `Email config` и `Email recovery` отклоняют неподтвержденный адрес с ошибкой `Email is not verified`. Старый флаг `EMAIL_REQUIRE_VERIFICATION=false` больше не разрешает отправку конфигов на неподтвержденный email.

## 10. Подготовить Telegram-бота

В `.env` заполнить:

```env
TELEGRAM_BOT_TOKEN=CHANGE_ME_TOKEN_FROM_BOTFATHER
ADMIN_TELEGRAM_IDS=CHANGE_ME_ADMIN_TELEGRAM_IDS
APP_SECRET_KEY=CHANGE_ME_GENERATED_RANDOM_SECRET_32_PLUS_CHARS
DATABASE_PATH=data/amneziya.sqlite3
SERVER_CONFIG_PATH=servers.yml
SERVER_NAME=debian-vps-1
VPS_APPLY_ENABLED=false
```

Если Telegram с VPS недоступен напрямую, указать SOCKS5 proxy:

```env
TELEGRAM_PROXY_URL=socks5://USER:PASSWORD@HOST:PORT
```

Или без авторизации:

```env
TELEGRAM_PROXY_URL=socks5://HOST:PORT
```

Проверить доступ к Telegram:

```bash
cd /opt/amn2
source venv/bin/activate
python -m app.cli bot check-network
```

Если используется локальный proxy на VPS, дополнительно:

```bash
curl --socks5-hostname 127.0.0.1:1080 -I https://api.telegram.org
```

### Read-only статус для оператора

В admin-меню Telegram-бота кнопка `Состояние` показывает безопасную сводку из
локальной базы данных:

- количество active/blocked пользователей;
- количество active/degraded серверов;
- количество active/disabled устройств;
- количество pending заявок;
- состояние integration credentials: healthy, rotation due, expired и revoked;
- фактическое состояние VPS write gate;
- состояние публичной выдачи конфигов и публичной экспозиции.

Сводка доступна только Telegram-администраторам. Она не содержит имена,
идентификаторы, адреса, token hash или raw token, не выполняет SSH-команды и не
опрашивает VPS. Просмотр записывается в безопасный audit как
`bot_operator_status_read`.

До отдельной live-активации Telegram-бота этот срез проверяется локально. Его
наличие в исходниках само по себе не запускает bot service и не меняет VPS.

### Read-only трафик пользователей

Кнопка `Трафик` в admin-меню показывает активные устройства и последние
сохраненные счетчики received/sent/total. Данные берутся из локальной таблицы
traffic snapshots; callback не выполняет SSH-команды и не запускает новый
опрос VPS. Если snapshot отсутствует или устарел, бот явно показывает это в
ответе.

Раздел доступен только Telegram-администраторам и использует выбранный язык
оператора. Просмотр записывается в audit как `bot_admin_traffic_read`; metadata
содержит только количество показанных устройств и локальный источник данных,
без device names, user identity, traffic values или config material.

## 11. Подготовить `servers.yml`

Файл `servers.yml` хранит параметры VPS и VPN-сервера. Его не коммитить в GitHub.

Для старта можно скопировать один из шаблонов:

```bash
cp deploy/examples/servers.host_systemd.example.yml servers.yml
# или
cp deploy/examples/servers.docker.example.yml servers.yml
```

После копирования обязательно заменить `CHANGE_ME_*` значения.

Рекомендуемый вариант для live health check - SSH key auth. Если в `servers.yml` временно указан:

```yaml
ssh:
  auth:
    type: password
```

то на сервере, где запущены web-панель и бот, установить `sshpass`:

```bash
sudo apt-get update
sudo apt-get install -y sshpass
```

И задать пароль в `.env`:

```env
VPS_SSH_PASSWORD=CHANGE_ME_REAL_SSH_PASSWORD
```

Минимально в нем должны быть:

- SSH host и port;
- SSH user;
- SSH auth type;
- VPN endpoint host;
- VPN UDP port;
- VPN interface;
- VPN network CIDR;
- server address;
- server public key;
- firewall provider;
- runtime.

Проверить файл без изменения VPS:

```bash
cd /opt/amn2
source venv/bin/activate
python -m app.cli server retest-plan --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
python -m app.cli server preflight --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run
```

В карточке сервера web-панель также показывает блок `VPS retest bundle` с коротким набором команд для повторного VPS-прогона: `git pull`, `server retest-plan`, `preflight`, `server check` и `sync-peers`.

Выполнить read-only проверку реального VPS:

```bash
python -m app.cli server check --config servers.yml --server debian-vps-1
```

До успешной проверки держать:

```env
VPS_APPLY_ENABLED=false
```

Включать применение peer на живом VPS только после успешных проверок:

```env
VPS_APPLY_ENABLED=true
```

### Docker runtime

Если AmneziaWG работает не на хосте через `systemd`, а внутри Docker-контейнера, в `servers.yml` использовать:

```yaml
runtime:
  type: docker
  container_name: amnezia-awg
  config_path: /opt/amnezia/awg/awg0.conf
```

Проверить имя контейнера на VPS:

```bash
docker ps --format '{{.Names}}'
```

После этого web-панель и CLI смогут выполнять read-only health check через:

```text
docker ps --format {{.Names}}
docker exec amnezia-awg awg show awg0
```

Для Docker runtime применение и отзыв peer выполняются через постоянный конфиг: приложение читает `runtime.config_path` внутри контейнера, переписывает peer-блоки, затем выполняет `docker restart <container_name>`. При создании нового устройства приложение также читает `AllowedIPs` из этого файла и выдает следующий IP после уже существующих peer в `awg0.conf`, чтобы не расходиться с живой AmneziaWG-нодой. Перед включением `VPS_APPLY_ENABLED=true` убедиться, что `config_path` указывает на реальный конфиг AmneziaWG, который переживает перезапуск контейнера.

Для сверки того, что уже есть в AmneziaWG, выполнить:

```bash
python -m app.cli server sync-peers --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
```

## 12. Запустить Telegram-бота вручную

```bash
cd /opt/amn2
source venv/bin/activate
python -m app.main
```

Проверить в Telegram:

- бот отвечает на `/start`;
- администратор видит admin-функции;
- пользователь может отправить заявку;
- администратор может одобрить заявку;
- после одобрения создается устройство;
- пользователь получает `.conf`, QR и текст с данными доставки;
- ранее созданные пользователи появляются в web-панели.

Матрица совместимости клиентского импорта зафиксирована в
`app.vpn.client_compatibility` и проверяется тестами. Текущие правила:

- `.conf` остается основным надежным fallback для DefaultVPN, AmneziaVPN и
  standalone AmneziaWG-клиентов;
- iOS DefaultVPN считается основным путем в РФ;
- iOS AmneziaWG поддерживается как installed/legacy путь только для пользователей,
  у которых приложение уже есть;
- Android AmneziaWG считается отдельным поддерживаемым путем;
- `vpn://` отправляется отдельным сообщением, чтобы его можно было открыть или
  скопировать без выделения большого текста;
- QR содержит `vpn://` payload, но не считается универсальным способом импорта
  для DefaultVPN, AmneziaVPN и standalone AmneziaWG одновременно;
- перед рекомендацией AmneziaVPN учитывать ограничения текущего release:
  Android 9+, macOS 13+, Linux x64 tar with GUI dependencies, временно
  недоступные Android 7/8 и macOS 10.15-12; distro-specific Linux packages не
  обещаются;
- native `.vpn` / Amnezia JSON artifacts не генерировать без отдельного
  config-delivery design gate.

Если бот падает при старте, смотреть:

```bash
tail -n 200 logs/app.log
```

Если бот запущен через systemd:

```bash
sudo journalctl -u amneziya-bot -n 200 --no-pager
```

## 13. Включить systemd для web-панели

Сначала убедиться, что ручной запуск работает. После этого:

```bash
cd /opt/amn2
sudo cp deploy/systemd/amneziya-web.service.example /etc/systemd/system/amneziya-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now amneziya-web
sudo systemctl status amneziya-web --no-pager
```

Проверить:

```bash
curl -i http://127.0.0.1:3030/login
sudo journalctl -u amneziya-web -n 200 --no-pager
```

Если проект находится не в `/opt/amn2` или запускается не от пользователя `amneziya`, перед запуском отредактировать:

```bash
sudo nano /etc/systemd/system/amneziya-web.service
```

Проверить поля:

```ini
User=amneziya
Group=amneziya
WorkingDirectory=/opt/amn2
EnvironmentFile=/opt/amn2/.env
ExecStart=/opt/amn2/venv/bin/python -m app.cli web serve --host 127.0.0.1 --port 3030
```

После правки:

```bash
sudo systemctl daemon-reload
sudo systemctl restart amneziya-web
sudo systemctl status amneziya-web --no-pager
```

## 14. Включить systemd для Telegram-бота

Сначала убедиться, что ручной запуск `python -m app.main` работает. После этого:

```bash
cd /opt/amn2
sudo cp deploy/systemd/amneziya-bot.service.example /etc/systemd/system/amneziya-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now amneziya-bot
sudo systemctl status amneziya-bot --no-pager
```

Проверить:

```bash
sudo journalctl -u amneziya-bot -n 200 --no-pager
tail -n 200 logs/app.log
```

Если проект находится не в `/opt/amn2` или запускается не от пользователя `amneziya`, перед запуском отредактировать:

```bash
sudo nano /etc/systemd/system/amneziya-bot.service
```

Проверить поля:

```ini
User=amneziya
Group=amneziya
WorkingDirectory=/opt/amn2
EnvironmentFile=/opt/amn2/.env
ExecStart=/opt/amn2/venv/bin/python -m app.main
```

После правки:

```bash
sudo systemctl daemon-reload
sudo systemctl restart amneziya-bot
sudo systemctl status amneziya-bot --no-pager
```

## 15. Проверка обоих сервисов

```bash
sudo systemctl status amneziya-web --no-pager
sudo systemctl status amneziya-bot --no-pager
curl -i http://127.0.0.1:3030/login
tail -n 200 logs/app.log
```

Проверить, что оба сервиса используют один `.env`:

```bash
sudo systemctl cat amneziya-web
sudo systemctl cat amneziya-bot
```

В обоих сервисах должно быть:

```ini
EnvironmentFile=/opt/amn2/.env
```

## 16. Частые ошибки web-панели

### `WEB_ADMIN_PASSWORD_HASH must be set`

Не заполнен `WEB_ADMIN_PASSWORD_HASH` или осталось значение `replace-with-password-hash`.

Решение:

```bash
python -m app.cli web hash-password
```

Вставить полученный hash в `.env`.

### `WEB_ADMIN_PASSWORD_HASH must be a valid pbkdf2_sha256 hash`

В `WEB_ADMIN_PASSWORD_HASH` вставлен обычный пароль или hash обрезан.

Решение: сгенерировать hash заново и вставить всю строку `pbkdf2_sha256$...$...`.

### `WEB_ADMIN_SESSION_SECRET must be at least 32 characters`

Слишком короткий `WEB_ADMIN_SESSION_SECRET` или осталось placeholder-значение.

Решение:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Панель возвращает на `/login` после успешного ввода пароля

Частая причина: `WEB_ADMIN_SESSION_COOKIE_SECURE=true` при доступе по обычному HTTP.

Решение для временного теста:

```env
WEB_ADMIN_SESSION_COOKIE_SECURE=false
```

После изменения `.env` перезапустить web-панель.

### `Address already in use`

Порт `3030` уже занят.

Проверить:

```bash
ss -lntp | grep ':3030'
```

Остановить старый процесс или выбрать другой порт:

```bash
python -m app.cli web serve --host 127.0.0.1 --port 3031
```

### `ModuleNotFoundError: app`

Команда запущена не из директории проекта или пакет не установлен.

Решение:

```bash
cd /opt/amn2
source venv/bin/activate
python -m pip install -e .
```

### Web-панель работает на VPS, но не открывается с компьютера

Проверить:

```bash
curl -i http://127.0.0.1:3030/login
ss -lntp | grep ':3030'
sudo ufw status
```

Если сервис слушает только `127.0.0.1`, использовать SSH tunnel или HTTPS reverse proxy. Не переключать web-admin на `0.0.0.0` без отдельного firewall/TLS/exposure gate.

## 17. Локальные bot media assets

AMN2 умеет локально проверить и поставить в registry картинки для access/support/news ботов. Это только локальная подготовка assets: команда не вызывает Telegram API, не меняет аватар бота, не отправляет сообщения и не требует Telegram token.

Проверить картинку без записи registry:

```bash
python -m app.cli bot-media validate --bot-kind access --surface start_header --path /path/to/header.png --pretty
```

Скопировать валидную картинку в локальное хранилище `data/bot-media/` и записать safe metadata:

```bash
python -m app.cli bot-media stage --bot-kind support --surface start_header --path /path/to/support-header.png --pretty
```

Выбрать staged asset для runtime mapping:

```bash
python -m app.cli bot-media select --bot-kind support --surface start_header --asset-id support-start_header-... --pretty
```

Посмотреть manifest:

```bash
python -m app.cli bot-media manifest --pretty
```

`profile_icon` можно только staged/record locally. Применение иконки профиля через Bot API или BotFather остается live Telegram identity mutation и требует отдельный named gate.

## 18. Read-only server summary в web-панели

На странице сервера web-панель показывает блок `Read-only server summary`. Он использует только сохраненный локальный `server_health_checks` snapshot из базы и не запускает live probe.

Смысл полей:

- `data_source=cached_db` - данные взяты из локальной базы;
- `freshness=fresh/not_checked` - есть ли сохраненный snapshot;
- `latest_latency_ms` - агрегированная latency последней сохраненной проверки, без per-peer данных;
- `action_hint` - напоминание, что блок не меняет VPS или peers, а live check требует named gate.

Этот блок не показывает `.conf`, QR, `vpn://`, private key, preshared key, peer/user identifiers or raw logs.

## 19. Частые ошибки Telegram-бота

### Telegram недоступен с VPS

Проверить:

```bash
python -m app.cli bot check-network
```

Если прямой доступ не работает, заполнить:

```env
TELEGRAM_PROXY_URL=socks5://USER:PASSWORD@HOST:PORT
```

После изменения `.env` перезапустить бота.

### Бот и web-панель видят разные данные

Проверить, что у обоих одинаковый:

```env
DATABASE_PATH=data/amneziya.sqlite3
APP_SECRET_KEY=...
```

Если systemd используется для обоих сервисов, проверить:

```bash
sudo systemctl cat amneziya-web
sudo systemctl cat amneziya-bot
```

### Одобрение заявки не применяет peer на VPS

Для первого теста это нормально, если:

```env
VPS_APPLY_ENABLED=false
```

Перед включением `true` обязательно выполнить:

```bash
python -m app.cli server preflight --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
python -m app.cli server check --config servers.yml --server debian-vps-1
```

### Ошибка SSH или server health

Проверить `servers.yml`, SSH-доступ и read-only check:

```bash
python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run
python -m app.cli server check --config servers.yml --server debian-vps-1
```

## 20. Что прислать для диагностики

Если web-панель или бот не запускаются, собрать:

```bash
cd /opt/amn2
git log -1 --oneline
git status --short
python -m app.cli web serve --host 127.0.0.1 --port 3030
sudo journalctl -u amneziya-web -n 200 --no-pager
sudo journalctl -u amneziya-bot -n 200 --no-pager
tail -n 200 logs/app.log
```

Секреты перед отправкой скрыть:

- `TELEGRAM_BOT_TOKEN`;
- `APP_SECRET_KEY`;
- `WEB_ADMIN_PASSWORD_HASH`;
- `WEB_ADMIN_SESSION_SECRET`;
- `SMTP_PASSWORD`;
- private keys и preshared keys;
- полный пользовательский `.conf`.
