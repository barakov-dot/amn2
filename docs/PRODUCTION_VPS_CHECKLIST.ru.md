# Production VPS Checklist

Короткий путь перед первым тестом на живом VPS.

Перед повторным заходом на VPS использовать короткий протокол: `docs/VPS_RETEST_PROTOCOL.ru.md`.

## 1. Получить код

```bash
git clone -b codex-vps-test-prep https://github.com/barakov-dot/amn2.git
cd amn2
```

## 2. Подготовить Python-окружение

На новом VPS:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

Если проект уже был склонирован ранее и нужно получить свежие изменения:

```bash
git pull
source venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

## 3. Подготовить `.env`

```bash
cp .env.example .env
```

Заполнить минимум:

```env
TELEGRAM_BOT_TOKEN=CHANGE_ME_TOKEN_FROM_BOTFATHER
TELEGRAM_PROXY_URL=
APP_SECRET_KEY=CHANGE_ME_GENERATED_RANDOM_SECRET_32_PLUS_CHARS
ADMIN_TELEGRAM_IDS=CHANGE_ME_ADMIN_TELEGRAM_IDS
VPS_APPLY_ENABLED=false
SERVER_CONFIG_PATH=servers.yml
SERVER_NAME=debian-vps-1
```

Если VPS не открывает `https://api.telegram.org` напрямую, указать SOCKS5 proxy:

```env
TELEGRAM_PROXY_URL=socks5://127.0.0.1:1080
```

Перед запуском бота проверить доступ через тот же proxy:

```bash
curl --socks5-hostname 127.0.0.1:1080 -I https://api.telegram.org
python -m app.cli bot check-network
```

`APP_SECRET_KEY` сохранить отдельно. Потеря ключа означает потерю доступа к
зашифрованным peer-секретам.

### Web-панель администрирования

Для первого запуска web-панель по умолчанию выключена. Когда включаем ее на VPS,
заполнить отдельные значения:

```env
WEB_ADMIN_ENABLED=false
WEB_ADMIN_HOST=0.0.0.0
WEB_ADMIN_PORT=3030
WEB_ADMIN_USERNAME=admin
WEB_ADMIN_PASSWORD_HASH=replace-with-password-hash
WEB_ADMIN_SESSION_SECRET=replace-with-generated-random-secret-32-plus-chars
WEB_ADMIN_SESSION_COOKIE_SECURE=true
```

`WEB_ADMIN_PASSWORD_HASH` сгенерировать на VPS без сохранения raw password в
shell history:

```bash
python -m app.cli web hash-password
```

Для automation в доверенной shell команда также принимает `--password`, но для
первой настройки безопаснее interactive prompt. `WEB_ADMIN_SESSION_SECRET`
задать как любое сильное случайное значение длиной 32+ символа, например из
password manager.

Запуск панели:

```bash
python -m app.cli web serve --host 0.0.0.0 --port 3030
```

Если `--host` или `--port` не указаны, команда берет `WEB_ADMIN_HOST` и
`WEB_ADMIN_PORT` из `.env`.

`WEB_ADMIN_SESSION_COOKIE_SECURE=true` требует HTTPS, reverse proxy с TLS или SSH
tunnel до панели. Для короткой проверки по plain HTTP на `:3030` можно временно
поставить `WEB_ADMIN_SESSION_COOKIE_SECURE=false`, но не оставлять так открытую
панель в интернете.

## 4. Шаблоны и выдача конфига

Текущие варианты получения конфига пользователем:

- Telegram-сообщение по шаблону `config_ready`;
- вложенный `.conf` файл;
- QR-код;
- повторная отправка пользователем из своих устройств;
- повторная отправка администратором;
- аварийная отправка raw config text, если файл/QR не ушли после создания устройства.

В доработке web-панели добавляется отдельный шаблон клиентского `.conf` по версиям
`amneziawg_v1_5` и `amneziawg_v2`, а также ссылка вида `vpn://...`.
После реализации держать VPS-правки шаблонов во внешней директории:

```env
CLIENT_CONFIG_TEMPLATE_DIR=config_templates
CLIENT_DNS=1.1.1.1
CLIENT_ALLOWED_IPS=0.0.0.0/0
CLIENT_PERSISTENT_KEEPALIVE=25
CLIENT_AWG_JC=4
CLIENT_AWG_JMIN=40
CLIENT_AWG_JMAX=70
CLIENT_AWG_S1=0
CLIENT_AWG_S2=0
CLIENT_AWG_H1=1
CLIENT_AWG_H2=2
CLIENT_AWG_H3=3
CLIENT_AWG_H4=4
```

Файлы overrides должны называться ровно так:

- `amneziawg_v1_5.conf.tpl`
- `amneziawg_v2.conf.tpl`

Шаблон содержит постоянные строки конфига и placeholders для переменных значений
пользователя/устройства. `.conf` файл остается каноническим способом доставки,
пока `vpn://` импорт не проверен на реальном AmneziaVPN-клиенте.
Постоянные строки AmneziaWG-клиента (`DNS`, `AllowedIPs`, `PersistentKeepalive`,
`Jc/Jmin/Jmax/S1/S2/H1-H4`) задаются через `CLIENT_*` переменные. Ключи,
`Address`, имя устройства и имя файла генерируются отдельно для каждого
устройства.
`CLIENT_AWG_H1-H4` можно задавать числами или диапазонами из `awg show`, например
`1622123045-2053868572`.

Если пользователь укажет email, web-панель может отправить письмо
подтверждения, а после подтверждения - конфиг устройства или одноразовую
recovery-code на этот адрес. Для первого живого запуска держать канал
выключенным, пока SMTP-настройки не заполнены и не проверены:

```env
EMAIL_DELIVERY_ENABLED=false
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_USE_TLS=true
EMAIL_REQUIRE_VERIFICATION=true
EMAIL_RECOVERY_TOKEN_TTL_MINUTES=30
EMAIL_CONFIG_ATTACHMENTS_ENABLED=true
```

Конфиги и recovery-письма уходят только на подтвержденный email. Значение
`EMAIL_REQUIRE_VERIFICATION=false` не разрешает отправку конфигов на
неподтвержденный адрес. Verification/recovery codes одноразовые, в базе
хранится только SHA-256 hash token, срок жизни задает
`EMAIL_RECOVERY_TOKEN_TTL_MINUTES`.
Письмо с конфигом содержит краткую инструкцию и `vpn://` import link; вложение
`.conf` управляется `EMAIL_CONFIG_ATTACHMENTS_ENABLED`.

SMTP password, raw verification/recovery tokens и полный config text не должны
попадать в логи и admin-action metadata.

## 5. Подготовить `servers.yml`

Файл не коммитить. Обязательные значения:

```yaml
ssh.host: VPS IP или домен
ssh.user: root или другой пользователь
ssh.auth.type: key или password
vpn.endpoint_host: публичный IP или домен
vpn.port: фиксированный UDP-порт, например 30001
vpn.network_cidr: 10.8.0.0/24
vpn.server_address: 10.8.0.1/24
vpn.server_public_key: public key сервера AmneziaWG
```

Если нужен готовый стартовый шаблон, взять один из файлов:

```bash
cp deploy/examples/servers.host_systemd.example.yml servers.yml
# или
cp deploy/examples/servers.docker.example.yml servers.yml
```

Затем заменить `CHANGE_ME_*` на реальные значения.

Для первого продового режима предпочтителен SSH key auth. Если временно используется password auth, на сервере, где запущены бот/web-панель, нужен `sshpass`:

```bash
sudo apt-get update
sudo apt-get install -y sshpass
```

В `.env` должен быть задан пароль:

```env
VPS_SSH_PASSWORD=CHANGE_ME_REAL_SSH_PASSWORD
```

## 6. Локальная проверка

```bash
python -m pytest tests
python -m app.cli server retest-plan --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
python -m app.cli server preflight --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
```

## 7. Безопасные VPS dry-run

```bash
python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run
python -m app.cli server apply-peer --config servers.yml --server debian-vps-1 --public-key PEER_PUBLIC_KEY --preshared-key PEER_PSK --vpn-ip 10.8.0.2 --dry-run
python -m app.cli server revoke-peer --config servers.yml --server debian-vps-1 --public-key PEER_PUBLIC_KEY --dry-run
python -m app.cli server collect-traffic --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3 --dry-run
```

Перед live-проверкой можно отдельно проверить runtime VPS без изменения сервера:

```bash
bash deploy/runtime/check_vps.sh
```

Для Docker-ноды:

```bash
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg bash deploy/runtime/check_vps.sh
```

Если проверка падает или нужно прислать полный отчет:

```bash
bash deploy/runtime/collect_debug_snapshot.sh
```

Для Docker-ноды:

```bash
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg bash deploy/runtime/collect_debug_snapshot.sh
```

## 8. Первый живой тест

Сначала выполнить read-only check:

```bash
python -m app.cli server check --config servers.yml --server debian-vps-1
```

Если check успешен, можно вручную проверить `apply-peer --apply` на тестовом peer.
Только после этого включать:

```env
VPS_APPLY_ENABLED=true
```

### Если AmneziaWG работает в Docker

Для Docker-ноды в `servers.yml` указать:

```yaml
runtime:
  type: docker
  container_name: amnezia-awg
  config_path: /opt/amnezia/awg/awg0.conf
```

Перед live-проверкой убедиться, что имя контейнера совпадает с реальным:

```bash
docker ps --format '{{.Names}}'
```

Затем выполнить безопасные проверки проекта:

```bash
python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run
python -m app.cli server check --config servers.yml --server debian-vps-1
python -m app.cli server sync-peers --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
```

Ожидаемые read-only команды для Docker:

```text
command -v docker
docker ps --format {{.Names}}
docker exec amnezia-awg awg show awg0
ss -lun
```

Для Docker runtime `apply-peer --apply` и `revoke-peer --apply` меняют файл `runtime.config_path` внутри контейнера и затем выполняют `docker restart <container_name>`. При создании нового устройства приложение читает `AllowedIPs` из этого же файла и выдает следующий IP после уже существующих peer в `awg0.conf`. Перед включением `VPS_APPLY_ENABLED=true` обязательно проверить, что `config_path` указывает на реальный постоянный конфиг AmneziaWG, иначе peer может исчезнуть после перезапуска или сломать рабочий контейнер.

## 9. Optional `systemd` services

Если ручные команды работают, можно установить example services. Перед установкой
поменять пути и Linux user, если проект лежит не в `/opt/amn2` или запускается
не от пользователя `amneziya`:

```bash
sudo cp deploy/systemd/amneziya-bot.service.example /etc/systemd/system/amneziya-bot.service
sudo cp deploy/systemd/amneziya-web.service.example /etc/systemd/system/amneziya-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now amneziya-bot
sudo systemctl enable --now amneziya-web
sudo systemctl status amneziya-bot --no-pager
sudo systemctl status amneziya-web --no-pager
```

Если web-панель не нужна во время первого VPN-теста, держать `amneziya-web`
остановленным.

## 10. Backup

```bash
python -m app.cli backup create --db data/amneziya.sqlite3 --output backups
python -m app.cli backup verify --file backups/<backup-file>.tar.enc
```

Перед переносом на другой сервер обязательно сохранить `.env`, `servers.yml` и
backup-файл отдельно от репозитория.
