# Шаблон конфигурации серверов

## Назначение

Данные VPS должны быть универсальными и заменяемыми. Для подключения нового сервера администратор должен заполнить конфигурацию сервера, после чего provisioning сможет быстро развернуть AmneziaWG 2.0 на новом Debian VPS.

Секреты не хранятся в репозитории. В документах и примерах используются только placeholder-значения.

Provisioning должен поддерживать два режима:

- `non-interactive` - читает заранее заполненный `servers.yml`;
- `interactive` - спрашивает недостающие значения и сам генерирует или обновляет `servers.yml`.

## Пример `servers.yml`

Готовые стартовые примеры лежат в:

- `deploy/examples/servers.host_systemd.example.yml`;
- `deploy/examples/servers.docker.example.yml`.

```yaml
servers:
  - name: "debian-vps-1"
    enabled: true
    location: "default"

    ssh:
      host: "CHANGE_ME_SERVER_IP_OR_DOMAIN"
      port: 22
      user: "CHANGE_ME_SSH_USER"
      auth:
        type: "key"
        private_key_path: "CHANGE_ME_PATH_TO_PRIVATE_KEY"

    vpn:
      endpoint_host: "CHANGE_ME_PUBLIC_IP_OR_DOMAIN"
      port: "auto"
      port_min: 30001
      port_max: 65535
      interface: "awg0"
      network_cidr: "10.8.0.0/24"
      server_address: "10.8.0.1/24"
      dns: "8.8.8.8, 8.8.4.4"
      allowed_ips: "0.0.0.0/0, ::/0"
      server_public_key: "CHANGE_ME_AWG_SERVER_PUBLIC_KEY"
      max_devices: 254

    firewall:
      provider: "ufw"
      open_vpn_port: true

    runtime:
      type: "host_systemd"
      service_name: "awg-quick@awg0"
```

## Несколько серверов

Для нескольких серверов добавляется еще один элемент в `servers`.

```yaml
servers:
  - name: "debian-vps-1"
    location: "nl"
    vpn:
      network_cidr: "10.8.0.0/24"

  - name: "debian-vps-2"
    location: "de"
    vpn:
      network_cidr: "10.9.0.0/24"
```

Пулы разных серверов не должны пересекаться.

Если `server_address` указан с CIDR-префиксом, например `10.8.1.1/24`,
приложение считает фактической сетью `10.8.1.0/24`. `network_cidr` лучше
держать таким же, чтобы конфиг читался однозначно.

## Расширение пула

Если на одном сервере ожидается больше 255 устройств, нужно заранее выбрать более крупную сеть.

Пример:

```yaml
vpn:
  network_cidr: "10.8.0.0/16"
  server_address: "10.8.0.1/16"
  max_devices: 65000
```

Для MVP можно начать с `10.8.0.0/24`, но IPAM-логика должна уметь работать с CIDR, а не с фиксированным последним октетом.

## Переменные окружения

Общие настройки, не привязанные к конкретному серверу:

```env
ACCESS_MODE=free_test
FREE_TEST_REQUIRES_APPROVAL=true
DEFAULT_PLAN_DAYS=7
MAX_DEVICES_PER_USER=5
CLIENT_DNS=8.8.8.8, 8.8.4.4
CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0
CLIENT_PERSISTENT_KEEPALIVE=25
CLIENT_AWG_JC=3
CLIENT_AWG_JMIN=10
CLIENT_AWG_JMAX=30
CLIENT_AWG_S1=15
CLIENT_AWG_S2=18
CLIENT_AWG_S3=20
CLIENT_AWG_S4=23
CLIENT_AWG_H1=1020325451
CLIENT_AWG_H2=3288052141
CLIENT_AWG_H3=1766607858
CLIENT_AWG_H4=2528465083
CLIENT_AWG_I1=
CLIENT_AWG_I2=
CLIENT_AWG_I3=
CLIENT_AWG_I4=
CLIENT_AWG_I5=
EXPIRATION_NOTICE_DAYS=7,5,3,1
VPN_PORT_MIN=30001
VPN_PORT_MAX=65535
VPN_SERVER_RUNTIME=host_systemd
```

`CLIENT_AWG_H1`...`CLIENT_AWG_H4` можно оставлять числами или задавать
диапазонами из `awg show`, например `1622123045-2053868572`.

`CLIENT_AWG_S3`, `CLIENT_AWG_S4` и `CLIENT_AWG_I1`...`CLIENT_AWG_I5`
заполняются из конфига, который создала Amnezia. Пустые `I2-I5` допустимы.

Эти `CLIENT_*` значения подставляются в клиентский `.conf` шаблон. Ключи,
`Address`, имя устройства и имя файла формируются отдельно для каждого
пользователя/устройства; `server_public_key` и `endpoint` берутся из `servers.yml`.

## Данные, которые нужно будет подставить позже

- `ssh.host`;
- `ssh.port`;
- `ssh.user`;
- `ssh.auth.private_key_path` или другой способ доступа;
- `vpn.endpoint_host`;
- `vpn.server_public_key`;
- Telegram bot token;
- Telegram ID администраторов.

Если выбран `ssh.auth.type: password`, пароль не указывать в `servers.yml`. Он хранится только в `.env`:

```env
VPS_SSH_PASSWORD=CHANGE_ME_REAL_SSH_PASSWORD
```

Для non-interactive password auth нужен `sshpass` на сервере, где запущены бот/web-панель. SSH key auth остается предпочтительным вариантом.

## Интерактивный мастер

Если `servers.yml` отсутствует или в нем остались `CHANGE_ME_*` значения, скрипт настройки должен предложить интерактивный режим.

Минимальные вопросы мастера:

1. Название сервера.
2. Локация или короткая метка сервера.
3. SSH host/IP.
4. SSH port.
5. SSH user.
6. Тип SSH-доступа: ключ или пароль.
7. Путь к SSH private key, если выбран ключ.
8. Public endpoint для клиентов: IP или домен.
9. VPN UDP-порт: auto или вручную.
10. VPN CIDR: по умолчанию `10.8.0.0/24`.
11. Server VPN address: по умолчанию первый доступный адрес в CIDR, например `10.8.0.1/24`.
12. DNS: по умолчанию `1.1.1.1`.
13. Allowed IPs: по умолчанию `0.0.0.0/0`.
14. Открывать порт в `ufw`: по умолчанию да.

После ответов мастер должен:

- показать summary без секретов;
- запросить подтверждение;
- сохранить конфиг;
- запустить provisioning или предложить команду для запуска.

## Non-interactive режим

Для повторяемого разворачивания на новом сервере можно заранее подготовить файл:

```powershell
python -m app.cli provision --config servers.yml --server debian-vps-1 --yes
```

Если указан `--yes`, скрипт не должен задавать вопросы, кроме случаев, когда отсутствуют обязательные значения.

## Interactive режим

Для ручной настройки:

```powershell
python -m app.cli provision --interactive
```

В этом режиме скрипт спрашивает данные, создает или обновляет `servers.yml`, а затем запускает provisioning после подтверждения.

## Docker runtime для первого VPS-теста

Если AmneziaWG уже развернут в Docker-контейнере и мы не управляем им через `systemd`, в `servers.yml` нужно указать runtime `docker` и имя контейнера:

```yaml
runtime:
  type: "docker"
  container_name: "amnezia-awg"
  config_path: "/opt/amnezia/awg/awg0.conf"
```

Для Docker runtime включены безопасные read-only проверки:

- наличие Docker на VPS;
- наличие запущенного контейнера по `container_name`;
- `docker exec <container_name> awg show <interface>`;
- видимость UDP-порта через `ss -lun` на хосте.

Команды `apply-peer` и `revoke-peer` для Docker требуют `runtime.config_path`: приложение читает этот файл внутри контейнера, переписывает peer-блоки и выполняет `docker restart <container_name>`. Указывать нужно именно постоянный конфиг AmneziaWG, иначе изменения не переживут перезапуск или могут сломать рабочий контейнер. `collect-traffic` и `sync-peers` читают `docker exec <container_name> awg show <interface> dump`.
