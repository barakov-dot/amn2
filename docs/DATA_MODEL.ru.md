# Модель данных MVP

## Принцип

База пользователей должна быть отдельным слоем приложения. Пользователь Telegram и его VPN-конфиги не должны смешиваться с временными заявками, платежами и логами.

Один пользователь может иметь несколько устройств. Каждое устройство получает отдельный VPN-конфиг, отдельный IP и отдельный peer на сервере.

## Таблицы

### `users`

Пользователь Telegram.

Поля:

- `id` - внутренний ID;
- `telegram_id` - Telegram user ID;
- `username` - Telegram username, если есть;
- `first_name`;
- `last_name`;
- `created_at` - дата создания пользователя в системе;
- `updated_at`;
- `status` - `active`, `blocked`, `deleted`;
- `is_admin` - флаг делегированных прав администратора для MVP, позже можно заменить ролями.

Пользователь может появиться в системе через Telegram `/start` или быть добавлен
администратором вручную через команды бота. В обоих случаях стабильным
идентификатором остается `telegram_id`, поэтому администратор может создать
заявку, сформировать конфиг, QR-код и видеть такого пользователя вместе с
обычными пользователями сервиса.

### `devices`

Устройство пользователя. Одно устройство равно одному VPN-конфигу.

Поля:

- `id` - внутренний ID;
- `user_id` - ссылка на `users.id`;
- `server_id` - ссылка на `servers.id`;
- `name` - имя устройства, например `iPhone`, `Windows PC`, `Android`;
- `created_at` - дата создания конфига;
- `activated_at` - дата активации;
- `expires_at` - дата окончания;
- `duration_days` - сколько дней работает доступ;
- `status` - `active`, `expired`, `revoked`, `pending`;
- `vpn_ip` - IP устройства внутри VPN-сети;
- `peer_public_key`;
- `peer_private_key_encrypted` - private key в зашифрованном виде;
- `preshared_key_encrypted` - если используется PSK;
- `config_version` - например `amneziawg_v2`;
- `last_config_sent_at`;
- `revoked_at`;
- `revoke_reason`.

### `servers`

VPN-серверы.

Поля:

- `id`;
- `name`;
- `host`;
- `ssh_port`;
- `endpoint_host`;
- `vpn_port`;
- `vpn_network_cidr`;
- `vpn_network_version` - например `ipv4`;
- `runtime` - `host_systemd` или `docker`; для Docker на текущем этапе включены read-only проверки ноды, без live apply/revoke;
- `firewall` - например `ufw`;
- `status` - `active`, `degraded`, `disabled`;
- `max_devices`;
- `current_devices`;
- `created_at`;
- `updated_at`;

### `server_ports`

Выделенные UDP-порты серверов. Для MVP можно хранить порт прямо в `servers.vpn_port`, но отдельная таблица полезна при будущих нескольких интерфейсах или нескольких протоколах на одном VPS.

Поля:

- `id`;
- `server_id`;
- `protocol` - `udp`;
- `port`;
- `purpose` - `amneziawg`;
- `opened_in_firewall` - открыт ли порт в `ufw`;
- `created_at`;

### `plans`

Тарифы/сроки.

Поля:

- `id`;
- `name`;
- `duration_days`;
- `price`;
- `currency`;
- `is_free`;
- `is_active`;
- `created_at`;

### `orders`

Заявка на создание или продление доступа.

Поля:

- `id`;
- `user_id`;
- `device_id` - может быть пустым для нового устройства;
- `plan_id`;
- `status` - `draft`, `payment_pending`, `manual_review`, `approved`, `rejected`, `fulfilled`;
- `payment_mode` - `free_test`, `manual`, `provider`;
- `created_at`;
- `approved_at`;
- `fulfilled_at`;

### `payments`

Будущий платежный слой.

Поля:

- `id`;
- `order_id`;
- `provider` - `manual`, `yookassa`, `cryptobot`, `telegram_stars`, другое;
- `external_payment_id`;
- `amount`;
- `currency`;
- `status`;
- `created_at`;
- `paid_at`;

### `admin_actions`

Аудит действий администраторов.

Поля:

- `id`;
- `admin_telegram_id`;
- `action`;
- `target_user_id`;
- `target_device_id`;
- `metadata_json`;
- `created_at`.

Текущие действия: ручное создание пользователя, ручное создание заявки,
делегирование прав администратора, подтверждение заявки и повторная отправка
конфига.

### `device_traffic_snapshots`

Снимки статистики трафика по устройствам.

Поля:

- `id`;
- `device_id` - ссылка на `devices.id`;
- `server_id` - ссылка на `servers.id`;
- `peer_public_key` - public key peer, по которому статистика сопоставляется с устройством;
- `rx_bytes` - входящий трафик, неотрицательное число;
- `tx_bytes` - исходящий трафик, неотрицательное число;
- `source` - источник статистики, например `fake`, позже `awg`;
- `collected_at` - время сбора статистики.

Последний снимок устройства используется для отображения статистики пользователю и администратору в Telegram-боте.

### `api_tokens`

Scoped API tokens для будущих external integrations.

Поля:

- `id` - стабильный token id для audit/revoke;
- `name` - операторское имя токена;
- `owner_user_id` - опциональная ссылка на `users.id`;
- `owner_label` - человекочитаемый владелец, например `ops` или `monitoring`;
- `token_hash` - только hash вида `sha256:<digest>`, raw token не хранится;
- `scopes_json` - JSON-список scopes;
- `expires_at`;
- `revoked_at`;
- `revoke_reason`;
- `last_used_at`;
- `rotated_from_token_id` - ссылка на предыдущий token id при rotation;
- `created_at`.

В первом slice разрешены read-only scopes `server:read` и `metrics:read`.
Phase 7 `P7-C005` добавляет gated scope `install:write` только для
audit-only install mutation request contour. `config:read`, `server:write`,
`clients:write`, Local Agent write, backup/restore и destructive scopes остаются
future gates.

## Настройки режимов

Минимальные настройки в `.env`:

```env
ACCESS_MODE=free_test
PAYMENT_PROVIDER=none
DEFAULT_PLAN_DAYS=7
ADMIN_TELEGRAM_IDS=123456789
VPN_PORT_MIN=30001
VPN_PORT_MAX=65535
DEFAULT_VPN_NETWORK_CIDR=10.8.0.0/24
EXPIRATION_NOTICE_DAYS=7,5,3,1
VPN_SERVER_RUNTIME=host_systemd
CLIENT_DNS=1.1.1.1
CLIENT_ALLOWED_IPS=0.0.0.0/0
MAX_DEVICES_PER_USER=5
FREE_TEST_REQUIRES_APPROVAL=true
CONTROL_PANEL_AUTH_METHODS=telegram_admin,password,key
CONTROL_PANEL_ADMIN_USERNAME=admin
CONTROL_PANEL_PASSWORD_HASH=
CONTROL_PANEL_PUBLIC_KEY_PATH=
```

Возможные значения `ACCESS_MODE`:

- `free_test` - тестовый режим, доступ можно выдавать бесплатно;
- `manual` - ручное подтверждение админом;
- `payment` - доступ только после успешной оплаты через провайдера.

`CONTROL_PANEL_AUTH_METHODS` заранее готовит будущую панель управления к
нескольким вариантам входа администратора:

- `telegram_admin` - allowlist Telegram-админов и админы, делегированные в БД;
- `password` - логин администратора и hash пароля;
- `key` - путь к public key администратора для входа по ключу.

Обычный пароль администратора нельзя хранить в `.env`. Когда будет реализован
слой панели управления, хранить нужно только стойкий hash пароля.

## Важное по ключам

Для повторной выдачи конфига нужно либо хранить private key, либо хранить зашифрованный готовый конфиг. Для MVP предпочтительно хранить `peer_private_key_encrypted` и генерировать `.conf` заново из данных БД и параметров сервера.

## Версии конфигов

Поддерживаемые значения `devices.config_version`:

- `amneziawg_v1_5`;
- `amneziawg_v2`.

Выбранная версия сохраняется на устройстве и должна использоваться при повторной выдаче конфига.
