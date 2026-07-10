# Amneziya VPN Automation

Проект для автоматического разворачивания AmneziaWG 2.0 на собственном VPS и управления пользовательскими VPN-конфигами через Telegram-бота.

## Цель

Сделать систему, которая:

- разворачивает AmneziaWG 2.0 на чистом VPS;
- создает VPN-доступы по запросу пользователя или администратора;
- выдает `.conf`, QR-код и import-ссылку с явной матрицей клиентов:
  iOS DefaultVPN как основной путь в РФ, iOS AmneziaWG только если приложение
  уже установлено, Android AmneziaWG как отдельный поддерживаемый путь;
- хранит сроки действия доступов;
- отключает просроченные конфиги;
- поддерживает оплату или ручную проверку перед выдачей;
- готова к расширению на несколько серверов.

## Документы

- [Техническое задание](docs/TECH_SPEC.md)
- [План реализации](docs/IMPLEMENTATION_PLAN.md)
- [Принятые решения](docs/DECISIONS.md)
- [Модель данных MVP](docs/DATA_MODEL.md)
- [Управление VPN-серверами](docs/SERVER_MANAGEMENT.md)
- [Шаблон конфигурации серверов](docs/SERVER_CONFIG_TEMPLATE.md)
- [Production VPS checklist RU](docs/PRODUCTION_VPS_CHECKLIST.ru.md)
- [Production VPS checklist EN](docs/PRODUCTION_VPS_CHECKLIST.en.md)
- [Emergency restore checklist RU](docs/EMERGENCY_RESTORE_CHECKLIST.ru.md)
- [Emergency restore checklist EN](docs/EMERGENCY_RESTORE_CHECKLIST.en.md)
- [Traffic collection schedule RU](docs/TRAFFIC_COLLECTION_SCHEDULE.ru.md)
- [Traffic collection schedule EN](docs/TRAFFIC_COLLECTION_SCHEDULE.en.md)
- [Beginner guide RU](docs/NEXT_STAGE_BEGINNER_GUIDE.ru.md)
- [Beginner guide EN](docs/NEXT_STAGE_BEGINNER_GUIDE.en.md)
- [Runtime/toolchain contract RU](docs/RUNTIME_TOOLCHAIN.ru.md)
- [Operator single-device create RU](docs/OPERATOR_SINGLE_DEVICE_CREATE.ru.md)
- [Открытые вопросы](docs/OPEN_QUESTIONS.md)

## VPS Preflight

Before enabling live VPS changes, keep `VPS_APPLY_ENABLED=false` and run:

```powershell
python -m app.cli server preflight --config servers.yml --server debian-vps-1 --db data/amneziya.sqlite3
python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run
```

Only after dry-runs and live read-only checks pass, test `apply-peer --apply`
with a test peer and then enable `VPS_APPLY_ENABLED=true`.

## Рекомендуемый стек

- CPython 3.12.x
- aiogram 3.x
- PostgreSQL для продакшна, SQLite для локального MVP
- Docker Compose для бота и вспомогательных сервисов
- SSH/SFTP для первичного provisioning VPS
- systemd + `awg`/`awg-quick` на VPS для AmneziaWG

## Базовый сценарий

1. Администратор добавляет VPS в конфигурацию проекта.
2. Provisioning-скрипт устанавливает AmneziaWG 2.0 и настраивает firewall/NAT.
3. Пользователь пишет Telegram-боту.
4. Бот проверяет оплату или отправляет заявку администратору.
5. После подтверждения бот создает peer, назначает IP и срок действия.
6. Пользователь получает `.conf`, QR-код и import-ссылку. `.conf` остается
   основным fallback; QR/`vpn://` проверяются отдельно для DefaultVPN,
   установленного iOS AmneziaWG и Android AmneziaWG.
7. Планировщик регулярно отключает просроченные peer.

## Local Development

1. Create `.env` from `.env.example`.
2. Set `TELEGRAM_BOT_TOKEN`, `APP_SECRET_KEY`, and `ADMIN_TELEGRAM_IDS`.
3. Create a CPython 3.12 virtual environment.
4. Install dependencies with `python -m pip install -e ".[dev]"`.
5. Check the runtime with `python -m app.toolchain check`.
6. Run tests with `.\scripts\test.ps1 tests -v` on Windows/Codex Desktop, or
   `python -m pytest tests -v` inside an activated CPython 3.12 environment.
7. Start the bot with `python -m app.main`.

## Backup

Create a local encrypted backup:

```powershell
python -m app.cli backup create --db data/amneziya.sqlite3 --output backups
```

Verify a backup:

```powershell
python -m app.cli backup verify --file backups/<backup-file>.tar.enc
```

Restore to a new database path:

```powershell
python -m app.cli backup restore --file backups/<backup-file>.tar.enc --target-db data/restored.sqlite3
```

The same `APP_SECRET_KEY` used when creating encrypted peer secrets is required for restore validation.
