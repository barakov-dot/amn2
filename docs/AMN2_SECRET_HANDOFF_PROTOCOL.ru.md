# AMN2 Secret Handoff Protocol

Дата: 2026-06-13.

Статус: local-only protocol for fresh installer planning.

Этот протокол фиксирует, как будущий чистый установщик AMN2 должен обращаться
с секретами. Он не открывает config delivery, public exposure, write API,
Telegram identity mutation или live VPS gate.

## Правило

Fresh install plan может описывать только места, где оператор должен локально
заполнить секреты. Сам plan, manifest, audit summary, bot message, public docs
и generated checklist не должны содержать реальные секреты.

Разрешено:

- имя переменной или поля;
- короткое описание назначения;
- кто вводит значение: operator;
- где значение должно жить после ручного ввода;
- факт, что значение еще не настроено.

Запрещено:

- raw Telegram bot token;
- web admin password;
- session secret;
- SSH private key or password;
- VPN private key;
- preshared key;
- client config payload;
- QR payload;
- import payload;
- token hash;
- Authorization header;
- database dump with secrets.

## Checklist

Operator-local checklist для будущего install wizard должен включать только
названия пунктов:

- create `.env` locally from `.env.example`;
- set `TELEGRAM_BOT_TOKEN` locally;
- set `APP_SECRET_KEY` locally;
- set web admin credentials locally;
- prepare server inventory locally;
- keep client config delivery disabled until named gate;
- keep `VPS_APPLY_ENABLED=false` until named gate.

Checklist не должен печатать сами значения.

## Storage Boundary

Секреты могут попадать только в локальные runtime-файлы оператора или в
production secret store, если он будет отдельно спроектирован и утвержден.

Для текущего local-only planning slice такими файлами считаются операторские
runtime artifacts, а не git/doc/test output. Git не должен получать `.env`,
runtime `servers.yml`, database files, generated client configs, QR payloads
или import links.

## Gate Boundary

Любой переход от checklist к реальной доставке секретов или конфигов требует
отдельного named gate:

- config delivery: `P6-C002`;
- write API: `P6-C003`;
- destructive cleanup/reinstall: `P6-C007`;
- live package/VPS apply: отдельный live apply/smoke gate;
- Telegram identity mutation: отдельный Telegram apply gate.
