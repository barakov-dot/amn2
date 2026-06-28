# Контракт экспорта конфигов

Дата: 2026-06-01.

Режим: local-only contract slice.

Этот срез добавляет typed boundary для будущего manager-driven config export, но не открывает новые маршруты и не меняет текущую доставку конфигов через bot/web/email.

## Что добавлено

- `app.services.config_export.ConfigExportRequest`
- `ConfigExportResult`
- `ConfigExportArtifact`
- `export_device_config_delivery()`
- `run_config_exporter()`

`export_device_config_delivery()` адаптирует существующий `DeviceConfigDelivery` / `ConfigDeliveryPackage` в typed artifacts:

- `wireguard_conf`
- `qr_payload`
- `qr_png`
- `amnezia_import_uri`
- `delivery_message`

Все реальные payload остаются `client-config-secret`. В audit/log/diagnostics допускается только `safe_metadata()`.

## Границы

Срез не добавляет:

- public/self-service config endpoint;
- `/api/*` route;
- API `config:read`;
- Local Agent `/configs`;
- новый QR/import behavior;
- live VPS calls;
- хранение raw config в базе.

Unsupported artifact, unsupported target client и manager signature mismatch возвращают стабильные safe categories без raw traceback, `.conf`, QR payload или `vpn://`.

Manager/runtime compatibility: если будущий manager export требует
`runtime.config_path`, контракт должен получить этот факт явно через request.
При отсутствующем пути export возвращает safe reason code
`runtime_config_path_missing` без `.conf`, QR/import payload, raw path или
traceback в `safe_metadata()`. При наличии пути metadata публикует только
`runtime_config_path_status=provided`, но не сам путь.

## Проверка

Основные тесты:

```text
tests/services/test_config_export.py
tests/services/test_config_delivery.py
tests/bot/test_delivery.py
tests/security/test_redaction.py
tests/security/test_surface_policy.py
tests/security/test_surface_policy_bindings.py
```

VPS gate для этого среза не нужен: peer apply/revoke/config defaults/sync/runtime behavior не меняются.
