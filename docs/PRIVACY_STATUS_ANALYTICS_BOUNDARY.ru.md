# Privacy/status analytics boundary

Документ фиксирует Phase 6 границу для P6-M002 и P6-N002: health/status
scheduler и admin analytics могут работать только как aggregate-only поверхности.
Это planning/security/productization lane, а не public launch и не live probe
enablement.

## Разрешено без отдельного gate

- Читать уже сохраненные server health snapshots.
- Показывать только агрегаты: количество серверов по состояниям, bucket возраста
  последней проверки и общий статус последнего scheduler run.
- Показывать admin analytics только как агрегированные widgets: users/orders/devices
  by status, servers by status и aggregate traffic totals.

## Заблокировано без named gate

- live probes и любое выполнение SSH, Docker, AWG или иных remote commands.
- raw check output, endpoint host export и command output.
- per-peer health fields, peer public key, client config и VPN import URI.
- per-user breakdown, Telegram ID, username, email и device name.

## Gate model

- P6-M002 требуется перед включением health/status polling scheduler, если он
  запускает live probes или извлекает raw operation output.
- P6-N002 требуется перед любым per-user или per-peer analytics detail view.
- API/web responses должны оставаться aggregate-only и не содержать raw secrets,
  public tokens, endpoint host, command text или config delivery artifacts.
