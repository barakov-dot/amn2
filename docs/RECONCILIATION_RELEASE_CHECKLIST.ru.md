# Attach-existing-server and release checklist boundary

Документ фиксирует Phase 6 границу для `P6-M003` и `P6-S001`.
Это local-only planning/security/productization slice: attach-existing-server
reconciliation можно описывать как safe report and checklist, но нельзя
превращать в live reconciliation без отдельного named gate.

## Разрешено без отдельного gate

- Сравнивать сохраненный server config, redacted peer inventory, operator-supplied
  mapping и aggregate health/status только в виде безопасного summary.
- Готовить adoption plan summary, blocked action list и manual gate checklist.
- Вести release checklist, changelog draft и operator-only release notes.
- Различать current branch head, latest VPS-smoked package head и package status
  for branch head.

## Заблокировано без named gate

- live reconciliation или любой импорт peer/user/device state в production.
- Создание локальных devices из remote peer inventory.
- Удаление peers, overwrite server config, write API enablement и Local Agent
  mutation.
- package apply/rebuild on VPS, public exposure, config delivery, backup/import
  and production peer/user mutation.

## Release checklist

Перед public release должны быть закрыты как отдельные named gates:

- `P6-C001` Public exposure gate.
- `P6-C002` Config delivery gate.
- `P6-C003` Write API production gate.
- `P6-C004` Production backup/restore/import gate.
- `P6-M003 apply gate` before any reconciliation apply behavior.

Default action remains `planning_only` until these gates are explicitly opened.
