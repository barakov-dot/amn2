# AMN2 Destructive Cleanup Gate Checklist

Дата: 2026-06-13.

Статус: Phase 6 local-only `P6-C007` checklist-only.

```text
destructive_execution_enabled=false
cleanup_commands_enabled=false
mode=checklist-only
```

Этот документ фиксирует критерии будущего destructive cleanup/reinstall gate.
Он не разрешает зачистку VPS и не является инструкцией для выполнения команд.

## Required Named Gate

Destructive cleanup/reinstall can only start after the operator explicitly opens:

```text
P6-C007 Destructive cleanup/reinstall gate
```

## Required Preconditions

Before any destructive action:

- operator opens `P6-C007` by name;
- retention and data-loss decision is recorded;
- latest AMN2 head and package choice is recorded;
- rollback or rebuild stop criteria is recorded;
- operator-local secret handoff is ready;
- second confirmation is given before any destructive action.

## Blocked Without Gate

Blocked without the named gate:

- provider rebuild;
- disk wipe;
- service stop;
- database deletion;
- firewall/public listener change;
- live cleanup command execution.

## Safe Default Work

Allowed by default:

- checklist drafting;
- dry-run package selection notes;
- retention decision template;
- stop criteria template;
- secret handoff checklist.

## Stop Criteria

Stop immediately if:

- target VPS is not the explicitly named validation server;
- retention decision is missing or ambiguous;
- selected AMN2 head/package is not recorded;
- rollback/rebuild path is missing;
- operator-local secret handoff is not ready;
- requested action expands into public exposure, config delivery, write API,
  Local Agent mutation, backup/restore/import apply, production peer/user
  mutation or Telegram identity mutation without its own named gate.

`P6-C007` is not opened by this document.
