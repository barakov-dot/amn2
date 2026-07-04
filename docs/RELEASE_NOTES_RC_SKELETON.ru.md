# AMN2 Release Notes RC Skeleton

Дата: 2026-06-14.

Статус: черновик release notes для будущего release candidate. Это не public
launch и не объявление релиза.

## Версия

```text
candidate_label=AMN2 RC TBD
current_local_head=b121865
known_good_vps_smoked_head=b121865
vps_apply_enabled_default=false
```

## Что Готово Локально

- fresh installer question/answer wizard;
- clean installer RC acceptance checklist;
- package and source asset path preflight for `b121865`;
- secret/input contract without raw secret rendering;
- multi-instance/IPAM conflict model review for clean installer decisions;
- API/docs taxonomy RC drift check;
- public/config/write prerequisite split;
- public exposure readiness design;
- config delivery channel readiness;
- write API scope decision with public API read-only for RC;
- backup/restore/import readiness checklist;
- Telegram identity/profile/media readiness checklist;
- operator-local evidence templates.

## Что Не Открыто

- public exposure;
- config delivery, QR, `.conf` and import links;
- write API and install mutations;
- Local Agent mutations;
- backup, restore and import;
- destructive cleanup/reinstall;
- Telegram identity/profile/media mutations.

## Evidence Placeholders

```text
local_package_preflight=recorded
local_full_tests=recorded
live_vps_smoke=passed-for-b121865-under-P7-C001
public_exposure=not-opened
config_delivery=not-opened
write_api=not-opened
backup_restore_import=not-opened
destructive_execution=not-opened
telegram_identity=not-opened
```

## Operator Notes

- `b121865` is the latest known-good VPS-smoked/package baseline after the
  named `P7-C001` live package/apply/smoke gate.
- `0de7a77` remains previous known-good history/rollback evidence.
- Any future release note that mentions live smoke must cite the named gate,
  package checksum, source checksum and smoke evidence.
- Public launch, public exposure, config delivery, write API, backup/import,
  destructive execution and Telegram mutation remain unopened until exact named
  gates.
