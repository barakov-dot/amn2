# AMN2 Public Docs/API Taxonomy Boundary

Дата: 2026-06-13.

Статус: Phase 6 local-only `P6-N001`.

Этот документ фиксирует public docs/API taxonomy. Он не публикует документацию,
не открывает API наружу и не включает public launch.

```text
publication_enabled=false
public_openapi_enabled=false
public_api_exposed=false
```

## Public-Safe Taxonomy

Публично безопасные категории только для будущих материалов:

- `product_overview`;
- `client_compatibility_guidance`;
- `operator_only_status_summary`;
- `support_intake_copy`.

Они могут описывать продукт, поддерживаемые клиенты, общую модель доступа и
безопасный support copy, но не должны раскрывать operational details.

## Operator-Private Taxonomy

Остается private/operator-only:

- web admin;
- integration status;
- aggregate metrics;
- users summary;
- Local Agent runtime summary.

Эти поверхности не становятся публичными от наличия taxonomy.

## Blocked Secret-Bearing Taxonomy

Остается blocked/gated:

- config delivery;
- tokenized config links;
- client config artifacts;
- device secret recovery.

Any real config delivery remains behind `P6-C002`.

## Blocked Write/Destructive Taxonomy

Остается blocked/gated:

- client write CRUD;
- peer apply/revoke;
- backup/restore/import;
- destructive cleanup.

Write API remains behind `P6-C003`. Destructive cleanup remains behind
`P6-C007`.

## Publication Gate

Actual publication requires `P6-C001 Public exposure gate` with listener,
firewall, auth/session/rate-limit, rollback and incident plan review.

This slice only names categories and safe fields. It does not publish OpenAPI,
public docs, public API, public web/admin, config delivery or write routes.
