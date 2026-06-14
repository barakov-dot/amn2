# AMN2 Multi-Instance / IPAM Conflict Model

Дата: 2026-06-14.

Статус: Phase 6 local-only `P6-M005`.

Этот документ фиксирует будущую модель конфликтов для нескольких VPN runtime
instances, ports and IPAM planning. Он не включает live multi-instance apply,
не меняет firewall, не пишет runtime config и не выдает пользовательские
конфиги.

## Gate

```text
gate=local-only/docs/tests
live_multi_instance_apply_allowed=false
write_api_required_before_apply=P6-C003
config_delivery_required_before_user_output=P6-C002
```

## Required Checks

- `unique_runtime_instance_id`;
- `unique_listen_port_per_instance`;
- `non_overlapping_vpn_cidr`;
- `unique_interface_name`;
- `endpoint_pair_review`;
- `dns_ipv6_policy_review`.

## Safe Outputs

- `conflict_report`;
- `operator_notes`;
- `blocked_gate_summary`.

## Blocked Outputs

- `runtime_config_write`;
- `firewall_change`;
- `peer_migration`;
- `config_delivery`;
- `service_restart`.

## Negative Controls

- no live VPS commands;
- no SSH commands;
- no write API;
- no config delivery;
- no Local Agent mutation;
- no production peer/user mutation;
- no upstream/GPL code copy.
