# Client-specific import naming: local export API

2026-09-08. Local implementation; client import and deployment are NOT verified.
Target display name is `Neobyatnaya.NET` (15 characters).

`app.vpn.config_templates.build_client_import_artifact(config_text,
target_client=..., existing_names=...)` returns an in-memory artifact:

- `amneziawg`: `Neobyatnaya.NET.conf`, original UTF-8 content unchanged, no vpn link.
- `amneziavpn`: `Neobyatnaya.NET.vpn`, Qt-compressed Amnezia JSON containing
  description, normalized connection metadata and the unchanged raw config.
- `defaultvpn`: same envelope, explicitly marked unverified; published source
  may replace MTU. Verify the installed version and every protocol field before use.

The existing `build_vpn_import_link` API accepts explicit `target_client` for
native exports. Calls without it retain their legacy byte-for-byte behavior.
Existing delivery handlers are not switched to the new mode. No Telegram send,
web route, DB, issuance policy, existing peer or stored config is changed.
The standalone artifact API supplies the exact filename without changing internal
identity or historical artifact filenames.

The accepted input is one Interface and one Peer, supported WG/AWG fields only,
with explicit endpoint port and one or two IP DNS addresses. Unknown fields,
duplicate sections/keys, executable hooks, ambiguous PSK aliases, invalid address
shape and a supplied existing name collision fail closed with fixed error codes.
This is an export-shape validator, not a full protocol/key validity checker.
No keys are created, resolved or read; no filesystem/network IO occurs.
The artifact's content and link are excluded from repr, but are still secrets
when the caller supplies real material. Do not log or publish either value.

`existing_names` must come from the caller's permitted client inventory; omission
is not proof of no conflict. The function never writes or replaces a file/tunnel.
Native QR compatibility and automatic collision resolution are not implemented.
Do not append a suffix to the Android name: it already uses its 15-character limit.

Verification: synthetic-only TDD, initially 17 failed / 1 passed (missing API).
Final targeted command covers test_client_import_artifacts, test_config_templates,
and bot/test_delivery: 51 passed. Includes AWG3/3.1 field preservation, exact raw
round-trip including CRLF, DNS/MTU, IPv6 endpoint, conflicts, unknown fields and
legacy delivery regression. No Qt/iOS/native import or VPN connectivity test.

Wire-format references (read for interoperability; no upstream code copied):
- https://github.com/amnezia-vpn/amnezia-client/blob/5.0.1.5/client/core/controllers/selfhosted/importController.cpp
- https://github.com/amnezia-vpn/amnezia-client/blob/5.0.1.5/client/core/utils/constants/configKeys.h
- https://github.com/amnezia-vpn/amnezia-client/blob/5.0.1.5/client/core/controllers/selfhosted/exportController.cpp
- https://github.com/amnezia-vpn/DefaultVPN/blob/3cee753b9fb3658ddebdc0982036979e08c7d8ba/client/ui/controllers/importController.cpp

Next: separately permitted isolated client import acceptance; only then select the
new mode in delivery. Live material handling and deployment require their exact
gates. Package016, AWG2 runtime and general issuance remain untouched.
