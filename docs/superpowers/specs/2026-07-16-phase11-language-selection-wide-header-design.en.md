# Phase 11: language-selection wide header image

Date: 2026-07-16

Status: the operator approved this design with
`APPROVE_LANGUAGE_SELECTION_NEW_WIDE_HEADER_SCOPE` as part of the approved
recommended Phase 11 chain.

## Goal

Replace the old square image that the Telegram bot shows after `/start` beside
the language-selection buttons with the operator-provided wide image. The new
PNG is used only as the language-selection screen header. The existing square
canonical logo remains unchanged for the web UI and other square placements.

This slice is a local source-tree change. It does not call the Telegram API,
send a message through the real bot, change the Telegram profile photo, upload
or apply a production overlay, mutate a VPS, start the persistent bot, or stop
or restart production AWG.

## Source asset

The operator supplied:

```text
C:\Users\SooL\Downloads\Сгенерированное изображение 1 (16).png
```

Verified properties:

- format: PNG;
- dimensions: `1672 x 941`;
- file size: `2647131` bytes;
- SHA-256: `BBDDFA72D1D1FC37E412D2F4A9B4124001FF91FBD641635E31A47E008FC4611F`.

The repository receives an exact byte-for-byte copy without redrawing,
re-encoding, cropping, or changing the image text.

## Considered approaches

### A. Separate role-specific asset — selected

Add a separate wide asset for the language-selection screen and switch only
`handle_start` to the new path. Preserve the old square bot asset and
`brand-full.png`.

Benefits: the format matches the Telegram header; the web UI does not receive an
unsuitable wide image; every asset has an explicit role; rollback changes only
one reference. Cost: the repository keeps two images with different roles.

### B. Overwrite the existing bot asset — rejected

Keep the old filename but replace its contents. This reduces the code diff but
hides the role change and complicates verification and rollback. The old name
also participates in the current square-brand contract.

### C. Replace bot and web branding with one wide asset — rejected

This would create one new visual identity but would break the square
login/dashboard layout and expand the task beyond the operator request.

## Architecture and components

### New asset

Add:

```text
app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png
```

The name describes the role instead of a temporary version. The existing
`app/bot/assets/NEOBYATNAYA-AMNZ-BOT.png` and
`app/web/static/brand-full.png` files remain unchanged and are not removed.

### `app/bot/assets.py`

Add dedicated constants for the language-selection header name and path. Keep
the existing square bot constants to avoid hidden incompatibility for future or
external consumers.

### `app/bot/handlers.py`

`handle_start` uses the new language-selection path in `answer_photo`. The
caption and inline keyboard remain unchanged:

```text
🌐 Выберите язык / Choose your language:
🇷🇺 Русский | 🇬🇧 English
```

User registration and selected-language handling do not change. If the new file
is missing, retain the current fail-soft fallback: send the same text and
keyboard through `answer`, without falling back to the old image. This exposes a
package-completeness issue instead of silently restoring obsolete branding.

## Data flow

1. The user sends `/start`.
2. The handler registers the user through the existing workflow.
3. The handler checks for the new local wide-header asset.
4. When present, the Telegram photo message contains the new asset, the existing
   caption, and the existing language buttons.
5. When missing, the bot sends a text-only language selector.
6. The chosen-language callback continues through the existing locale/menu flow
   unchanged.

## Errors and security

- A repository-owned static constant constructs the path; there is no
  user-controlled path.
- Runtime does not download the asset from the network.
- The new contract adds no token, Telegram ID, VPS address, or other secret.
- PNG metadata/chunks, secrets, and the diff are reviewed before commit.
- A missing asset does not block language selection or initiate a network
  fallback.
- Production rollout remains a separate exact approval gate.

## TDD and verification

First change the existing handler test to expect the new role-specific filename;
it is RED before implementation. Then add or update checks that prove:

- `/start` sends the wide-header asset with the existing caption and language
  keyboard;
- the repository asset exists, is a `1672 x 941` PNG, and has the approved
  SHA-256;
- the square bot and web assets remain unchanged;
- the text-only fallback works when the language-header asset is absent;
- locale callback and main-menu regressions remain unchanged;
- the package/build contract includes the new file.

After GREEN, run scoped bot/asset/package tests, the full source test suite,
compile/toolchain checks, `git diff --check`, diff review, and security review.

## Documentation and delivery

After implementation, synchronize the current Phase 11 status/handoff
documents. Commit the design, plan, source, tests, and status changes as
intentional commits and push them to the trusted origin branch
`codex-vps-test-prep`. These commits perform no production apply.

## Acceptance criteria

- `/start` uses the exact approved wide image on the language-selection screen.
- The caption, buttons, registration, and locale flow are functionally
  unchanged.
- The square canonical logo and web UI images are preserved byte-for-byte.
- A missing wide asset produces a safe text-only selector.
- All scoped and full tests pass; diff/security review reports no unresolved
  findings or secrets.
- The production bot remains inactive/disabled and production AWG is untouched.
