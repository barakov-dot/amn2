# Phase 11 Language-Selection Wide Header Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** show the exact approved wide image after `/start` on the language-selection screen while preserving the square canonical brand for the web and other roles.

**Architecture:** a new PNG receives a dedicated role-specific constant in `app.bot.assets`; `handle_start` uses only that path and retains the text-only fallback. Asset integrity and wheel inclusion become explicit tested contracts, while existing square assets remain unchanged.

**Tech Stack:** Python 3.12, aiogram 3, pytest 8, setuptools 69+, PNG binary header, Git.

## Global Constraints

- The new asset is an exact byte-for-byte copy of `C:\Users\SooL\Downloads\Сгенерированное изображение 1 (16).png`.
- Required dimensions: `1672 x 941`; SHA-256: `BBDDFA72D1D1FC37E412D2F4A9B4124001FF91FBD641635E31A47E008FC4611F`.
- Do not change or remove `app/bot/assets/NEOBYATNAYA-AMNZ-BOT.png` or `app/web/static/brand-full.png`.
- Do not change the caption, language buttons, registration, or locale callback flow.
- A missing wide asset must produce the text-only selector without falling back to the old image.
- Do not call the Telegram API, send a live bot message, change the profile photo, mutate a VPS/provider, apply a production overlay, or restart/stop AWG.
- Do not touch `docs/CLIENT_RELEASE_MONITOR_BASELINE.ru.md` or unrelated untracked paths.

---

### Task 1: role-specific asset and package contract

**Files:**
- Create: `tests/bot/test_bot_assets.py`
- Create: `app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png`
- Modify: `app/bot/assets.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: repository-owned `BOT_ASSETS_DIR: pathlib.Path`.
- Produces: `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME: str` and `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH: pathlib.Path`.

- [ ] **Step 1: write the failing asset/package tests**

```python
import hashlib
import struct
import tomllib
from pathlib import Path

from app.bot.assets import (
    BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME,
    BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH,
)


def test_language_selection_header_has_approved_identity_and_dimensions():
    image_bytes = BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH.read_bytes()

    assert BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME == (
        "NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png"
    )
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", image_bytes[16:24]) == (1672, 941)
    assert hashlib.sha256(image_bytes).hexdigest() == (
        "bbddfa72d1d1fc37e412d2f4a9b4124001ff91fbd641635e31a47e008fc4611f"
    )


def test_bot_png_assets_are_included_in_setuptools_package_data():
    repository_root = Path(__file__).resolve().parents[2]
    config = tomllib.loads((repository_root / "pyproject.toml").read_text("utf-8"))

    assert "assets/*.png" in config["tool"]["setuptools"]["package-data"][
        "app.bot"
    ]
```

- [ ] **Step 2: run the tests and confirm RED**

Run:

```powershell
python -m pytest tests/bot/test_bot_assets.py -q
```

Expected: collection FAIL because `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME`
and `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH` do not exist yet.

- [ ] **Step 3: copy the exact asset and add the minimal contract**

Copy exact bytes:

```powershell
Copy-Item -LiteralPath 'C:\Users\SooL\Downloads\Сгенерированное изображение 1 (16).png' -Destination 'app\bot\assets\NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png'
```

Add to `app/bot/assets.py`, preserving the existing constants:

```python
BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME = (
    "NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png"
)
BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH = (
    BOT_ASSETS_DIR / BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME
)
```

Add to `pyproject.toml`:

```toml
[tool.setuptools.package-data]
"app.bot" = ["assets/*.png"]
```

- [ ] **Step 4: confirm GREEN and square-brand immutability**

Run:

```powershell
python -m pytest tests/bot/test_bot_assets.py tests/web/test_app.py::test_bot_and_web_use_the_same_canonical_brand_asset -q
```

Expected: `3 passed`.

- [ ] **Step 5: commit the asset contract**

```powershell
git add pyproject.toml app/bot/assets.py app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png tests/bot/test_bot_assets.py
git commit -m "Add Phase 11 language header asset"
```

### Task 2: `/start` handler and safe fallback

**Files:**
- Modify: `tests/bot/test_bot_handlers.py`
- Modify: `app/bot/handlers.py`

**Interfaces:**
- Consumes: `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH: pathlib.Path` from Task 1.
- Produces: the existing `async handle_start(message, *, workflow) -> None` with the new image path and unchanged fallback contract.

- [ ] **Step 1: change the expected filename and add the failing fallback test**

Replace the existing filename assertion with:

```python
assert message.photos[0]["photo"].path.endswith(
    "NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png"
)
```

Add nearby:

```python
def test_handle_start_uses_text_only_selector_when_language_header_is_missing(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        "app.bot.handlers.BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH",
        tmp_path / "missing-language-header.png",
    )
    message = FakeMessage(user_id=9001, first_name="Admin")
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_start(message, workflow=workflow))

    assert workflow.registered_users == [9001]
    assert message.photos == []
    assert message.answers[0]["text"] == (
        "🌐 Выберите язык / Choose your language:"
    )
    assert _button_texts(message.answers[0]["reply_markup"]) == [
        ["🇷🇺 Русский", "🇬🇧 English"]
    ]
```

- [ ] **Step 2: run the primary test and confirm RED**

Run:

```powershell
python -m pytest tests/bot/test_bot_handlers.py::test_handle_start_sends_header_and_language_choices_with_russian_default -q
```

Expected: FAIL because the handler still sends `NEOBYATNAYA-AMNZ-BOT.png`.

- [ ] **Step 3: switch the handler to the role-specific constant**

In `app/bot/handlers.py`, replace the import with:

```python
from app.bot.assets import BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH
```

In `handle_start`, replace both references to the old path:

```python
if BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH.exists():
    await message.answer_photo(
        FSInputFile(str(BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH)),
        caption=render_language_prompt(),
        reply_markup=build_language_keyboard(),
    )
    return
```

- [ ] **Step 4: confirm handler GREEN**

Run:

```powershell
python -m pytest tests/bot/test_bot_handlers.py tests/bot/test_bot_assets.py -q
```

Expected: all tests PASS.

- [ ] **Step 5: commit the handler switch**

```powershell
git add app/bot/handlers.py tests/bot/test_bot_handlers.py
git commit -m "Use wide header for language selection"
```

### Task 3: full verification and security/diff review

**Files:**
- Inspect: every file changed after `bb45185`
- Build artifact: temporary wheel under `dist/` or an isolated temporary directory; do not commit it

**Interfaces:**
- Consumes: commits from Tasks 1–2.
- Produces: reproducible test, build, diff, metadata, and security evidence.

- [ ] **Step 1: run scoped tests**

```powershell
python -m pytest tests/bot/test_bot_assets.py tests/bot/test_bot_handlers.py tests/web/test_app.py -q
```

Expected: all scoped tests PASS.

- [ ] **Step 2: run the full source suite and compile check**

```powershell
python -m pytest -q
python -m compileall -q app tests
```

Expected: the full suite passes with only the previously known skip/warning;
compile exits `0`.

- [ ] **Step 3: verify wheel inclusion**

```powershell
python -m build --wheel
```

Open the resulting wheel as a ZIP and confirm that
`app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png` exists with the approved
SHA-256. Expected: path present, exact hash match. Do not stage or commit build
output.

- [ ] **Step 4: run diff and PNG metadata review**

```powershell
git diff bb45185..HEAD --check
git diff --stat bb45185..HEAD
git status --short --branch
```

Parse PNG chunks and confirm there is no secret-bearing `tEXt`, `zTXt`, `iTXt`,
or `eXIf` payload. Confirm that both square assets still have SHA-256
`40ACD9465DC9FDA06644D2D829DA996E1D9BF6C856E95298B624B31154FEC791`.

- [ ] **Step 5: run `codex-security:security-diff-scan`**

Scope: Git diff `bb45185..HEAD`. Review path traversal, unsafe runtime download,
secret/metadata leakage, package omission, and unplanned live side effects.
Expected: no reportable finding; if a finding exists, fix it first and repeat
the required RED/GREEN cycle and scan.

### Task 4: Phase 11 status sync, commits, and push

**Files:**
- Modify in root docs branch: `docs/PROJECT_STATUS_CURRENT.ru.md`
- Modify in root docs branch: `docs/AMN2_PHASE_11_CURRENT_PRIORITY_PLAN.ru.md`
- Modify in root docs branch: `docs/NEXT_CHAT_AMN2_PHASE_11_CONTROLLED_LAUNCH_AND_OPERATIONS.ru.md`

**Interfaces:**
- Consumes: the exact source HEAD, test totals, and security receipt from Task 3.
- Produces: the current Phase 11 source pin and updated combined-overlay next gate.

- [ ] **Step 1: push the verified source branch**

```powershell
git status --short --branch
git push origin codex-vps-test-prep
```

Expected: local `codex-vps-test-prep` equals trusted origin.

- [ ] **Step 2: synchronize root status without unrelated files**

In the three named documents, record the exact 40-character source HEAD, actual
scoped/full test totals, clean security result, and the new
`PHASE11-BRAND-002` task as completed-local. Move the combined-package candidate
from `08c56f2` to the exact verified HEAD. Preserve production overlay
`801f8c3`, bot `inactive_disabled`, AWG
`running_restart_0_peers_12_set_unchanged`, sealed fallback, and second-VPS
handover constraints.

- [ ] **Step 3: verify the root docs suite and scope**

```powershell
python -m pytest -q
git diff --check
git status --short --branch
```

Expected: root suite PASS; only the three named docs are changed, while
`.codex-security-worker-b-writeup/` and
`docs/CLIENT_RELEASE_MONITOR_BASELINE.ru.md` remain untracked and untouched.

- [ ] **Step 4: commit and push root docs**

```powershell
git add docs/PROJECT_STATUS_CURRENT.ru.md docs/AMN2_PHASE_11_CURRENT_PRIORITY_PLAN.ru.md docs/NEXT_CHAT_AMN2_PHASE_11_CONTROLLED_LAUNCH_AND_OPERATIONS.ru.md
git commit -m "Sync Phase 11 language header status"
git push origin codex-spark-phase9-docs-sync
```

Expected: the docs branch equals trusted origin; preserved untracked paths are
not staged.

- [ ] **Step 5: final readback verification**

Confirm both branch tips through `git log -1`, `git status --short --branch`,
and remote-tracking refs. The final report must list commits, test totals, and
the security result, and explicitly confirm that production did not change,
the regular bot did not start, and AWG was untouched.
