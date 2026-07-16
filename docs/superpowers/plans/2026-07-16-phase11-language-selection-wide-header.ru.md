# Phase 11: план реализации широкого заголовка выбора языка

> **Для agentic workers:** ОБЯЗАТЕЛЬНЫЙ SUB-SKILL: используйте `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans` для пошагового выполнения. Шаги используют checkbox-синтаксис (`- [ ]`) для отслеживания.

**Цель:** показывать точное утверждённое широкое изображение после `/start` на экране выбора языка, сохранив квадратный canonical brand для web и других ролей.

**Архитектура:** новый PNG получает отдельный role-specific constant в `app.bot.assets`; `handle_start` использует только этот path и сохраняет text-only fallback. Asset integrity и wheel inclusion становятся отдельными тестируемыми контрактами; существующие square assets не изменяются.

**Технологии:** Python 3.12, aiogram 3, pytest 8, setuptools 69+, PNG binary header, Git.

## Глобальные ограничения

- Новый asset является точной побайтовой копией `C:\Users\SooL\Downloads\Сгенерированное изображение 1 (16).png`.
- Требуемые dimensions: `1672 x 941`; SHA-256: `BBDDFA72D1D1FC37E412D2F4A9B4124001FF91FBD641635E31A47E008FC4611F`.
- `app/bot/assets/NEOBYATNAYA-AMNZ-BOT.png` и `app/web/static/brand-full.png` не изменять и не удалять.
- Caption, language buttons, registration и locale callback flow не менять.
- Missing wide asset должен давать text-only selector без fallback к старому изображению.
- Никаких Telegram API calls, live bot messages, profile-photo changes, VPS/provider mutations, production overlay apply или AWG restart/stop.
- `docs/CLIENT_RELEASE_MONITOR_BASELINE.ru.md` и посторонние untracked paths не трогать.

---

### Task 1: role-specific asset и package contract

**Files:**
- Create: `tests/bot/test_bot_assets.py`
- Create: `app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png`
- Modify: `app/bot/assets.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: repository-owned `BOT_ASSETS_DIR: pathlib.Path`.
- Produces: `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME: str` и `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH: pathlib.Path`.

- [ ] **Step 1: написать failing asset/package tests**

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

- [ ] **Step 2: запустить тесты и подтвердить RED**

Run:

```powershell
python -m pytest tests/bot/test_bot_assets.py -q
```

Expected: collection FAIL, потому что `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME`
и `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH` ещё отсутствуют.

- [ ] **Step 3: скопировать exact asset и добавить минимальный contract**

Copy exact bytes:

```powershell
Copy-Item -LiteralPath 'C:\Users\SooL\Downloads\Сгенерированное изображение 1 (16).png' -Destination 'app\bot\assets\NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png'
```

Добавить в `app/bot/assets.py`, сохранив существующие constants:

```python
BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME = (
    "NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png"
)
BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH = (
    BOT_ASSETS_DIR / BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME
)
```

Добавить в `pyproject.toml`:

```toml
[tool.setuptools.package-data]
"app.bot" = ["assets/*.png"]
```

- [ ] **Step 4: подтвердить GREEN и неизменность square brand**

Run:

```powershell
python -m pytest tests/bot/test_bot_assets.py tests/web/test_app.py::test_bot_and_web_use_the_same_canonical_brand_asset -q
```

Expected: `3 passed`.

- [ ] **Step 5: commit asset contract**

```powershell
git add pyproject.toml app/bot/assets.py app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png tests/bot/test_bot_assets.py
git commit -m "Add Phase 11 language header asset"
```

### Task 2: `/start` handler и безопасный fallback

**Files:**
- Modify: `tests/bot/test_bot_handlers.py`
- Modify: `app/bot/handlers.py`

**Interfaces:**
- Consumes: `BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH: pathlib.Path` из Task 1.
- Produces: прежний `async handle_start(message, *, workflow) -> None` с новым image path и неизменным fallback contract.

- [ ] **Step 1: изменить expected filename и добавить failing fallback test**

Заменить существующий filename assertion на:

```python
assert message.photos[0]["photo"].path.endswith(
    "NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png"
)
```

Добавить рядом:

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

- [ ] **Step 2: запустить primary test и подтвердить RED**

Run:

```powershell
python -m pytest tests/bot/test_bot_handlers.py::test_handle_start_sends_header_and_language_choices_with_russian_default -q
```

Expected: FAIL, потому что handler ещё отправляет
`NEOBYATNAYA-AMNZ-BOT.png`.

- [ ] **Step 3: переключить handler на role-specific constant**

В `app/bot/handlers.py` заменить import на:

```python
from app.bot.assets import BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH
```

В `handle_start` заменить обе ссылки на старый path:

```python
if BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH.exists():
    await message.answer_photo(
        FSInputFile(str(BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH)),
        caption=render_language_prompt(),
        reply_markup=build_language_keyboard(),
    )
    return
```

- [ ] **Step 4: подтвердить handler GREEN**

Run:

```powershell
python -m pytest tests/bot/test_bot_handlers.py tests/bot/test_bot_assets.py -q
```

Expected: all tests PASS.

- [ ] **Step 5: commit handler switch**

```powershell
git add app/bot/handlers.py tests/bot/test_bot_handlers.py
git commit -m "Use wide header for language selection"
```

### Task 3: полная верификация и security/diff review

**Files:**
- Inspect: all files changed after `bb45185`
- Build artifact: temporary wheel under `dist/` or an isolated temporary directory; do not commit it

**Interfaces:**
- Consumes: commits from Tasks 1–2.
- Produces: reproducible test, build, diff, metadata and security evidence.

- [ ] **Step 1: выполнить scoped tests**

```powershell
python -m pytest tests/bot/test_bot_assets.py tests/bot/test_bot_handlers.py tests/web/test_app.py -q
```

Expected: all scoped tests PASS.

- [ ] **Step 2: выполнить полный source suite и compile check**

```powershell
python -m pytest -q
python -m compileall -q app tests
```

Expected: full suite PASS с только уже известными skip/warning; compile exit `0`.

- [ ] **Step 3: проверить wheel inclusion**

```powershell
python -m build --wheel
```

Открыть созданный wheel как ZIP и подтвердить наличие
`app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png` с утверждённым SHA-256.
Expected: path present, exact hash match. Build output не stage/commit.

- [ ] **Step 4: выполнить diff и PNG metadata review**

```powershell
git diff bb45185..HEAD --check
git diff --stat bb45185..HEAD
git status --short --branch
```

Разобрать PNG chunks и убедиться, что нет secret-bearing `tEXt`, `zTXt`,
`iTXt` или `eXIf` payload. Подтвердить SHA-256 обоих square assets как
`40ACD9465DC9FDA06644D2D829DA996E1D9BF6C856E95298B624B31154FEC791`.

- [ ] **Step 5: выполнить `codex-security:security-diff-scan`**

Scope: Git diff `bb45185..HEAD`. Проверить path traversal, unsafe runtime
download, secret/metadata leakage, package omission и незапланированные live
side effects. Expected: no reportable finding; при finding сначала исправить и
полностью повторить нужный RED/GREEN и scan.

### Task 4: Phase 11 status sync, commits и push

**Files:**
- Modify in root docs branch: `docs/PROJECT_STATUS_CURRENT.ru.md`
- Modify in root docs branch: `docs/AMN2_PHASE_11_CURRENT_PRIORITY_PLAN.ru.md`
- Modify in root docs branch: `docs/NEXT_CHAT_AMN2_PHASE_11_CONTROLLED_LAUNCH_AND_OPERATIONS.ru.md`

**Interfaces:**
- Consumes: exact source HEAD, test totals and security receipt from Task 3.
- Produces: current Phase 11 source pin and updated combined-overlay next gate.

- [ ] **Step 1: push verified source branch**

```powershell
git status --short --branch
git push origin codex-vps-test-prep
```

Expected: local `codex-vps-test-prep` equals trusted origin.

- [ ] **Step 2: синхронизировать root status без посторонних файлов**

В трёх перечисленных документах записать exact 40-character source HEAD,
фактические scoped/full test totals, clean security result и новый task
`PHASE11-BRAND-002` как completed-local. Обновить combined package candidate с
`08c56f2` на exact verified HEAD. Сохранить production overlay `801f8c3`, bot
`inactive_disabled`, AWG `running_restart_0_peers_12_set_unchanged`, sealed
fallback и second-VPS handover constraints.

- [ ] **Step 3: проверить root docs suite и scope**

```powershell
python -m pytest -q
git diff --check
git status --short --branch
```

Expected: root suite PASS; изменены только три named docs, а
`.codex-security-worker-b-writeup/` и
`docs/CLIENT_RELEASE_MONITOR_BASELINE.ru.md` остаются untracked и untouched.

- [ ] **Step 4: commit и push root docs**

```powershell
git add docs/PROJECT_STATUS_CURRENT.ru.md docs/AMN2_PHASE_11_CURRENT_PRIORITY_PLAN.ru.md docs/NEXT_CHAT_AMN2_PHASE_11_CONTROLLED_LAUNCH_AND_OPERATIONS.ru.md
git commit -m "Sync Phase 11 language header status"
git push origin codex-spark-phase9-docs-sync
```

Expected: docs branch equals trusted origin; preserved untracked paths не
staged.

- [ ] **Step 5: финальная readback verification**

Подтвердить обе branch tips через `git log -1`, `git status --short --branch` и
remote-tracking refs. Итоговый отчёт должен перечислить commits, test totals,
security result и явно подтвердить: production не менялся, regular bot не
запускался, AWG не затронут.
