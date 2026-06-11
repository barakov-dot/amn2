# Runtime/toolchain contract

Этот документ фиксирует локальный runtime-контракт AMN2 для Phase 5.

## Поддерживаемый Python

Поддерживаемый runtime для текущего gate: CPython 3.12.x.

Проверенная локальная версия: CPython 3.12.13.

`pyproject.toml` намеренно ограничен как `>=3.12,<3.13`. Python 3.14 не
считается поддержанным runtime для этого gate: перед переходом на него нужен
отдельный upgrade-slice с пересборкой зависимостей, focused tests и полным
`pytest`.

Проверить текущий интерпретатор:

```powershell
python -m app.toolchain check
```

Ожидаемый успешный вывод:

```text
AMN2 toolchain ok: CPython 3.12.x.
```

## Windows PowerShell bootstrap

Для каждого git worktree создаем отдельный `.venv` внутри этого worktree.
Правило: не использовать `.venv` из соседнего worktree. На Windows это ломает
sandbox/permissions и делает результаты тестов менее воспроизводимыми.

Создать окружение:

```powershell
py -3.12 -m venv .venv
```

Обновить pip:

```powershell
.venv\Scripts\python.exe -m pip install --upgrade pip
```

Поставить проект с dev-зависимостями:

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Проверить runtime:

```powershell
.venv\Scripts\python.exe -m app.toolchain check
```

Запустить полный локальный test suite:

```powershell
.venv\Scripts\python.exe -m pytest tests -v
```

## Linux bootstrap

Создать окружение:

```bash
python3.12 -m venv .venv
```

Активировать и поставить зависимости:

```bash
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Проверить runtime и тесты:

```bash
python -m app.toolchain check
python -m pytest tests -v
```

## Package/VPS gate

Перед любым package rebuild, VPS deploy или live write/config gate нужно:

1. Выбрать конкретный AMN2 git commit.
2. Создать чистое CPython 3.12.x окружение.
3. Выполнить `python -m app.toolchain check`.
4. Выполнить focused tests для измененного slice.
5. Выполнить полный `python -m pytest tests -v`.

Эта проверка не включает live VPS commands, не открывает public API, не меняет
peer/user/config и не выполняет backup/import/reboot.
