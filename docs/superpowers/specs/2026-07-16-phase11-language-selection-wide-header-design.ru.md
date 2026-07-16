# Phase 11: широкое изображение экрана выбора языка

Дата: 2026-07-16

Статус: дизайн одобрен оператором командой
`APPROVE_LANGUAGE_SELECTION_NEW_WIDE_HEADER_SCOPE` в составе утверждённой
рекомендуемой цепочки Phase 11.

## Цель

Заменить старое квадратное изображение, которое Telegram-бот показывает после
`/start` вместе с кнопками выбора языка, на предоставленное оператором широкое
изображение. Новый PNG используется только как заголовок экрана выбора языка.
Существующий квадратный canonical logo сохраняется без изменений для web UI и
других размещений с квадратным форматом.

Этот slice является локальным изменением source tree. Он не включает вызовы
Telegram API, отправку сообщения реальному боту, смену Telegram profile photo,
upload или apply production overlay, изменение VPS, запуск persistent bot либо
остановку/перезапуск production AWG.

## Исходный asset

Оператор предоставил файл:

```text
C:\Users\SooL\Downloads\Сгенерированное изображение 1 (16).png
```

Проверенные характеристики:

- формат: PNG;
- размер: `1672 x 941`;
- размер файла: `2647131` bytes;
- SHA-256: `BBDDFA72D1D1FC37E412D2F4A9B4124001FF91FBD641635E31A47E008FC4611F`.

Репозиторий получает точную побайтовую копию без перерисовки, перекодирования,
кадрирования или изменения текста на изображении.

## Рассмотренные варианты

### A. Отдельный role-specific asset — выбран

Добавить отдельный широкий asset для экрана выбора языка и переключить только
`handle_start` на новый путь. Старый квадратный bot asset и `brand-full.png`
сохраняются.

Плюсы: формат соответствует Telegram-заголовку; web UI не получает
неподходящее широкое изображение; назначение каждого asset явно; откат требует
изменить только одну ссылку. Минус: в репозитории остаются два изображения с
разными ролями.

### B. Перезаписать существующий bot asset — отклонён

Сохранить старое имя файла, но заменить его содержимое. Это уменьшает code diff,
однако скрывает изменение роли и усложняет проверку/откат. Кроме того, старое
имя связано с текущим square-brand contract.

### C. Заменить bot и web branding одним широким asset — отклонён

Такой вариант создаёт единый новый образ, но нарушает квадратную компоновку
login/dashboard и расширяет задачу за пределы запроса оператора.

## Архитектура и компоненты

### Новый asset

Добавляется:

```text
app/bot/assets/NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png
```

Имя описывает роль, а не временную версию. Исходный файл
`app/bot/assets/NEOBYATNAYA-AMNZ-BOT.png` и web asset
`app/web/static/brand-full.png` не изменяются и не удаляются.

### `app/bot/assets.py`

Добавляются отдельные constants для имени и пути language-selection header.
Существующие square bot constants сохраняются, чтобы не создавать скрытую
несовместимость для будущих или внешних consumers.

### `app/bot/handlers.py`

`handle_start` использует новый language-selection path при вызове
`answer_photo`. Caption и inline keyboard остаются прежними:

```text
🌐 Выберите язык / Choose your language:
🇷🇺 Русский | 🇬🇧 English
```

Регистрация пользователя и обработка выбранного языка не меняются. Если новый
файл отсутствует, сохраняется текущий fail-soft fallback: бот отправляет тот же
текст и keyboard через `answer`, без попытки использовать старое изображение.
Это делает проблему package completeness заметной и не возвращает UI скрыто к
устаревшему branding.

## Поток данных

1. Пользователь отправляет `/start`.
2. Handler регистрирует пользователя существующим workflow.
3. Handler проверяет наличие нового локального wide-header asset.
4. При наличии Telegram photo message содержит новый asset, прежний caption и
   прежние language buttons.
5. При отсутствии asset отправляется text-only language selector.
6. Callback выбранного языка продолжает существующий locale/menu flow без
   изменений.

## Ошибки и безопасность

- Путь строится из repository-owned static constant; user-controlled path нет.
- Asset не загружается из сети во время runtime.
- Токены, Telegram IDs, VPS addresses и другие секреты в новый contract не
  добавляются.
- Перед commit выполняются проверка PNG metadata/chunks, secret scan и diff
  review.
- Missing asset не блокирует выбор языка и не инициирует сетевой fallback.
- Production rollout остаётся отдельным exact approval gate.

## TDD и проверка

Сначала существующий handler test меняется так, чтобы ожидать новый role-specific
filename; до implementation это RED. Затем добавляются/обновляются проверки:

- `/start` отправляет wide-header asset с прежним caption и language keyboard;
- repository asset существует, является PNG размером `1672 x 941` и имеет
  утверждённый SHA-256;
- square bot и web assets не изменены;
- text-only fallback работает при отсутствии language-header asset;
- locale callback и main menu regressions не меняются;
- package/build contract включает новый файл.

После GREEN запускаются scoped bot/asset/package tests, полный source test suite,
compile/toolchain checks, `git diff --check`, diff review и security review.

## Документация и доставка

После реализации синхронизируются текущие Phase 11 status/handoff документы.
Design, plan, source, tests и status changes коммитятся осознанными commits и
push в trusted origin ветки `codex-vps-test-prep`. Никакой production apply не
выполняется в рамках этих commits.

## Критерии приёмки

- `/start` использует точную утверждённую широкую картинку на экране выбора
  языка.
- Caption, кнопки, registration и locale flow функционально не изменились.
- Квадратный canonical logo и web UI изображения сохранены побайтово.
- Отсутствующий wide asset приводит к безопасному text-only selector.
- Все scoped и full tests проходят; diff/security review не содержит открытых
  findings или секретов.
- Production bot остаётся inactive/disabled, production AWG не затронут.
