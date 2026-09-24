# Соответствие требованиям хакатона

| Пункт ТЗ | Реализация | Проверка |
|---|---|---|
| 4.1.2 — без участия человека | CLI без input, все параметры до запуска | CLI tests |
| 4.1.3 — стабильный формат | Строгие контракты модели, report.schema.json | Client и report tests |
| 4.1.5 — не менять репозиторий | Только чтение, output вне цели, чистый checkout, сверка снимка | Inventory/output tests |
| 4.2 — основные модули | client, project, engine, reporting, CLI, workflow | Сквозные contract tests |
| 4.3.1 — push и отдельный шаг | Security assessment workflow | Реальный GitHub run после публикации |
| 4.3.2 — до merge/deploy | Зависимый delivery-gate; обязательный status check настраивает владелец | См. CI.md |
| 4.3.3 — коды 0/1/2 | decision и worker, неполный анализ → 2 | Gate/error tests |
| 4.3.4 — артефакты | upload-artifact с always; исключение внешнего сбоя по 4.7.3 | Workflow + первый реальный run |
| 4.3.5 — понятный лог | exit_code, violations, requirements | CLI tests |
| 4.3.6 — предупреждения не блокируют | EXTRA не влияет на код 1 | EXTRA-only test |
| 4.4.1–4.4.3 — весь проект | git ls-files, UTF-8/DOCX, конфигурации, зависимости и CI | Inventory и DOCX tests |
| 4.4.4 — ограниченный контекст | Все фрагменты → наблюдения → оценка по требованию → запросы диапазонов | Chunk/retrieval tests |
| 4.4.5 — отсутствие защиты | Явно включено в system/review и catalogue | Требует live-оценки качества модели |
| 4.5 — восемь требований | resources/requirements.json, один review для каждого | Все восемь статусов обязательны |
| 4.6 — отчёт | JSON + Markdown, локаторы, цитаты, критичность, рекомендации, SHA, времена, статусы | Schema/report tests |
| 4.7.1 — до 30 минут | По умолчанию 1500 с, максимум 1740 с, hard timeout | Timeout test; live-длительность ещё измерить |
| 4.7.2 — частичный отчёт при таймауте | Atomic checkpoint → report с incomplete | Timeout test |
| 4.7.3 — ошибка сервиса без отчёта | error.json + execution.log, удаление checkpoint/report | Provider failure test |
| 4.8.1 — отдельные дополнительные дефекты | additional_findings и EXTRA | EXTRA-only test |
| 4.9 — ограничения модели | Официальный DeepSeek, модель из окружения | Settings tests |
| Сдача — секреты не попадают в отчёт | Redactor до API и артефактов | Redaction tests; эвристические ограничения описаны |

## Что не подтверждено локальными тестами

Локальные тесты проверяют программный контракт и обработку ошибок. Они не измеряют полноту обнаружения реальных уязвимостей и отсутствие ложных срабатываний модели. Для этого нужны реальные вызовы DeepSeek, разрешённые тестовые версии, ручная проверка доказательств и сравнение с доступной разметкой.
