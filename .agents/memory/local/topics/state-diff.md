# State diff и история хоста

## Факты

- Модуль [src/state_diff.py](../../../../src/state_diff.py) даёт два режима:
  - **diff** между двумя `scan_state.json`: добавленные/удалённые/изменённые хосты со сводкой переходов `scan_status` / `category` / `type` / `os_type` и глубоким diff по `web_probes` / `service_details` (added/removed/changed порты с подсветкой полей внутри).
  - **history** одного хоста: timeline снимков из `backups/scan_state_*.json` + текущий `scan_state.json`. Подсветка полей, изменившихся относительно предыдущего снимка.
- Интегрирован в [src/reporting.py](../../../../src/reporting.py): метод `_generate_state_diff()` запускается из `generate_all()` и пишет `output/<domain>/scan_diff.html`, сравнивая последний бэкап с текущим состоянием. Backup в `Storage.__init__` создаётся ДО прогона → diff показывает «что изменилось за этот прогон».
- CLI:
  ```
  python -m src.state_diff diff <prev.json> <curr.json> [--out diff.html]
  python -m src.state_diff history <ip> --state-dir output/<domain> [--out hist.html]
  ```
- `auth_attempts` в diff показывает таблицу попыток нового снимка с error-сообщением (для отладки логина).
- `web_probes` / `service_details` сравниваются по портам: добавленный порт показывает первые 3 поля (server/title/...), удалённый — то же из старого снимка, изменённый — таблицу полей со старым/новым значением.

## Грабли

- ⚠️ Если запускать `--step report` сразу после прошлого прогона без изменений — diff будет пустым (бэкап и текущее состояние идентичны). Это норма, не баг.
- ⚠️ История ограничена ротацией бэкапов в `Storage` (`BACKUP_KEEP = 30`). Старее 30 прогонов истории нет.
