# Конфиг net-conf-gen

## Факты

- Канонический порядок ключей: `domain → targets → credentials → concurrency → ports_file → exclusions`. Поддерживается в [config.example.yaml](../../../../config.example.yaml) и в выводе мастера ([src/config_wizard.py](../../../../src/config_wizard.py)).
- `domain` опционален (пустая строка допустима). В `main.py` управляет подкаталогами `output/<domain>` и `log/<domain>`.
- Мастер пишет `config.yaml` через `yaml.dump(..., sort_keys=False)` — порядок ключей берётся из порядка добавления в dict в `create_config()`. При добавлении новых ключей сохраняй порядок и в example, и в мастере.

## Грабли

- ⚠️ На Windows `pip install --upgrade pip` ломает следующий вызов `pip` (race на pip.exe). Использовать `python -m pip` везде — это уже исправлено в [install.bat](../../../../install.bat).
- ⚠️ Если `pywinrm[credssp]` падает на установке (нет build tools), резолвер может оборвать установку и `pyyaml` не доедет. В `install.bat` добавлен fallback: `python -c "import yaml"` → явная установка `pyyaml`.
