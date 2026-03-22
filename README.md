# net-conf-gen

`net-conf-gen` строит сетевой инвентарь в три этапа: сначала делает discovery, затем при необходимости выполняет authenticated enrichment через SSH/WinRM/PsExec и в конце генерирует артефакты для эксплуатации.

Результат:

- `inventory.yaml` для Ansible
- `ssh_config`
- `hosts.txt`
- отчеты в `html`, `csv`, `json`, `yaml`

## Архитектура

Текущий pipeline состоит из трех этапов:

1. `discovery`: быстрый native TCP/ARP discovery по целевым портам с первичной классификацией хостов
2. `scan`: optional authenticated enrichment через SSH/WinRM/PsExec
3. `report`: генерация inventory, `ssh_config` и отчетов из `scan_state.json`

Главный runtime-state хранится в `output/<domain>/scan_state.json`.

Схема и точная семантика полей описаны в [docs/scan_state_schema.md](./docs/scan_state_schema.md).

## Требования

- Python 3.12+
- сетевой доступ к целевым подсетям

## Установка

Linux:

```bash
chmod +x ./install.sh && ./install.sh
```

Windows:

```batch
./install.bat
```

## Конфиг

Базовый шаблон: [config.example.yaml](./config.example.yaml)

Ключевые поля:

- `targets`: список подсетей или адресов для сканирования
- `exclusions`: IP-адреса, которые нужно исключить из discovery
- `ports_file`: JSON с перечнем целевых портов и их display-именами
- `credentials`: учётные данные для этапа authenticated enrichment
- `concurrency`: параллелизм authenticated enrichment

При первом запуске без `config.yaml` запускается интерактивный wizard.

## Использование

Полный запуск:

```bash
python main.py
```

Покомпонентно:

```bash
# Справка
python main.py --help

# Только discovery
python main.py --step discovery

# Только authenticated enrichment
python main.py --step scan

# Только генерация отчетов
python main.py --step report

# Один хост
python main.py --host 10.0.0.1 --force --debug
```

## Smoke Check

Быстрая проверка после установки:

```bash
python -m unittest discover -s tests -v
python main.py --config config.yaml --step discovery --host 10.0.0.1 --debug
python main.py --config config.yaml --step report
```

## Выходные файлы

Для `domain: example.local` артефакты будут созданы в:

- `output/example.local/scan_state.json`
- `output/example.local/inventory.yaml`
- `output/example.local/ssh_config`
- `output/example.local/scan_report.html`
- `output/example.local/scan_report.csv`
- `output/example.local/scan_report.json`

Пример HTML-отчета: [docs/scan_report.html](./docs/scan_report.html)
