# Enrichment и inventory

## Факты

- Приоритетный протокол подключения — SSH для всех категорий хостов (включая Windows). Заходит в [src/enrichment.py](../../../../src/enrichment.py) в `_protocol_order`.
- Soft-upgrade: при повторном запуске без `--force` хосты со статусом `completed`, у которых `auth_method != 'ssh'` и открыт порт 22, повторно пробуются по SSH. При успехе запись обновляется. Хосты, у которых уже `ssh` или нет 22, не трогаются.
- `--force` переопрашивает все хосты заново, с тем же порядком протоколов.
- Группы в инвентаре: `managed/linux/{linux_ssh, linux_workstations_ssh}`, `managed/windows/{windows_ssh, windows_winrm, windows_psexec}`, `managed/devices_ssh`. Имя `linux_servers_ssh` переименовано в `linux_ssh`.
- `_write_group_vars` сам удаляет файлы `group_vars/*.yml` для несуществующих групп — переименование подхватывается на следующем `--step report`.

## Эвристика по web-сигналам

- `src/vendor_db.SERVER_HEADER_SIGNATURES` — таблица `Server`-header → hints (`category`, `type`, `vendor`, `device_family`). Покрывает: Virata-EmWeb (network/embedded), Allegro-Rompager (network, часто Digi/UPS), RAID HTTPServer (network), WMI V* (Mobotix camera), gSOAP (ONVIF camera), MikroTik HttpProxy, MiniServ (Webmin → linux/server).
- `extract_model_from_realm` — парсит модель из `WWW-Authenticate: Basic realm="<MODEL>"`. Подходит для switches вроде `GS1910-48`, `DGN3500`, etc.
- `collect_host_text` теперь включает `www_authenticate` и используется маркерами в `classification.py` (например, `gs1910` в `NETWORK_MARKERS`).
- В `_fetch_targeted_probe_metadata` (`src/web_probe.py`): `Server: gSOAP*` всегда триггерит ONVIF SOAP probe (`/onvif/device_service`, `/`) даже если хост не помечен как camera-like; список ONVIF портов расширен до `{80, 8899, 5000, 9090}`.
- `_https_context()` снижает SECLEVEL и допускает TLSv1+legacy renegotiation — иначе на embedded (APC PDU, старые switches/UPS) сплошной `SSLV3_ALERT_HANDSHAKE_FAILURE`. Есть DeprecationWarning на TLSv1 — допустимый шум.
- `_probe_port` делает fallback на `http` при SSL/handshake error (`WRONG_VERSION_NUMBER`, `UNSAFE_LEGACY_RENEGOTIATION_DISABLED`, etc.). В результирующем probe ставится `scheme_fallback_from: 'https'`. Закрывает кейс «:10000 объявлен https, но Webmin отдаёт plain http».

## Грабли

- **Discovery теперь настраивается через `config.yaml`** в блоке `discovery: {concurrency, timeout, retries}`. Раньше в [src/discovery.py](../../../../src/discovery.py) были жёсткие константы `CONCURRENCY_LIMIT=1000` и `TIMEOUT=0.5`. На Windows одновременных TCP-проверок > ~200 захлёбывается стек: SYN тонут в очереди, таймаут 0.5с истекает → порт ложно помечен закрытым → классификация теряет сигналы (Windows-WS без RDP, MikroTik без 8291/8728, Synology без 5000). Новые дефолты: concurrency 64, timeout 1.5с, retries 0.

- ⚠️ **gSOAP — это не только ONVIF.** Сетевые принтеры (Kyocera, HP) поднимают gSOAP-сервер для WSD (Web Services for Devices). Если просто использовать `gsoap`-сигнатуру для category=camera, принтеры ложно классифицируются как камеры. В [src/classification.py](../../../../src/classification.py) блок `_looks_like_printer` стоит ДО блока `CAMERA_MARKERS` — порядок важен, не менять.
- ⚠️ **WinRM и национальные локали.** На локализованной Win11 `Win32_OperatingSystem.Caption` через CIM/WMI приходит уже с символами `?` вместо национальных букв — известный баг CIM с длинными локализованными строками. Ни `[Console]::OutputEncoding=UTF8`, ни оборачивание в `ConvertTo-Json` не помогают: потеря происходит **на стороне источника**, до того как PS получает строку. Решение: читать `ProductName` из реестра `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion` — там строка корректная. Реализовано в [src/connectors/winrm.py](../../../../src/connectors/winrm.py) методом `_get_host_info` через единый `ConvertTo-Json`-блок. Нюанс: на Windows 11 `ProductName` в реестре застрял на «Windows 10 ...» (Microsoft не обновил поле), реальная мажорная версия определяется по `kernel_version` (10.0.22000+) через `windows_name_from_kernel`.
- **Storage семантика (обновлённая 2026-05-15).** `Storage.apply_discovery_snapshot(records, force=False)` в [src/storage.py](../../../../src/storage.py) применяет результат discovery к state по правилам:
  - Хост отсутствует в state → добавляем целиком.
  - Хост в state, `force=True` → полная замена.
  - Хост в state, `scan_status` НЕ в `{completed, virtualization_completed, web_completed}` → полная замена.
  - Хост в state, `scan_status` завершённый, `force=False` → не трогаем.
  - Хосты, отсутствующие в новом discovery, остаются в state без изменений.
- `--force` теперь влияет ТОЛЬКО на discovery. Параметр `force` убран из `enrich_host`/`enrich_all` в [src/enrichment.py](../../../../src/enrichment.py): authenticated scan обрабатывает только незавершённые хосты, для завершённых работает только soft-upgrade на SSH (если 22 открыт и метод не ssh).
- `scan_state.json` теперь имеет структуру `{"meta": {"version": 1, "last_scan": "..."}, "hosts": {<ip>: {...}}}`. Старый плоский формат `{<ip>: {...}}` читается backward-compat и при следующем `flush()` переписывается в новый.
- При создании `Storage` в `__init__` делается резервная копия текущего `scan_state.json` в `output/<domain>/backups/scan_state_<YYYYMMDD-HHMMSS>.json`. Ротация — последние 30 файлов.

- ⚠️ SSH-коннектор раньше брал любой stdout из `hostname`/`uname` без валидации. Embedded-устройства с собственным CLI (как «cmdstat ... COMMAND PROCESSING FAILED») возвращают ошибочный текст, который попадал в `hostname` и `os`. Теперь [src/connectors/ssh.py](../../../../src/connectors/ssh.py) валидирует: hostname по RFC-чарсету (без `\n\r\t:;`, без `---`, длина ≤ 253), os/distribution — single-line с лимитом длины.
- ⚠️ Если ни один Linux-маркер (os/distribution/kernel_version) не прочитан — `os_type` НЕ ставится в `'linux'`. Это критично: иначе любое embedded-устройство с SSH-сервером маскировалось под Linux server.
- ⚠️ Раньше для Windows порядок был `[winrm, psexec, ssh]` → группа `windows_ssh` никогда не наполнялась, даже если на хосте был SSH. Сейчас SSH идёт первым.
