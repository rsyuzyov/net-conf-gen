# `scan_state.json` Schema

Документ фиксирует текущую семантику полей в `output/<domain>/scan_state.json`.

Принцип:

- этап `1` (`discovery`) пишет только сетевые факты и осторожные эвристики;
- этап `1.5` (`web probe`) пишет structured HTTP/HTTPS/TLS fingerprint только для web-портов;
- этап `2` (`authenticated enrichment`) при успешном `SSH`/`WinRM`/`PsExec` становится источником истины;
- поле `auth_method` означает только **успешный** метод авторизации;
- информация о доступных по сети протоколах определяется по `open_ports` и `services`, а не по `auth_method`.

## Поля

| Поле | Смысл | Как заполняется |
|---|---|---|
| `ip` | IPv4-адрес хоста | Этап `1`, из целевого IP при discovery. Обязательное поле. |
| `open_ports` | Список открытых TCP-портов из целевого набора | Этап `1`, native TCP connect scan по портам из `ports.json`. |
| `services` | Человекочитаемые ярлыки сервисов для `open_ports` | Этап `1`, маппинг `port -> service label` из `ports.json`. Это не banner detection, а нормализованное имя сервиса по порту. |
| `service_details` | Детали сервиса по каждому открытому порту | Этап `1`, словарь `port -> {name, product, version, extrainfo, tunnel}`. В native discovery сейчас в основном содержит `product=<label из ports.json>`, остальные поля обычно пусты. |
| `web_probes` | Structured web/TLS fingerprint по web-портам | Этап `1.5`, словарь `port -> {scheme, reachable, status_code, server, title, content_type, location, final_url, www_authenticate, auth_scheme, redirect_to_login, is_login_page, tls_subject, tls_issuer, tls_san, tls_not_before, tls_not_after, error}`. |
| `hostnames` | Список hostname-кандидатов из discovery | Этап `1`, сейчас может заполняться через PTR/reverse DNS. Может уточняться на этапе `2`. |
| `hostname` | Основной hostname хоста | Приоритет: 1) этап `2`, успешный auth-коннектор; 2) PTR/reverse DNS на этапе `1`. Если успешный auth не вернул hostname и PTR отсутствует, поле может остаться пустым даже при `scan_status=completed`. |
| `mac` | MAC-адрес | Этап `1`, из локального `arp -a`; этап `2` может уточнить через коннектор. |
| `vendor` | Нормализованный vendor устройства/системы | Discovery-эвристики и/или этап `2`. После успешного auth может быть пересчитан через `determine_vendor_model()`. Это интерпретационное поле, не первичный факт. |
| `model` | Модель/платформа/уточнение типа ОС | Discovery-эвристики и/или этап `2`. После успешного auth обычно отражает подтверждённую платформу или distribution. |
| `os` | Основная строка ОС | Приоритет: 1) успешный auth; 2) discovery-эвристика. После успешного auth discovery-guess должен считаться переопределённым. |
| `os_type` | Нормализованный тип ОС | Одно из значений: `linux`, `windows`, либо пусто. На этапе discovery ставится только при достаточной уверенности. После успешного auth пересчитывается заново. |
| `category` | Внутренняя категория для логики pipeline | Обычно одно из: `linux`, `windows`, `network`, `mikrotik`, `printer`, `camera`, `ipkvm`, `unknown`. На этапе discovery это guess, после успешного auth это финальная категория. |
| `type` | Итоговый тип хоста для inventory/reporting | Обычно одно из: `server`, `workstation`, `network`, `mikrotik`, `printer`, `camera`, `ipkvm`, `unknown`. На этапе discovery ставится только при достаточной уверенности. После успешного auth пересчитывается заново. |
| `scan_status` | Итоговый статус обработки хоста | `discovered`: найден discovery, этап `2` ещё не отработал. `completed`: есть успешная авторизация и получены authenticated facts. `virtualization_completed`: прямой вход не удался, но trusted-данные о хосте подтверждены через этап `3` с виртуализационного хоста (текущая реализация: PVE CT и PVE VM с чтением config/guest-agent, если доступен). `web_completed`: прямого входа не было, но через trusted unauthenticated web probe удалось уверенно определить web-managed host типа `printer` или `ipkvm` с `vendor` и `model`. `auth_available_no_access`: сетевой протокол auth-доступа есть, но авторизация не удалась. `scanned`: этап `2`/`3` завершён без успешного обогащения. |
| `auth_method` | **Метод успешной авторизации** | Заполняется только при успешном `SSH`/`WinRM`/`PsExec`. Возможные значения: `ssh`, `winrm`, `psexec`. Если успешной авторизации не было, поле должно быть пустым. |
| `user` | Пользователь успешной авторизации | Заполняется только вместе с `auth_method`. Если успешной авторизации не было, поле должно быть пустым. |
| `key_path` | Путь к SSH-ключу, если успех был по ключу | Заполняется только при успешном `SSH` по ключу. |
| `auth_attempts` | Попытки аутентификации текущего/последнего запуска stage `2` | Этап `2`, список объектов вида `{method, user, status, error}`. Перед новым scan для хоста очищается и заполняется заново. Используется для диагностики, а не как первичный факт о хосте. |
| `auth_methods` | Внутренний технический след методов текущего/последнего запуска, по которым были auth-attempts или auth-fail | Этап `2`. Перед новым scan для хоста очищается и строится заново. Поле служебное и не должно трактоваться как “успешные методы подключения”. Для пользовательской логики ориентироваться на `auth_method`, а для сетевой доступности на `open_ports` и `services`. |
| `distribution` | Уточнённый distribution/название ОС из authenticated source | Обычно ставится SSH-коннектором для Linux/OpenWrt/Buildroot и используется как сильный сигнал для финальной классификации. |
| `kernel_version` | Версия ядра/OS build из authenticated source | Этап `2`, из успешного коннектора. |
| `success` | Legacy/connector helper flag | Может присутствовать после успешного auth. Семантически дублирует `scan_status=completed` и не должен использоваться как основной статус. |
| `last_updated` | Время последнего изменения записи | Заполняется storage на любом обновлении записи. |

## Правила интерпретации

### 1. Что считается фактом discovery

К discovery-facts относятся:

- `ip`
- `open_ports`
- `services`
- `service_details`
- `web_probes`
- `mac`

Эти поля можно считать данными этапа `1`.

### 2. Что считается подтверждённым фактом

К authenticated-facts относятся:

- `auth_method`
- `user`
- `hostname`
- `os`
- `distribution`
- `kernel_version`

Если `auth_method` не пустой, именно эти данные имеют приоритет над discovery-эвристиками.

### 3. Как понимать `auth_method`

`auth_method`:

- показывает только успешный метод авторизации;
- не описывает просто “доступный протокол”;
- не должен быть заполнен при `auth_available_no_access`, `scanned`, `virtualization_completed` или `web_completed`.

Примеры:

- `open_ports=[22]`, `auth_method=""`, `scan_status="auth_available_no_access"`: SSH по сети доступен, но войти не удалось.
- `open_ports=[22]`, `auth_method="ssh"`, `scan_status="completed"`: SSH по сети доступен и вход успешен.
- `open_ports=[22,5432]`, `auth_method=""`, `scan_status="virtualization_completed"`: прямой вход на хост не подтвердился, но trusted данные о контейнере/госте получены через этап виртуализации.
- `open_ports=[80,443]`, `auth_method=""`, `scan_status="web_completed"`: прямого входа не было, но через web UI без авторизации удалось надёжно определить управляемое устройство.

### 4. Как понимать `auth_methods`

`auth_methods` не является пользовательским полем результата.

Оно означает:

- какие методы участвовали в auth-attempts;
- по каким методам был зафиксирован auth-fail или success.

Для определения успешного входа нужно смотреть только на `auth_method`.

### 4.1. Что сбрасывается перед новым stage `2`

Если хост заново идёт в authenticated enrichment, перед попытками подключения очищаются:

- `auth_attempts`
- `auth_methods`
- `auth_method`
- `user`
- `key_path`

То есть `scan_state.json` отражает состояние последнего прогона stage `2` по каждому хосту, а не накопительную историю за всё время.

### 5. Когда `hostname` может быть пустым при `completed`

Это допустимо, если:

- авторизация успешна;
- коннектор не смог достоверно получить hostname.

Типичный пример: часть OpenWrt/embedded-хостов.

## Этап 3: Virtualization Enrichment

Текущая реализация:

- работает только после этапа `2`;
- рассматривает только хосты с `scan_status != completed`;
- использует только trusted PVE-хосты, к которым уже есть прямой успешный SSH;
- собирает guest inventory из `pct list/config/exec` для CT и из `qm list/config/guest cmd` для VM;
- никогда не заполняет `auth_method`, `user`, `key_path` для guest-хоста, если прямого входа не было.

### Правила merge для этапа 3

- если direct-auth (`completed`) уже есть, этап `3` этот хост не трогает;
- guest сопоставляется с discovered host сначала по `ip`, затем по уникальному `mac`;
- если один и тот же `ip` или `mac` встречается у нескольких virtualization guests, совпадение считается неоднозначным и такой host **не** переводится в `virtualization_completed`;
- `virtualization_completed` ставится только если после такого сопоставления удалось получить достаточно trusted-данных о guest.

## Этап 1.5: Web Probe

Текущая реализация:

- выполняется после discovery и до authenticated enrichment;
- работает только по портам web-класса: `80`, `443`, `8080`, `8443`, `8006`, `4081`, `5000`, `5001`, `9090`, `3000`, `4040`, `10000`, `8291`, `8728`;
- не пытается логиниться и не использует default creds;
- собирает только безопасные признаки сервиса и сертификата.

### Что считается trusted web-fact

К trusted web-facts относятся:

- HTTP status code
- redirect target
- `Server`
- `WWW-Authenticate`
- HTML `title`
- `Content-Type`
- TLS subject / issuer / SAN / validity

Эти данные могут использоваться для пересчёта discovery-эвристик `vendor`, `model`, `category`, `type`, но не считаются authenticated access.

### Когда web probe поднимает `web_completed`

Текущая реализация:

- только если у хоста нет `completed` или `virtualization_completed`;
- только для `type in {printer, ipkvm}`;
- только если после web probe есть уверенные `vendor` и `model`.
