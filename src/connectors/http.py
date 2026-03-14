"""
HTTP-коннектор для проверки дефолтных учётных данных на веб-интерфейсах.

Поддерживаемые методы аутентификации:
- HTTP Basic Auth
- HTTP Digest Auth
- HTTP POST (form-encoded)
- HTTP POST (JSON)
- Проверка доступа без аутентификации
"""
import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import base64
import hashlib
import logging
import os
import re

logger = logging.getLogger(__name__)


def load_default_credentials(config_path='default_credentials.json'):
    """Загружает базу дефолтных учётных данных."""
    if not os.path.isabs(config_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(script_dir))
        config_path = os.path.join(project_root, config_path)

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logger.info(f"Загружено {len(data)} записей дефолтных учётных данных")
        return data
    except FileNotFoundError:
        logger.warning(f"Файл дефолтных учёток не найден: {config_path}")
        return []
    except Exception as e:
        logger.error(f"Ошибка загрузки дефолтных учёток: {e}")
        return []


def _match_entry(entry, host_info):
    """
    Проверяет, подходит ли запись из default_credentials.json для данного хоста.
    
    Returns:
        bool: True если запись подходит
    """
    match_rules = entry.get('match', {})
    
    if match_rules.get('_fallback'):
        return True  # Fallback — подходит ко всем
    
    open_ports = host_info.get('open_ports', [])
    entry_ports = entry.get('ports', [])
    
    # Проверяем что хотя бы один порт из entry открыт
    if not any(p in open_ports for p in entry_ports):
        return False
    
    # Проверяем type
    if 'type' in match_rules:
        if host_info.get('type', '') != match_rules['type']:
            return False
    
    # Проверяем vendor
    if 'vendor' in match_rules:
        host_vendor = host_info.get('vendor', '').lower()
        if match_rules['vendor'].lower() not in host_vendor:
            return False
    
    # Проверяем services_contain
    if 'services_contain' in match_rules:
        services = host_info.get('services', [])
        keyword = match_rules['services_contain'].lower()
        if not any(keyword in s.lower() for s in services):
            return False
    
    # Проверяем http_title_contains
    if 'http_title_contains' in match_rules:
        http_title = host_info.get('http_title', '').lower()
        if match_rules['http_title_contains'].lower() not in http_title:
            return False
    
    return True


def _get_ssl_context():
    """Создаёт SSL-контекст без проверки сертификатов."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_url(ip, port, path):
    """Строит URL с определением протокола по порту."""
    scheme = 'https' if port in (443, 4081, 5001, 8006, 8443, 10000) else 'http'
    return f"{scheme}://{ip}:{port}{path}"


def _format_url(url_template, user, password):
    """Подставляет user/password в URL-шаблон."""
    return url_template.replace('{user}', urllib.parse.quote(user)).replace('{password}', urllib.parse.quote(password))


def _format_post_data(data_template, user, password):
    """Подставляет user/password в шаблон POST-данных (рекурсивно)."""
    if isinstance(data_template, str):
        return data_template.replace('{user}', user).replace('{password}', password)
    elif isinstance(data_template, dict):
        return {k: _format_post_data(v, user, password) for k, v in data_template.items()}
    elif isinstance(data_template, list):
        return [_format_post_data(v, user, password) for v in data_template]
    return data_template


def _check_success(response_code, response_body, success_indicator):
    """Проверяет ответ по критериям успеха."""
    allowed_statuses = success_indicator.get('status', [200])
    
    if response_code not in allowed_statuses:
        # 401 — явно не подошло
        if response_code == 401:
            return False
        # Для http_basic: 401 = нужна авторизация, 200 = успех
        # Если получили 200, а ждали 200 — ок
        if response_code not in allowed_statuses:
            return False
    
    body_keyword = success_indicator.get('body_contains', '')
    if body_keyword:
        if body_keyword.lower() not in response_body.lower():
            return False
    
    return True


def _try_http_basic(ip, port, path, user, password, success_indicator, timeout=5):
    """Проверка HTTP Basic Auth."""
    url = _build_url(ip, port, path)
    
    credentials_str = f"{user}:{password}"
    b64 = base64.b64encode(credentials_str.encode()).decode()
    
    req = urllib.request.Request(url)
    req.add_header('Authorization', f'Basic {b64}')
    req.add_header('User-Agent', 'net-conf-gen/1.0')
    
    try:
        ctx = _get_ssl_context() if url.startswith('https') else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode('utf-8', errors='ignore')
            if _check_success(resp.status, body, success_indicator):
                return {
                    'success': True,
                    'auth_type': 'http_basic',
                    'user': user,
                    'password': password,
                    'http_status': resp.status,
                    'port': port
                }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None  # Неверные учётки
        logger.debug(f"HTTP Basic {ip}:{port} — HTTP {e.code}")
    except Exception as e:
        logger.debug(f"HTTP Basic {ip}:{port} — {e}")
    
    return None


def _try_http_digest(ip, port, path, user, password, success_indicator, timeout=5):
    """Проверка HTTP Digest Auth (упрощённая реализация)."""
    url = _build_url(ip, port, path)
    
    try:
        ctx = _get_ssl_context() if url.startswith('https') else None
        
        # Шаг 1: получить challenge (nonce)
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'net-conf-gen/1.0')
        
        try:
            urllib.request.urlopen(req, timeout=timeout, context=ctx)
            # Если прошло без 401 — аутентификация не требуется
            return {
                'success': True,
                'auth_type': 'http_no_auth',
                'user': '',
                'password': '',
                'http_status': 200,
                'port': port
            }
        except urllib.error.HTTPError as e:
            if e.code != 401:
                return None
            www_auth = e.headers.get('WWW-Authenticate', '')
            if 'Digest' not in www_auth:
                return None
        
        # Шаг 2: парсим challenge
        realm_m = re.search(r'realm="([^"]*)"', www_auth)
        nonce_m = re.search(r'nonce="([^"]*)"', www_auth)
        qop_m = re.search(r'qop="([^"]*)"', www_auth)
        
        if not realm_m or not nonce_m:
            return None
        
        realm = realm_m.group(1)
        nonce = nonce_m.group(1)
        qop = qop_m.group(1) if qop_m else None
        
        # Шаг 3: строим Digest-ответ
        ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"GET:{path}".encode()).hexdigest()
        
        if qop:
            nc = '00000001'
            cnonce = hashlib.md5(os.urandom(8)).hexdigest()[:16]
            response_hash = hashlib.md5(
                f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
            ).hexdigest()
            auth_header = (
                f'Digest username="{user}", realm="{realm}", '
                f'nonce="{nonce}", uri="{path}", '
                f'qop={qop}, nc={nc}, cnonce="{cnonce}", '
                f'response="{response_hash}"'
            )
        else:
            response_hash = hashlib.md5(
                f"{ha1}:{nonce}:{ha2}".encode()
            ).hexdigest()
            auth_header = (
                f'Digest username="{user}", realm="{realm}", '
                f'nonce="{nonce}", uri="{path}", '
                f'response="{response_hash}"'
            )
        
        req2 = urllib.request.Request(url)
        req2.add_header('Authorization', auth_header)
        req2.add_header('User-Agent', 'net-conf-gen/1.0')
        
        with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode('utf-8', errors='ignore')
            if _check_success(resp.status, body, success_indicator):
                return {
                    'success': True,
                    'auth_type': 'http_digest',
                    'user': user,
                    'password': password,
                    'http_status': resp.status,
                    'port': port
                }
    except Exception as e:
        logger.debug(f"HTTP Digest {ip}:{port} — {e}")
    
    return None


def _try_http_post_form(ip, port, path, user, password, post_data_template, success_indicator, timeout=5):
    """Проверка через HTTP POST (form-encoded)."""
    url = _build_url(ip, port, _format_url(path, user, password))
    
    if post_data_template:
        data = _format_post_data(post_data_template, user, password)
        encoded = urllib.parse.urlencode(data).encode()
    else:
        encoded = None
    
    req = urllib.request.Request(url, data=encoded, method='POST')
    req.add_header('User-Agent', 'net-conf-gen/1.0')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    
    try:
        ctx = _get_ssl_context() if url.startswith('https') else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode('utf-8', errors='ignore')
            if _check_success(resp.status, body, success_indicator):
                return {
                    'success': True,
                    'auth_type': 'http_post_form',
                    'user': user,
                    'password': password,
                    'http_status': resp.status,
                    'port': port
                }
    except urllib.error.HTTPError as e:
        # Некоторые API возвращают 302 при успешном логине
        if e.code in success_indicator.get('status', []):
            return {
                'success': True,
                'auth_type': 'http_post_form',
                'user': user,
                'password': password,
                'http_status': e.code,
                'port': port
            }
        logger.debug(f"HTTP POST form {ip}:{port} — HTTP {e.code}")
    except Exception as e:
        logger.debug(f"HTTP POST form {ip}:{port} — {e}")
    
    return None


def _try_http_post_json(ip, port, path, user, password, post_data_template, success_indicator, timeout=5):
    """Проверка через HTTP POST (JSON body)."""
    url = _build_url(ip, port, _format_url(path, user, password))
    
    if post_data_template:
        data = _format_post_data(post_data_template, user, password)
        body_bytes = json.dumps(data).encode()
    else:
        body_bytes = None
    
    req = urllib.request.Request(url, data=body_bytes, method='POST')
    req.add_header('User-Agent', 'net-conf-gen/1.0')
    req.add_header('Content-Type', 'application/json')
    
    try:
        ctx = _get_ssl_context() if url.startswith('https') else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode('utf-8', errors='ignore')
            if _check_success(resp.status, body, success_indicator):
                return {
                    'success': True,
                    'auth_type': 'http_post_json',
                    'user': user,
                    'password': password,
                    'http_status': resp.status,
                    'port': port
                }
    except urllib.error.HTTPError as e:
        logger.debug(f"HTTP POST JSON {ip}:{port} — HTTP {e.code}")
    except Exception as e:
        logger.debug(f"HTTP POST JSON {ip}:{port} — {e}")
    
    return None


def _try_http_no_auth(ip, port, path, success_indicator, timeout=5):
    """Проверка доступа без аутентификации (принтеры, etc)."""
    url = _build_url(ip, port, path)
    
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'net-conf-gen/1.0')
    
    try:
        ctx = _get_ssl_context() if url.startswith('https') else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode('utf-8', errors='ignore')
            if _check_success(resp.status, body, success_indicator):
                return {
                    'success': True,
                    'auth_type': 'http_no_auth',
                    'user': '',
                    'password': '',
                    'http_status': resp.status,
                    'port': port
                }
    except urllib.error.HTTPError as e:
        logger.debug(f"HTTP no-auth {ip}:{port} — HTTP {e.code}")
    except Exception as e:
        logger.debug(f"HTTP no-auth {ip}:{port} — {e}")
    
    return None


def check_default_credentials(ip, host_info, default_creds_db=None):
    """
    Проверяет дефолтные учётные данные для хоста.
    
    Args:
        ip: IP-адрес
        host_info: dict с информацией о хосте из storage
        default_creds_db: список записей из default_credentials.json (опционально)
    
    Returns:
        dict: Результат проверки или None
        {
            'vendor_matched': 'MikroTik',
            'port': 80,
            'auth_type': 'http_basic',
            'default_creds_found': True/False,
            'user': 'admin',
            'password': '',
            'attempts': [...]
        }
    """
    if default_creds_db is None:
        default_creds_db = load_default_credentials()
    
    if not default_creds_db:
        return None
    
    open_ports = host_info.get('open_ports', [])
    
    # HTTP-подобные порты
    http_ports = {80, 443, 3000, 4040, 4081, 5000, 5001, 8006, 8080, 8443, 10000}
    has_http = bool(http_ports & set(open_ports))
    
    if not has_http:
        return None
    
    results = {
        'default_creds_found': False,
        'attempts': []
    }
    
    # Находим подходящие записи (не-fallback сначала)
    matched_entries = []
    fallback_entries = []
    
    for entry in default_creds_db:
        if _match_entry(entry, host_info):
            if entry.get('match', {}).get('_fallback'):
                fallback_entries.append(entry)
            else:
                matched_entries.append(entry)
    
    # Используем конкретные записи, если они есть; иначе fallback
    entries_to_try = matched_entries if matched_entries else fallback_entries
    
    if not entries_to_try:
        return None
    
    for entry in entries_to_try:
        vendor = entry.get('vendor', '')
        auth_type = entry.get('auth_type', '')
        check_url = entry.get('check_url', '/')
        success_indicator = entry.get('success_indicator', {'status': [200]})
        post_data = entry.get('post_data', None)
        creds = entry.get('credentials', [])
        entry_ports = entry.get('ports', [])
        
        # Определяем порты для проверки
        ports_to_check = [p for p in entry_ports if p in open_ports]
        
        if not ports_to_check:
            continue
        
        for port in ports_to_check:
            if auth_type == 'http_no_auth':
                result = _try_http_no_auth(ip, port, check_url, success_indicator)
                attempt = {
                    'vendor': vendor,
                    'port': port,
                    'auth_type': auth_type,
                    'user': '',
                    'status': 'success' if result else 'failed'
                }
                results['attempts'].append(attempt)
                
                if result:
                    results.update({
                        'vendor_matched': vendor,
                        'port': port,
                        'auth_type': auth_type,
                        'default_creds_found': True,
                        'user': '',
                        'password': '',
                        'web_accessible': True
                    })
                    logger.info(f"  Веб-интерфейс {ip}:{port} доступен без аутентификации ({vendor})")
                    return results
                continue
            
            for cred in creds:
                user = cred['user']
                password = cred['password']
                
                result = None
                
                if auth_type == 'http_basic':
                    result = _try_http_basic(ip, port, check_url, user, password, success_indicator)
                elif auth_type == 'http_digest':
                    result = _try_http_digest(ip, port, check_url, user, password, success_indicator)
                elif auth_type == 'http_post_form':
                    result = _try_http_post_form(ip, port, check_url, user, password, post_data, success_indicator)
                elif auth_type == 'http_post_json':
                    result = _try_http_post_json(ip, port, check_url, user, password, post_data, success_indicator)
                
                attempt = {
                    'vendor': vendor,
                    'port': port,
                    'auth_type': auth_type,
                    'user': user,
                    'status': 'success' if result else 'failed'
                }
                results['attempts'].append(attempt)
                
                if result:
                    results.update({
                        'vendor_matched': vendor,
                        'port': port,
                        'auth_type': auth_type,
                        'default_creds_found': True,
                        'user': user,
                        'password': password
                    })
                    pwd_display = password if password else '(пустой)'
                    logger.info(f"  ДЕФОЛТНЫЕ УЧЁТКИ НАЙДЕНЫ: {ip}:{port} ({vendor}) — {user}:{pwd_display}")
                    return results
    
    logger.debug(f"  Дефолтные учётки не подошли для {ip}")
    return results
