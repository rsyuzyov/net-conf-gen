"""Общие утилиты net-conf-gen."""
import logging
import re
import socket

logger = logging.getLogger(__name__)


def ip_to_int(ip):
    """Convert IP address to integer for proper sorting."""
    try:
        parts = ip.split('.')
        return int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])
    except Exception as e:
        logger.warning(f"Некорректный IP при сортировке: {ip}, {e}")
        return 0


def decode_windows_output(data: bytes) -> str:
    """Декодирует вывод cmd.exe / WinRM: UTF-8 (с BOM) → cp1251 → cp866 → latin-1."""
    if not data:
        return ''
    # Удаляем BOM если есть
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    for enc in ('utf-8', 'cp1251', 'cp866', 'latin-1'):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode('utf-8', errors='replace')


def normalize_os_name(os_str: str) -> str:
    """Нормализация имени ОС.

    - Майкрософт → Microsoft
    - Кракозябры (???? Windows 10 Pro) → Microsoft Windows 10 Pro
    """
    if not os_str or not isinstance(os_str, str):
        return os_str or ''

    # Нормализация «Майкрософт» → «Microsoft»
    if 'Майкрософт' in os_str:
        os_str = os_str.replace('Майкрософт', 'Microsoft')

    # Кракозябры в начале
    if re.match(r'^\?{3,}\s+', os_str):
        os_str = re.sub(r'^\?+\s*', 'Microsoft ', os_str)

    return os_str


def reverse_dns_name(ip: str) -> tuple[str, list[str]]:
    """Возвращает canonical hostname и aliases через PTR lookup.

    Returns:
        tuple[str, list[str]]: (hostname, hostnames)
    """
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return '', []

    names = []
    for candidate in [hostname, *aliases]:
        value = str(candidate).strip().lower().rstrip('.')
        if value and value not in names:
            names.append(value)

    if not names:
        return '', []

    primary = names[0]
    short = primary.split('.')[0]
    return short, names
