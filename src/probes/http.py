"""HTTP probe — получение title и body с веб-страниц."""
import re
import ssl
import html as html_module
import logging

logger = logging.getLogger(__name__)

# Порты, которые обычно используют HTTPS
HTTPS_PORTS = {443, 4081, 5001, 8006, 8443, 10000}

# Все HTTP-подобные порты для сканирования
HTTP_PORTS = {80, 443, 3000, 4040, 4081, 5000, 5001, 8006, 8080, 8443, 10000}


def get_http_title(ip, port=80, timeout=3, return_body=False):
    """Получить <title> с HTTP-страницы.

    Args:
        ip: IP адрес
        port: порт
        timeout: таймаут
        return_body: если True, возвращает кортеж (title, body_snippet)

    Returns:
        str | tuple: title или (title, body) если return_body=True
    """
    try:
        import urllib.request
        import urllib.error
        scheme = 'https' if port in HTTPS_PORTS else 'http'
        url = f"{scheme}://{ip}:{port}/"
        req = urllib.request.Request(url, headers={'User-Agent': 'net-conf-gen/1.0'})
        ctx = None
        if scheme == 'https':
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            read_size = 32768 if return_body else 4096
            body = response.read(read_size).decode('utf-8', errors='ignore')
            title = ''
            match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
            if match:
                title = html_module.unescape(match.group(1).strip())
            if return_body:
                return title, body
            return title
    except Exception:
        pass
    if return_body:
        return '', ''
    return ''


def scan_http_ports(ip, open_ports, deep=False):
    """Собрать HTTP titles (и body при deep=True) со всех HTTP-портов.

    Args:
        ip: IP адрес
        open_ports: список открытых портов
        deep: если True, собирает body для анализа

    Returns:
        dict: {'titles': {port: title}, 'bodies': {port: body}, 'primary_title': str}
    """
    ports = set(open_ports) & HTTP_PORTS
    titles = {}
    bodies = {}

    for port in sorted(ports):
        title, body = get_http_title(ip, port=port, timeout=3, return_body=True)
        if title:
            titles[port] = title
            logger.info(f"  HTTP title {ip}:{port} = {title[:60]}")
        if deep and body:
            bodies[port] = body

    primary_title = ''
    if titles:
        primary_port = 80 if 80 in titles else min(titles.keys())
        primary_title = titles[primary_port]

    return {
        'titles': titles,
        'bodies': bodies,
        'primary_title': primary_title,
    }
