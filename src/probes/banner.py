"""Banner grabbing probe — получение баннеров TCP-сервисов."""
import socket
import re
import logging

logger = logging.getLogger(__name__)

# Порты для banner grabbing
BANNER_PORTS = {22, 80, 8080, 21, 25}
EXTRA_BANNER_PORTS = {23, 554, 1433, 1521, 3306, 5432, 5900, 8291}


def grab_banner(ip, port, timeout=1):
    """Получить баннер сервиса.

    Returns:
        str | None: Текст баннера или None.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (80, 8080, 8000):
                sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
            elif port == 443:
                return None
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner
    except Exception as e:
        logger.debug(f"Banner grab failed {ip}:{port} - {e}")
        return None


def scan_banners(ip, open_ports, extra=False):
    """Собрать баннеры с портов.

    Args:
        ip: IP адрес
        open_ports: список открытых портов
        extra: включает дополнительные порты (23, 554, etc.)

    Returns:
        dict: {port: banner_text}
    """
    target_ports = BANNER_PORTS | EXTRA_BANNER_PORTS if extra else BANNER_PORTS
    ports = set(open_ports) & target_ports
    banners = {}

    for port in sorted(ports):
        banner = grab_banner(ip, port, timeout=1)
        if banner:
            banners[port] = banner[:200]
            logger.debug(f"Banner {ip}:{port} = {banner[:60]}")

    return banners
