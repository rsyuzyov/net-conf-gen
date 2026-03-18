"""Общие утилиты net-conf-gen."""
import logging

logger = logging.getLogger(__name__)


def ip_to_int(ip):
    """Convert IP address to integer for proper sorting."""
    try:
        parts = ip.split('.')
        return int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])
    except Exception as e:
        logger.warning(f"Некорректный IP при сортировке: {ip}, {e}")
        return 0
