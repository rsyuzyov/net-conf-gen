"""TTL ping — определение ОС по TTL."""
import subprocess
import platform
import re
import logging

logger = logging.getLogger(__name__)


def ping_ttl(ip, timeout=2):
    """Получить TTL через ping.

    Returns:
        int | None: TTL значение или None если ping не удался.
    """
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(
            ['ping', param, '1', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        ttl_match = re.search(r'TTL[=:]?\s*(\d+)', result.stdout, re.IGNORECASE)
        if ttl_match:
            return int(ttl_match.group(1))
    except Exception as e:
        logger.debug(f"Ping failed for {ip}: {e}")
    return None


def os_hint_from_ttl(ttl):
    """Грубое определение ОС по TTL.

    Returns:
        dict: {'os_type': ..., 'type': ...} или пустой dict.
    """
    if not ttl:
        return {}
    if 110 <= ttl <= 128:
        return {'os_type': 'windows'}
    elif 50 <= ttl <= 64:
        return {'os_type': 'linux'}
    elif ttl > 200:
        return {'os_type': 'linux', 'type': 'network'}
    return {}
