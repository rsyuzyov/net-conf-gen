"""Стратегии сканирования для каждой категории устройств.

Каждая стратегия — упорядоченный список шагов.
Если шаг помечен stop_on_success=True, дальнейшие шаги пропускаются
когда этот шаг успешно собрал данные.
"""


class ScanStep:
    """Один шаг стратегии сканирования."""
    __slots__ = ('action', 'stop_on_success', 'params')

    def __init__(self, action, stop_on_success=False, **params):
        self.action = action
        self.stop_on_success = stop_on_success
        self.params = params

    def __repr__(self):
        return f"ScanStep({self.action!r}, stop={self.stop_on_success})"


# ===== Стратегии по категориям =====

STRATEGIES = {
    'windows': [
        ScanStep('reverse_dns'),
        ScanStep('connect_winrm', stop_on_success=True),
        ScanStep('connect_psexec', stop_on_success=True),
        ScanStep('connect_ssh'),
    ],
    'linux': [
        ScanStep('reverse_dns'),
        ScanStep('connect_ssh', stop_on_success=True),
        ScanStep('http_deep'),        # deep: NanoKVM, TP-Link с SSH, Proxmox
        ScanStep('snmp'),
    ],
    'mikrotik': [
        ScanStep('snmp'),
        ScanStep('connect_ssh'),
        ScanStep('reverse_dns'),
    ],
    'printer': [
        ScanStep('http_title'),
        ScanStep('snmp'),
        ScanStep('reverse_dns'),
    ],
    'camera': [
        ScanStep('http_title'),
        ScanStep('snmp'),
        ScanStep('reverse_dns'),
    ],
    'ipkvm': [
        ScanStep('http_deep'),
        ScanStep('reverse_dns'),
    ],
    'network': [
        ScanStep('http_deep'),        # body для TP-Link/ASUS/D-Link
        ScanStep('snmp'),
        ScanStep('ssl_cert'),
        ScanStep('reverse_dns'),
    ],
    'unknown': [
        ScanStep('reverse_dns'),
        ScanStep('snmp'),
        ScanStep('http_deep'),
        ScanStep('ssl_cert'),
        ScanStep('banner'),
        ScanStep('connect_ssh'),
        ScanStep('connect_winrm'),
    ],
}


def get_strategy(category):
    """Получить стратегию для категории. Fallback на 'unknown'."""
    return STRATEGIES.get(category, STRATEGIES['unknown'])
