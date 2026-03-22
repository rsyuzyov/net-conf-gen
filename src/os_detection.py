"""Определение ОС по kernel version."""
import logging

logger = logging.getLogger(__name__)


# ===== Linux kernel version → distro heuristic =====
_LINUX_KERNEL_PATTERNS = [
    ('-pve', 'Proxmox VE (Debian)'),
    ('.el9', 'RHEL/CentOS/AlmaLinux 9'),
    ('.el8', 'RHEL/CentOS/AlmaLinux 8'),
    ('.el7', 'CentOS/RHEL 7'),
    ('.el6', 'CentOS/RHEL 6'),
    ('-amd64', 'Debian'),
    ('-686-pae', 'Debian (32-bit)'),
    ('-686', 'Debian (32-bit)'),
    ('-generic', 'Ubuntu'),
    ('-lowlatency', 'Ubuntu (lowlatency)'),
    ('-alt', 'ALT Linux'),
    ('-arch', 'Arch Linux'),
    ('.fc', 'Fedora'),
    ('-lts', 'Linux (LTS)'),
]


def linux_distro_from_kernel(kernel_version):
    """Определяет дистрибутив Linux по суффиксам ядра."""
    if not kernel_version:
        return ''
    kv = str(kernel_version).lower()
    for pattern, distro in _LINUX_KERNEL_PATTERNS:
        if pattern in kv:
            return distro
    return ''


# ===== Windows kernel version → OS name =====
_WINDOWS_KERNEL_MAP = {
    '5.1': ('Windows XP', None),
    '5.2': ('Windows XP x64', 'Windows Server 2003'),
    '6.0': ('Windows Vista', 'Windows Server 2008'),
    '6.1': ('Windows 7', 'Windows Server 2008 R2'),
    '6.2': ('Windows 8', 'Windows Server 2012'),
    '6.3': ('Windows 8.1', 'Windows Server 2012 R2'),
}

_WINDOWS_10_BUILD_MAP = {
    10240: ('Windows 10 1507', None),
    10586: ('Windows 10 1511', None),
    14393: ('Windows 10 1607', 'Windows Server 2016'),
    15063: ('Windows 10 1703', None),
    16299: ('Windows 10 1709', None),
    17134: ('Windows 10 1803', None),
    17763: ('Windows 10 1809', 'Windows Server 2019'),
    18362: ('Windows 10 1903', None),
    18363: ('Windows 10 1909', None),
    19041: ('Windows 10 2004', None),
    19042: ('Windows 10 20H2', None),
    19043: ('Windows 10 21H1', None),
    19044: ('Windows 10 21H2', None),
    19045: ('Windows 10 22H2', None),
    20348: (None, 'Windows Server 2022'),
    22000: ('Windows 11 21H2', None),
    22621: ('Windows 11 22H2', None),
    22631: ('Windows 11 23H2', None),
    26100: ('Windows 11 24H2', 'Windows Server 2025'),
}


def windows_name_from_kernel(kernel_version, is_server=False):
    """Определяет имя ОС Windows по kernel_version (major.minor.build)."""
    if not kernel_version:
        return ''
    parts = str(kernel_version).split('.')
    if len(parts) < 2:
        return ''
    major_minor = f"{parts[0]}.{parts[1]}"

    # Windows 5.x, 6.x
    if major_minor in _WINDOWS_KERNEL_MAP:
        desktop, server = _WINDOWS_KERNEL_MAP[major_minor]
        if is_server and server:
            return server
        return desktop or server or ''

    # Windows 10.0.xxxxx
    if major_minor == '10.0' and len(parts) >= 3:
        try:
            build = int(parts[2])
        except ValueError:
            return 'Windows 10+'

        if build in _WINDOWS_10_BUILD_MAP:
            desktop, server = _WINDOWS_10_BUILD_MAP[build]
            if is_server and server:
                return server
            return desktop or server or f'Windows 10 (build {build})'

        # Ближайший известный build
        known_builds = sorted(_WINDOWS_10_BUILD_MAP.keys())
        closest = min(known_builds, key=lambda b: abs(b - build))
        if abs(closest - build) <= 500:
            desktop, server = _WINDOWS_10_BUILD_MAP[closest]
            if is_server and server:
                return server
            return desktop or server or f'Windows 10 (build {build})'
        return f'Windows (build {build})'

    return ''
