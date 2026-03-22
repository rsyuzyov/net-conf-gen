from dataclasses import dataclass, field

from src.constants import CATEGORY_UNKNOWN, TYPE_UNKNOWN


@dataclass
class HostRecord:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    service_details: dict[int, dict] = field(default_factory=dict)
    hostnames: list[str] = field(default_factory=list)
    hostname: str = ''
    mac: str = ''
    vendor: str = ''
    os: str = ''
    os_type: str = ''
    type: str = TYPE_UNKNOWN
    category: str = CATEGORY_UNKNOWN
    model: str = ''
    scripts: dict[str, str] = field(default_factory=dict)
    auth_methods: list[str] = field(default_factory=list)
    auth_attempts: list[dict] = field(default_factory=list)
    auth_method: str = ''
    user: str = ''
    key_path: str = ''
    kernel_version: str = ''
    distribution: str = ''
    success: bool = False
    scan_status: str = ''
    last_updated: str = ''

    @classmethod
    def from_dict(cls, data):
        service_details = data.get('service_details', {}) or {}
        normalized_service_details = {}
        for key, value in service_details.items():
            try:
                normalized_key = int(key)
            except (TypeError, ValueError):
                normalized_key = key
            normalized_service_details[normalized_key] = value

        return cls(
            ip=data['ip'],
            open_ports=list(data.get('open_ports', [])),
            services=list(data.get('services', [])),
            service_details=normalized_service_details,
            hostnames=list(data.get('hostnames', [])),
            hostname=data.get('hostname', ''),
            mac=data.get('mac', ''),
            vendor=data.get('vendor', ''),
            os=data.get('os', ''),
            os_type=data.get('os_type', ''),
            type=data.get('type', TYPE_UNKNOWN),
            category=data.get('category', CATEGORY_UNKNOWN),
            model=data.get('model', ''),
            scripts=dict(data.get('scripts', {})),
            auth_methods=list(data.get('auth_methods', [])),
            auth_attempts=list(data.get('auth_attempts', [])),
            auth_method=data.get('auth_method', ''),
            user=data.get('user', ''),
            key_path=data.get('key_path', ''),
            kernel_version=data.get('kernel_version', ''),
            distribution=data.get('distribution', ''),
            success=bool(data.get('success', False)),
            scan_status=data.get('scan_status', ''),
            last_updated=data.get('last_updated', ''),
        )

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def to_dict(self):
        return {
            'ip': self.ip,
            'open_ports': list(self.open_ports),
            'services': list(self.services),
            'service_details': dict(self.service_details),
            'hostnames': list(self.hostnames),
            'hostname': self.hostname,
            'mac': self.mac,
            'vendor': self.vendor,
            'os': self.os,
            'os_type': self.os_type,
            'type': self.type,
            'category': self.category,
            'model': self.model,
            'scripts': dict(self.scripts),
            'auth_methods': list(self.auth_methods),
            'auth_attempts': list(self.auth_attempts),
            'auth_method': self.auth_method,
            'user': self.user,
            'key_path': self.key_path,
            'kernel_version': self.kernel_version,
            'distribution': self.distribution,
            'success': self.success,
            'scan_status': self.scan_status,
            'last_updated': self.last_updated,
        }
