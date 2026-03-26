import csv
import json
import os
import logging
import html
from collections import Counter
from pathlib import Path
import yaml
from src.constants import (
    STATUS_COMPLETED,
    STATUS_UNKNOWN,
    STATUS_VIRTUALIZATION_COMPLETED,
)
from src.models import HostRecord
from src.report_presenters import (
    CSV_KEYS,
    ansible_connection_for_host,
    csv_row_for_host,
    html_row_for_host,
    inventory_group_for_host,
)
from src.utils import ip_to_int

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, storage, output_dir='output', domain='', targets=None):
        self.storage = storage
        self.output_dir = output_dir
        self.domain = domain
        self.targets = targets or []
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _format_ports(self, ports):
        """Форматирует список портов в строку."""
        if not ports:
            return ''
        if isinstance(ports, list):
            return ', '.join(map(str, sorted(ports)))
        return str(ports)

    def _format_services(self, services):
        """Форматирует список сервисов в строку."""
        if not services:
            return ''
        if isinstance(services, list):
            return ', '.join(services)
        return str(services)

    def _is_scan_completed(self, host):
        """Определяет, есть ли успешный результат подключения."""
        return host.get('scan_status') == STATUS_COMPLETED

    def _has_ansible_access(self, host):
        """Определяет, можно ли использовать хост в рабочем inventory."""
        connection = self._determine_ansible_connection(host)
        if not connection:
            return False
        return host.get('scan_status') in (STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED)

    def _get_primary_auth_method(self, host):
        """Возвращает только успешный метод подключения."""
        return host.get('auth_method', '')

    def _get_preferred_ansible_method(self, host):
        methods = []
        auth_methods = host.get('auth_methods', []) or []
        if isinstance(auth_methods, list):
            methods.extend(str(method).strip().lower() for method in auth_methods if method)

        primary_method = str(host.get('auth_method', '') or '').strip().lower()
        if primary_method:
            methods.append(primary_method)

        for candidate in ('ssh', 'winrm', 'psexec'):
            if candidate in methods:
                return candidate
        return None

    def _get_scan_status(self, host):
        return host.get('scan_status', '') or STATUS_UNKNOWN

    def _sanitize_host_alias(self, value):
        """Делает hostname безопасным для inventory/ssh alias."""
        if not value:
            return ''
        alias = str(value).strip().split('.')[0]
        alias = ''.join(ch if ch.isalnum() or ch == '-' else '-' for ch in alias)
        alias = alias.strip('-')
        if not alias:
            return ''
        if alias.lstrip('-').isdigit():
            return ''
        return alias[:63]

    def _fallback_inventory_alias(self, host, base_group=''):
        ip = str(host.get('ip', '')).strip()
        ip_slug = ip.replace('.', '-') if ip else 'host'
        host_type = str(host.get('type', '')).strip().lower()
        os_type = str(host.get('os_type', '')).strip().lower()

        prefix_map = {
            'printers': 'printer',
            'cameras': 'camera',
            'mikrotik': 'mikrotik',
            'network_devices': 'network',
            'windows': 'windows',
            'linux': 'linux',
            STATUS_UNKNOWN: 'unknown',
        }
        prefix = (
            prefix_map.get(base_group)
            or (host_type if host_type and host_type != STATUS_UNKNOWN else '')
            or (os_type if os_type and os_type != STATUS_UNKNOWN else '')
            or 'host'
        )
        prefix = self._sanitize_host_alias(prefix) or 'host'
        return f"{prefix}-{ip_slug}"

    def _make_inventory_alias(self, host, used_aliases, base_group=''):
        raw_hostname = str(host.get('hostname', '') or '').strip()
        alias = self._sanitize_host_alias(raw_hostname)
        generic_aliases = {'host', 'unknown', 'localhost'}

        if not alias or alias.lower() in generic_aliases:
            alias = self._fallback_inventory_alias(host, base_group=base_group)

        base_alias = alias
        counter = 2
        while alias in used_aliases:
            alias = f"{base_alias}-{counter}"
            counter += 1
        used_aliases.add(alias)
        return alias

    def _build_inventory_hostvars(self, host, include_metadata=False, metadata_fields=None, compact=False):
        hostvars = {
            'ansible_host': host['ip'],
        }

        if self._has_ansible_access(host):
            user = host.get('user')
            if user:
                hostvars['ansible_user'] = user

            key_path = host.get('key_path')
            if key_path:
                hostvars['ansible_ssh_private_key_file'] = key_path

        if include_metadata:
            os_value = host.get('os', '')
            model_value = host.get('model', '')
            os_type = str(host.get('os_type', '') or '').lower()
            scan_status = self._get_scan_status(host)
            if model_value and os_value and (model_value.lower() == os_value.lower() or model_value.lower() in os_value.lower()):
                model_value = ''

            available_metadata = {
                'netconf_type': host.get('type', ''),
                'netconf_os_type': host.get('os_type', ''),
                'netconf_vendor': host.get('vendor', ''),
                'netconf_model': model_value,
                'netconf_scan_status': scan_status,
                'netconf_auth_method': self._get_primary_auth_method(host),
            }
            if compact:
                if os_type == 'windows':
                    available_metadata['netconf_vendor'] = ''
                    available_metadata['netconf_model'] = ''
                if scan_status == STATUS_COMPLETED:
                    available_metadata['netconf_scan_status'] = ''
            selected_fields = metadata_fields or tuple(available_metadata.keys())
            for key in selected_fields:
                value = available_metadata.get(key, '')
                if value:
                    hostvars[key] = value

        return hostvars

    def _build_compact_inventory(self):
        return {
            'all': {
                'children': {
                    'managed': {
                        'children': {
                            'linux': {
                                'children': {
                                    'linux_servers_ssh': {'hosts': {}},
                                    'linux_workstations_ssh': {'hosts': {}},
                                },
                            },
                            'windows': {
                                'children': {
                                    'windows_ssh': {'hosts': {}},
                                    'windows_winrm': {'hosts': {}},
                                    'windows_psexec': {'hosts': {}},
                                },
                            },
                            'devices_ssh': {
                                'hosts': {},
                            },
                        },
                    },
                },
            }
        }

    def _build_full_inventory(self):
        return {
            'all': {
                'children': {
                    'managed': {
                        'children': {
                            'linux': {
                                'children': {
                                    'linux_servers_ssh': {'hosts': {}},
                                    'linux_workstations_ssh': {'hosts': {}},
                                },
                            },
                            'windows': {
                                'children': {
                                    'windows_ssh': {'hosts': {}},
                                    'windows_winrm': {'hosts': {}},
                                    'windows_psexec': {'hosts': {}},
                                },
                            },
                            'devices_ssh': {
                                'hosts': {},
                            },
                        },
                    },
                    'discovered': {
                        'children': {
                            'linux_discovered': {'hosts': {}},
                            'windows_discovered': {'hosts': {}},
                            'mikrotik': {'hosts': {}},
                            'network_devices': {'hosts': {}},
                            'printers': {'hosts': {}},
                            'cameras': {'hosts': {}},
                            STATUS_UNKNOWN: {'hosts': {}},
                        },
                    },
                },
            }
        }

    def _compact_inventory_group_for_host(self, host):
        connection = self._determine_ansible_connection(host)
        os_type = str(host.get('os_type', '') or '').lower()
        host_type = str(host.get('type', '') or '').lower()

        if connection == 'ssh':
            if os_type == 'linux' and host_type in ('server', 'workstation'):
                return 'linux_servers_ssh' if host_type == 'server' else 'linux_workstations_ssh'
            if os_type == 'windows':
                return 'windows_ssh'
            return 'devices_ssh'
        if connection == 'winrm':
            return 'windows_winrm'
        if connection == 'psexec':
            return 'windows_psexec'
        return None

    def _full_inventory_group_for_host(self, host):
        if self._has_ansible_access(host):
            return 'managed', self._compact_inventory_group_for_host(host)

        group, _subgroup = self._classify_host_group(host)
        discovered_map = {
            'linux': 'linux_discovered',
            'windows': 'windows_discovered',
            'mikrotik': 'mikrotik',
            'network_devices': 'network_devices',
            'printers': 'printers',
            'cameras': 'cameras',
            STATUS_UNKNOWN: STATUS_UNKNOWN,
        }
        return 'discovered', discovered_map.get(group, STATUS_UNKNOWN)

    def _inventory_group_node(self, inventory, group_path):
        node = inventory['all']
        for group_name in group_path:
            node = node['children'][group_name]
        return node

    def _try_inventory_group_node(self, inventory, group_path):
        try:
            return self._inventory_group_node(inventory, group_path)
        except KeyError:
            return None

    def _write_yaml_with_header(self, path, data, header_lines=None):
        with open(path, 'w', encoding='utf-8') as f:
            if header_lines:
                for line in header_lines:
                    f.write(f"# {line}\n")
                f.write("\n")
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)

    def _collect_dominant_group_vars(self, inventory):
        group_candidates = {
            'linux_servers_ssh': {
                'keys': ['ansible_user', 'ansible_ssh_private_key_file'],
                'threshold': 0.7,
                'key_thresholds': {
                    'ansible_ssh_private_key_file': 0.6,
                },
            },
            'linux_workstations_ssh': {
                'keys': ['ansible_user', 'ansible_ssh_private_key_file'],
                'threshold': 0.7,
                'key_thresholds': {
                    'ansible_ssh_private_key_file': 0.6,
                },
            },
            'windows_winrm': {
                'keys': ['ansible_user'],
                'threshold': 0.7,
            },
            'windows_ssh': {
                'keys': ['ansible_user', 'ansible_ssh_private_key_file'],
                'threshold': 0.7,
                'key_thresholds': {
                    'ansible_ssh_private_key_file': 0.6,
                },
            },
            'windows_psexec': {
                'keys': ['ansible_user'],
                'threshold': 0.7,
            },
            'devices_ssh': {
                'keys': ['ansible_user', 'ansible_ssh_private_key_file'],
                'threshold': 0.7,
                'key_thresholds': {
                    'ansible_ssh_private_key_file': 0.6,
                },
            },
        }
        dominant_vars = {
            'all': {
                'ansible_ssh_common_args': '-o StrictHostKeyChecking=no',
            },
            'linux': {
                'ansible_connection': 'ssh',
            },
            'windows_winrm': {
                'ansible_connection': 'winrm',
                'ansible_winrm_server_cert_validation': 'ignore',
            },
            'windows_ssh': {
                'ansible_connection': 'ssh',
            },
            'windows_psexec': {
                'ansible_connection': 'psexec',
            },
            'devices_ssh': {
                'ansible_connection': 'ssh',
            },
        }

        for group_name, policy in group_candidates.items():
            node = None
            if group_name.startswith('linux_'):
                node = self._try_inventory_group_node(inventory, ('managed', 'linux', group_name))
            elif group_name.startswith('windows_'):
                node = self._try_inventory_group_node(inventory, ('managed', 'windows', group_name))
            elif group_name == 'devices_ssh':
                node = self._try_inventory_group_node(inventory, ('managed', 'devices_ssh'))

            if not node:
                continue

            hosts = node.get('hosts', {})
            host_count = len(hosts)
            if not host_count:
                continue

            eligible_hosts = [
                hostvars for hostvars in hosts.values()
                if hostvars.get('netconf_scan_status') == STATUS_COMPLETED
            ] or list(hosts.values())

            for key in policy.get('keys', []):
                threshold = policy.get('key_thresholds', {}).get(key, policy.get('threshold', 0.8))
                values = [hostvars.get(key) for hostvars in eligible_hosts if hostvars.get(key)]
                if not values:
                    continue
                if key == 'ansible_user':
                    eligible_count = len([hostvars for hostvars in eligible_hosts if hostvars.get(key)])
                else:
                    eligible_count = len(eligible_hosts)
                value, count = Counter(values).most_common(1)[0]
                if eligible_count and count / eligible_count >= threshold:
                    dominant_vars.setdefault(group_name, {})[key] = value
                    for hostvars in hosts.values():
                        if hostvars.get(key) == value:
                            del hostvars[key]
                        elif key == 'ansible_ssh_private_key_file' and key not in hostvars:
                            # Prevent inheriting the dominant SSH key on hosts where no key was discovered.
                            hostvars[key] = None

        return dominant_vars

    def _write_group_vars(self, inventory):
        group_vars_dir = Path(self.output_dir) / 'group_vars'
        group_vars_dir.mkdir(parents=True, exist_ok=True)

        group_vars = self._collect_dominant_group_vars(inventory)

        for existing_file in group_vars_dir.glob('*.yml'):
            if existing_file.stem not in group_vars:
                existing_file.unlink()

        for group_name, values in group_vars.items():
            with open(group_vars_dir / f'{group_name}.yml', 'w', encoding='utf-8') as f:
                yaml.dump(values, f, allow_unicode=True, sort_keys=False)

    def _prune_empty_inventory_groups(self, node):
        if not isinstance(node, dict):
            return

        children = node.get('children')
        if isinstance(children, dict):
            for name in list(children.keys()):
                child = children[name]
                self._prune_empty_inventory_groups(child)
                if not child.get('hosts') and not child.get('children'):
                    del children[name]



    def _sort_hosts_by_ip(self, hosts):
        """Sort hosts list by IP address."""
        return sorted(hosts, key=lambda h: ip_to_int(h.get('ip', '')))

    def _sort_data_by_ip(self, data):
        """Sort data dictionary by IP address."""
        return dict(sorted(data.items(), key=lambda x: ip_to_int(x[0])))

    def generate_all(self):
        hosts = self._sort_hosts_by_ip(list(self.storage.iter_host_records()))
        sorted_data = self._sort_data_by_ip({host.ip: host.to_dict() for host in hosts})
        
        self._generate_hosts_txt(hosts)
        self._generate_csv(hosts)
        self._generate_json(sorted_data)
        self._generate_ansible_inventory(hosts)
        self._generate_ssh_config(hosts)
        self._generate_html(hosts)
        
        logger.info(f"Reports generated in {self.output_dir}")

    def _generate_hosts_txt(self, hosts):
        with open(os.path.join(self.output_dir, 'hosts.txt'), 'w', encoding='utf-8') as f:
            for h in hosts:
                f.write(f"{h['ip']}\n")

    def _generate_csv(self, hosts):
        with open(os.path.join(self.output_dir, 'scan_report.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_KEYS, extrasaction='ignore')
            writer.writeheader()
            for host in hosts:
                row = csv_row_for_host(
                    host,
                    get_scan_status=self._get_scan_status,
                    get_primary_auth_method=self._get_primary_auth_method,
                    format_ports=self._format_ports,
                    format_services=self._format_services,
                )
                writer.writerow(row)

    def _generate_json(self, data):
        with open(os.path.join(self.output_dir, 'scan_report.json'), 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        with open(os.path.join(self.output_dir, 'scan_report.yaml'), 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True)

    def _classify_host_group(self, host):
        return inventory_group_for_host(host)

    def _determine_ansible_connection(self, host):
        return ansible_connection_for_host(self._get_preferred_ansible_method(host) or '')

    def _generate_ansible_inventory(self, hosts):
        inventory = self._build_compact_inventory()
        full_inventory = self._build_full_inventory()
        secrets = {}
        used_compact_aliases = set()
        used_full_aliases = set()

        for h in hosts:
            compact_group = self._compact_inventory_group_for_host(h) if self._has_ansible_access(h) else None
            if compact_group:
                compact_name = self._make_inventory_alias(h, used_compact_aliases, base_group=compact_group)
                compact_group_path = ('managed', 'devices_ssh') if compact_group == 'devices_ssh' else (
                    ('managed', 'linux', compact_group) if compact_group.startswith('linux_') else ('managed', 'windows', compact_group)
                )
                self._inventory_group_node(inventory, compact_group_path)['hosts'][compact_name] = self._build_inventory_hostvars(
                    h,
                    include_metadata=True,
                    compact=True,
                    metadata_fields=(
                        'netconf_vendor',
                        'netconf_model',
                        'netconf_scan_status',
                    ),
                )

                if h.get('user'):
                    secrets[compact_name] = {
                        'ansible_user': h['user']
                    }
                    if self._determine_ansible_connection(h) == 'winrm':
                        secrets[compact_name]['ansible_connection'] = 'winrm'
                        secrets[compact_name]['ansible_winrm_server_cert_validation'] = 'ignore'

            scope, full_group = self._full_inventory_group_for_host(h)
            if full_group:
                full_name = self._make_inventory_alias(h, used_full_aliases, base_group=full_group)
                if scope == 'managed':
                    full_group_path = ('managed', 'devices_ssh') if full_group == 'devices_ssh' else (
                        ('managed', 'linux', full_group) if full_group.startswith('linux_') else ('managed', 'windows', full_group)
                    )
                else:
                    full_group_path = ('discovered', full_group)
                self._inventory_group_node(full_inventory, full_group_path)['hosts'][full_name] = self._build_inventory_hostvars(
                    h,
                    include_metadata=True,
                )

        # Убираем пустые группы для чистоты вывода
        self._prune_empty_inventory_groups(inventory['all'])
        self._prune_empty_inventory_groups(full_inventory['all'])

        self._write_group_vars(inventory)

        self._write_yaml_with_header(
            os.path.join(self.output_dir, 'inventory.yaml'),
            inventory,
            header_lines=[
                'Compact Ansible inventory with managed hosts only.',
                'Shared connection settings are written to group_vars/*.yml.',
            ],
        )

        self._write_yaml_with_header(
            os.path.join(self.output_dir, 'inventory_full.yaml'),
            full_inventory,
            header_lines=[
                'Full inventory with managed and discovered hosts.',
                'managed/linux/linux_servers_ssh: Linux servers with SSH access.',
                'managed/linux/linux_workstations_ssh: Linux workstations with SSH access.',
                'managed/windows/windows_ssh: Windows hosts reachable through SSH.',
                'managed/windows/windows_winrm: Windows hosts reachable through WinRM.',
                'managed/windows/windows_psexec: Windows hosts reachable through PsExec.',
                'managed/devices_ssh: Other SSH-manageable devices.',
                'discovered/*: Found devices without usable Ansible access yet.',
            ],
        )

        with open(os.path.join(self.output_dir, 'secrets.yaml'), 'w', encoding='utf-8') as f:
            yaml.dump(secrets, f, allow_unicode=True, sort_keys=False)

    def _generate_ssh_config(self, hosts):
        config_lines = []
        # Keep track of used host aliases to avoid duplicates
        used_aliases = set()

        # Заголовок
        if self.domain:
            config_lines.append(f"# SSH config для домена {self.domain}")
            config_lines.append(f"# Сгенерировано автоматически из inventory")
            config_lines.append("")

        # Группируем хосты по os_type для комментариев
        grouped = {}
        for h in hosts:
            if self._is_scan_completed(h) and self._get_primary_auth_method(h) == 'ssh':
                os_type = h.get('os_type', STATUS_UNKNOWN)
                grouped.setdefault(os_type, []).append(h)

        # Порядок вывода
        group_order = ['linux', 'windows']
        group_labels = {'linux': 'Linux', 'windows': 'Windows'}
        # Добавляем остальные группы, которые не в порядке
        for os_type in grouped:
            if os_type not in group_order:
                group_order.append(os_type)

        for os_type in group_order:
            if os_type not in grouped:
                continue
            
            label = group_labels.get(os_type, os_type.capitalize())
            config_lines.append(f"# --- {label} ---")

            for h in grouped[os_type]:
                ip = h['ip']
                hostname = self._sanitize_host_alias(h.get('hostname'))
                user = h.get('user')
                key_path = h.get('key_path')

                # Determine Host alias
                if hostname:
                    short_name = hostname.split('.')[0]
                else:
                    short_name = ip
                
                # Ensure unique alias
                base_alias = short_name
                counter = 1
                while short_name in used_aliases:
                    short_name = f"{base_alias}-{counter}"
                    counter += 1
                used_aliases.add(short_name)

                # FQDN alias: hostname.domain
                if hostname and self.domain:
                    fqdn = f"{hostname}.{self.domain}" if '.' not in hostname else hostname
                    # Host line: fqdn + short alias
                    if fqdn != short_name:
                        config_lines.append(f"Host {fqdn} {short_name}")
                    else:
                        config_lines.append(f"Host {short_name}")
                else:
                    config_lines.append(f"Host {short_name}")
                
                config_lines.append(f"    HostName {ip}")
                if user:
                    config_lines.append(f"    User {user}")
                if key_path:
                    config_lines.append(f"    IdentityFile {key_path}")
                
                config_lines.append("")
        
        with open(os.path.join(self.output_dir, 'ssh_config'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(config_lines))

    def _generate_html(self, hosts):
        from datetime import datetime
        from collections import Counter
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        table_rows = [
            html_row_for_host(
                host,
                domain=self.domain or '',
                sanitize_host_alias=self._sanitize_host_alias,
                get_primary_auth_method=self._get_primary_auth_method,
                get_scan_status=self._get_scan_status,
            )
            for host in hosts
        ]
        
        # Load template
        template_path = os.path.join(os.path.dirname(__file__), 'report_template.html')
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except Exception as e:
            logger.error(f"Failed to load HTML template: {e}")
            return
        
        # Build type summary
        from collections import Counter
        type_counts = Counter(h.get('type', STATUS_UNKNOWN) or STATUS_UNKNOWN for h in hosts)
        type_summary_parts = [f'{t}: {c}' for t, c in sorted(type_counts.items())]
        type_summary_html = ' &nbsp;|&nbsp; '.join(type_summary_parts)

        hostname_counts = Counter(
            (h.get('hostname') or '').strip().lower()
            for h in hosts
            if (h.get('hostname') or '').strip()
        )
        duplicate_hostnames = sorted(name for name, count in hostname_counts.items() if count > 1)
        if duplicate_hostnames:
            duplicate_items = ', '.join(html.escape(name) for name in duplicate_hostnames[:10])
            if len(duplicate_hostnames) > 10:
                duplicate_items += f' и еще {len(duplicate_hostnames) - 10}'
            report_alert = (
                '<div class="report-alert">'
                'Обнаружены дубликаты hostname/FQDN. '
                'Режим адресации FQDN может быть неоднозначным: '
                f'{duplicate_items}'
                '</div>'
            )
        else:
            report_alert = ''

        # Fill template
        targets_str = ', '.join(self.targets) if self.targets else ''
        html_content = template.format(
            timestamp=timestamp,
            table_rows=''.join(table_rows),
            total_hosts=len(hosts),
            type_summary=type_summary_html,
            domain=self.domain,
            targets=targets_str,
            report_alert=report_alert,
        )
        
        # Write to file
        output_path = os.path.join(self.output_dir, 'scan_report.html')
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report generated: {output_path}")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")
