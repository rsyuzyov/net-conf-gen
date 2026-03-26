import csv
import json
import os
import logging
import html
import yaml
from src.constants import STATUS_COMPLETED, STATUS_UNKNOWN
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

    def _get_primary_auth_method(self, host):
        """Возвращает только успешный метод подключения."""
        return host.get('auth_method', '')

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
        return ansible_connection_for_host(host.get('auth_method', ''))

    def _generate_ansible_inventory(self, hosts):
        # Все группы верхнего уровня
        groups = [
            'windows', 'linux', 'mikrotik',
            'network_devices', 'printers', 'cameras', STATUS_UNKNOWN
        ]
        # Подгруппы
        subgroups = {
            'windows': ['windows_servers', 'windows_workstations'],
            'linux': ['linux_servers'],
        }

        # Инициализация структуры inventory с общими vars
        inventory = {'all': {
            'vars': {
                'ansible_ssh_common_args': '-o StrictHostKeyChecking=no',
            },
            'children': {}
        }}
        for g in groups:
            if g in subgroups:
                # Группа с подгруппами
                inventory['all']['children'][g] = {
                    'hosts': {},
                    'children': {sg: {'hosts': {}} for sg in subgroups[g]}
                }
            else:
                inventory['all']['children'][g] = {'hosts': {}}

        secrets = {}

        for h in hosts:
            ip = h['ip']
            name = self._sanitize_host_alias(h.get('hostname')) or ip

            group, subgroup = self._classify_host_group(h)

            # Формируем данные хоста
            host_data = {'ansible_host': ip}

            # Добавляем connection-данные если authenticated enrichment завершён
            if self._is_scan_completed(h):
                connection = self._determine_ansible_connection(h)
                if connection:
                    host_data['ansible_connection'] = connection
                    if connection == 'winrm':
                        host_data['ansible_winrm_server_cert_validation'] = 'ignore'

                user = h.get('user')
                if user:
                    host_data['ansible_user'] = user

            # Помещаем хост в подгруппу (если есть) или в основную группу
            if subgroup and subgroup in inventory['all']['children'].get(group, {}).get('children', {}):
                inventory['all']['children'][group]['children'][subgroup]['hosts'][name] = host_data
            else:
                inventory['all']['children'][group]['hosts'][name] = host_data

            # Secrets (для обратной совместимости)
            if self._is_scan_completed(h) and h.get('user'):
                secrets[name] = {
                    'ansible_user': h['user']
                }
                if self._get_primary_auth_method(h) == 'winrm':
                    secrets[name]['ansible_connection'] = 'winrm'
                    secrets[name]['ansible_winrm_server_cert_validation'] = 'ignore'

        # Убираем пустые группы/подгруппы для чистоты вывода
        for g in list(inventory['all']['children'].keys()):
            group_data = inventory['all']['children'][g]
            # Убираем пустые подгруппы
            if 'children' in group_data:
                for sg in list(group_data['children'].keys()):
                    if not group_data['children'][sg]['hosts']:
                        del group_data['children'][sg]
                if not group_data['children']:
                    del group_data['children']
            # Убираем полностью пустую группу
            if not group_data.get('hosts') and not group_data.get('children'):
                del inventory['all']['children'][g]

        with open(os.path.join(self.output_dir, 'inventory.yaml'), 'w', encoding='utf-8') as f:
            yaml.dump(inventory, f, allow_unicode=True)

        with open(os.path.join(self.output_dir, 'secrets.yaml'), 'w', encoding='utf-8') as f:
            yaml.dump(secrets, f, allow_unicode=True)

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
