import json
import logging
import os
import subprocess


logger = logging.getLogger(__name__)


def load_port_config(config_path='ports.json'):
    if not os.path.isabs(config_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        config_path = os.path.join(project_root, config_path)

    with open(config_path, 'r', encoding='utf-8') as f:
        ports_dict = json.load(f)
    normalized = {int(port): name for port, name in ports_dict.items()}
    return sorted(normalized.keys()), normalized


def load_ports_from_file(config_path='ports.json'):
    ports, _ = load_port_config(config_path)
    return ports


class NmapRunner:
    def __init__(self, nmap_path='nmap', service_detection=True, os_detection=True, scripts=None, extra_args=None, host_timeout='90s'):
        self.nmap_path = nmap_path
        self.service_detection = service_detection
        self.os_detection = os_detection
        self.scripts = scripts or ['banner', 'http-title', 'ssl-cert', 'snmp-info']
        self.extra_args = extra_args or []
        self.host_timeout = host_timeout

    def build_command(self, targets, ports, exclusions=None):
        command = [self.nmap_path, '-oX', '-']

        if ports:
            command.extend(['-p', ','.join(str(port) for port in ports)])

        if self.service_detection:
            command.extend(['-sV', '--version-light'])

        if self.os_detection:
            command.extend(['-O', '--osscan-limit'])

        if self.scripts:
            command.extend(['--script', ','.join(self.scripts)])

        command.extend(['-T4', '--max-retries', '1'])
        if self.host_timeout:
            command.extend(['--host-timeout', str(self.host_timeout)])

        if exclusions:
            command.extend(['--exclude', ','.join(exclusions)])

        command.extend(self.extra_args)
        command.extend(targets)
        return command

    def run(self, targets, ports, exclusions=None):
        command = self.build_command(targets, ports, exclusions=exclusions)
        logger.info("Running nmap scan")
        logger.debug("nmap command: %s", ' '.join(command))

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=False,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise RuntimeError(f"nmap failed with exit code {result.returncode}: {stderr}")

        return result.stdout
