import argparse
import yaml
import os
import sys
import glob
import logging
import time
from datetime import datetime
from src.config_wizard import create_config
from src.discovery import NetworkScanner

logger = logging.getLogger(__name__)


def cleanup_old_logs(log_dir, max_age_days=30):
    """Удаляет лог-файлы старше max_age_days дней."""
    now = time.time()
    for log_file in glob.glob(os.path.join(log_dir, '*.log')):
        try:
            file_age = now - os.path.getmtime(log_file)
            if file_age > max_age_days * 86400:
                os.remove(log_file)
        except OSError:
            pass


def load_config(config_path):
    if not os.path.exists(config_path):
        logger.warning(f"Config file {config_path} not found.")
        choice = input("Create new config? [Y/n]: ").strip().lower()
        if choice in ('', 'y', 'yes'):
            return create_config()
        else:
            logger.error("Config file required. Exiting.")
            sys.exit(1)

    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="net-conf-gen - Network Scanner")
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    parser.add_argument('--step', choices=['discovery', 'scan', 'report', 'all'],
                        default='all', help='Step to run')
    parser.add_argument('--force', action='store_true', help='Force rescan of all hosts')
    parser.add_argument('--host', help='Scan specific host IP')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    # 1. Load Config
    config = load_config(args.config)
    targets = config.get('targets', [])

    domain = config.get('domain', '')
    if domain:
        output_dir = os.path.join('output', domain)
        log_dir = os.path.join('log', domain)
    else:
        output_dir = 'output'
        log_dir = 'log'

    # Setup logging
    os.makedirs(log_dir, exist_ok=True)
    cleanup_old_logs(log_dir, max_age_days=30)
    log_filename = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log")

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_filename, encoding='utf-8'),
        ]
    )

    logging.getLogger('pypsexec').setLevel(logging.WARNING)
    logging.getLogger('smbprotocol').setLevel(logging.WARNING)

    if not targets and not args.host:
        logger.error("No targets specified in config.")
        sys.exit(1)

    logger.info(f"Domain: {domain}")
    logger.info(f"Output directory: {output_dir}")

    # Initialize Storage
    from src.storage import Storage
    storage = Storage(output_dir=output_dir)

    # ===== Stage 1: Discovery =====
    if args.step in ['discovery', 'all']:
        logger.info("=== Stage 1: Discovery & Port Scan ===")
        scanner = NetworkScanner(ports_arg=None)

        if args.host:
            logger.info(f"Сканирование хоста: {args.host}")
            hosts = scanner.scan_all([f"{args.host}/32"])
            logger.info(f"Хост {'активен' if hosts else 'не отвечает'}")
        else:
            hosts = scanner.scan_all(targets)
            logger.info(f"Total active hosts found: {len(hosts)}")

        for host in hosts:
            storage.update_host(host['ip'], host)
        storage.flush()

    # ===== Stage 2: Classify + Scan =====
    if args.step in ['scan', 'all']:
        from src.classifier import classify
        from src.probes.ttl import ping_ttl
        from src.host_scanner import HostScanner

        if not storage.data:
            logger.warning("Нет хостов в storage. Запустите сначала discovery.")
        else:
            logger.info("=== Stage 2: Classify & Scan ===")

            # 2a. Quick classify
            if args.host:
                scan_hosts = {args.host: storage.get_host(args.host)}
                if not scan_hosts[args.host]:
                    logger.error(f"Хост {args.host} не найден в storage.")
                    sys.exit(1)
            else:
                scan_hosts = dict(storage.data)

            classifications = {}
            for ip, host_info in scan_hosts.items():
                ttl = ping_ttl(ip, timeout=2)
                category = classify(
                    open_ports=host_info.get('open_ports', []),
                    mac_vendor=host_info.get('vendor', ''),
                    ttl=ttl
                )
                classifications[ip] = category
                storage.update_host(ip, {'category': category})
                logger.info(f"  {ip} → {category}")

            # Статистика
            from collections import Counter
            stats = Counter(classifications.values())
            logger.info(f"Классификация: {dict(stats)}")

            # 2b. Scan по стратегии
            host_scanner = HostScanner(
                storage,
                config.get('credentials', []),
                concurrency=config.get('concurrency', 20)
            )
            host_scanner.scan_all(classifications, force=args.force)

            storage.flush()
            logger.info("Scan завершён.")

    # ===== Stage 3: Report =====
    if args.step in ['report', 'all']:
        from src.reporting import ReportGenerator
        logger.info("=== Stage 3: Reporting ===")
        reporter = ReportGenerator(storage, output_dir=output_dir, domain=domain, targets=targets)
        reporter.generate_all()


if __name__ == "__main__":
    main()
