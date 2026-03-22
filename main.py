import argparse
import glob
import logging
import os
import sys
import time
from datetime import datetime

import yaml

from src.config_wizard import create_config
from src.discovery import NativeDiscovery
from src.enrichment import AuthenticatedEnricher
from src.virtualization_enrichment import VirtualizationEnricher

logger = logging.getLogger(__name__)


def cleanup_old_logs(log_dir, max_age_days=30):
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
        logger.warning("Config file %s not found.", config_path)
        choice = input("Create new config? [Y/n]: ").strip().lower()
        if choice in ('', 'y', 'yes'):
            return create_config()
        logger.error("Config file required. Exiting.")
        sys.exit(1)

    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def run_discovery(config, targets, exclusions):
    scanner = NativeDiscovery(ports_file=config.get('ports_file', 'ports.json'))
    return scanner.scan(targets, exclusions=exclusions)


def main():
    parser = argparse.ArgumentParser(description="net-conf-gen - network inventory")
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    parser.add_argument('--step', choices=['discovery', 'scan', 'virt', 'report', 'all'], default='all', help='Step to run')
    parser.add_argument('--force', action='store_true', help='Force enrichment of all hosts')
    parser.add_argument('--host', help='Scan specific host IP')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    config = load_config(args.config)
    targets = [args.host] if args.host else config.get('targets', [])
    exclusions = [] if args.host else config.get('exclusions', [])

    domain = config.get('domain', '')
    if domain:
        output_dir = os.path.join('output', domain)
        log_dir = os.path.join('log', domain)
    else:
        output_dir = 'output'
        log_dir = 'log'

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

    if not targets:
        logger.error("No targets specified in config.")
        sys.exit(1)

    logger.info("Domain: %s", domain)
    logger.info("Output directory: %s", output_dir)

    from src.storage import Storage
    storage = Storage(output_dir=output_dir)

    if args.step in ['discovery', 'all']:
        logger.info("=== Stage 1: Discovery ===")
        hosts = run_discovery(config, targets, exclusions)
        logger.info("Total active hosts found: %s", len(hosts))
        storage.replace_discovery_snapshot(hosts)
        storage.flush()

    if args.step in ['scan', 'all']:
        logger.info("=== Stage 2: Authenticated Enrichment ===")
        existing_hosts = list(storage.iter_host_records())
        if not existing_hosts:
            logger.warning("No hosts in storage. Run discovery first.")
        else:
            scan_ips = [args.host] if args.host else [host.ip for host in existing_hosts]
            enricher = AuthenticatedEnricher(
                storage=storage,
                credentials=config.get('credentials', []),
                concurrency=config.get('concurrency', 10),
            )
            enricher.enrich_all(scan_ips, force=args.force)
            storage.flush()
            logger.info("Authenticated enrichment completed.")

    if args.step in ['virt', 'all']:
        logger.info("=== Stage 3: Virtualization Enrichment ===")
        existing_hosts = list(storage.iter_host_records())
        if not existing_hosts:
            logger.warning("No hosts in storage. Run discovery first.")
        else:
            virt_ips = [args.host] if args.host else None
            enricher = VirtualizationEnricher(
                storage=storage,
                credentials=config.get('credentials', []),
            )
            enricher.enrich_all(target_ips=virt_ips)
            storage.flush()
            logger.info("Virtualization enrichment completed.")

    if args.step in ['report', 'all']:
        logger.info("=== Stage 4: Reporting ===")
        from src.reporting import ReportGenerator
        reporter = ReportGenerator(storage, output_dir=output_dir, domain=domain, targets=targets)
        reporter.generate_all()


if __name__ == "__main__":
    main()
