import json
import unittest
from pathlib import Path

from src.constants import STATUS_DISCOVERED
from src.nmap_parser import parse_nmap_xml


class NmapParserTests(unittest.TestCase):
    def test_parse_mikrotik_fixture(self):
        fixture = Path('tests/fixtures/nmap_mikrotik.xml').read_text(encoding='utf-8')
        port_labels = {22: 'SSH', 80: 'HTTP', 8728: 'MikroTik-API'}

        records = parse_nmap_xml(fixture, port_labels=port_labels)

        self.assertEqual(1, len(records))
        record = records[0].to_dict()
        self.assertEqual('192.168.88.1', record['ip'])
        self.assertEqual([22, 80, 8728], record['open_ports'])
        self.assertEqual(['SSH', 'HTTP', 'MikroTik-API'], record['services'])
        self.assertEqual('MikroTik', record['vendor'])
        self.assertEqual('mikrotik', record['category'])
        self.assertEqual('mikrotik', record['type'])
        self.assertEqual('linux', record['os_type'])
        self.assertEqual('MikroTik RouterOS', record['os'])
        self.assertEqual(STATUS_DISCOVERED, record['scan_status'])


if __name__ == '__main__':
    unittest.main()
