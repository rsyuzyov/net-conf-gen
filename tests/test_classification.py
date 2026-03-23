import unittest

from src.classification import classify_host


class ClassificationTests(unittest.TestCase):
    def test_weak_vendor_signal_stays_unknown(self):
        result = classify_host({
            'ip': '192.168.1.10',
            'vendor': 'Proxmox Server Solutions GmbH',
            'open_ports': [],
            'services': [],
            'service_details': {},
        })

        self.assertEqual('unknown', result['category'])
        self.assertEqual('unknown', result['type'])
        self.assertEqual('', result['os_type'])

    def test_linux_guess_requires_stronger_signal_than_just_ssh_port(self):
        result = classify_host({
            'ip': '192.168.1.11',
            'open_ports': [22],
            'services': ['SSH'],
            'service_details': {22: {'name': '', 'product': 'SSH', 'version': '', 'extrainfo': '', 'tunnel': ''}},
        })

        self.assertEqual('unknown', result['category'])
        self.assertEqual('unknown', result['type'])


if __name__ == '__main__':
    unittest.main()
