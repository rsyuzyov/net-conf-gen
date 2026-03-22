import unittest

from src.os_detection import windows_name_from_kernel


class OsDetectionTests(unittest.TestCase):
    def test_windows_name_from_plain_build_number(self):
        self.assertEqual('Windows 10 22H2', windows_name_from_kernel('19045'))


if __name__ == '__main__':
    unittest.main()
