#!/usr/bin/env python3

from pathlib import Path
import unittest

import eac_logchecker

TESTS = [
    (Path('logs/01.log'), [{'message': 'Log entry is fine!', 'status': 'OK'}, {'message': 'Log entry is fine!', 'status': 'OK'}]),
    (Path('logs/02.log'), [{'message': 'Log entry is fine!', 'status': 'OK'}]),
    (Path('logs/03.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/04.log'), [{'message': 'Log entry is fine!', 'status': 'OK'}, {'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/05.log'), [{'message': 'Log entry is fine!', 'status': 'OK'}, {'message': 'Log entry is fine!', 'status': 'OK'}]),
    (Path('logs/06.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/07.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/08.log'), [{'message': 'Log entry was modified, checksum incorrect!', 'status': 'BAD'}]),
    (Path('logs/09.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/10.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/11.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/12.log'), [{'message': 'Log entry is fine!', 'status': 'OK'}]),
    (Path('logs/13.log'), [{'message': 'Log entry is fine!', 'status': 'OK'}]),
    (Path('logs/14.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/15.log'), [{'message': 'Log entry was modified, checksum incorrect!', 'status': 'BAD'}]),
    (Path('logs/16.log'), [{'message': 'Log entry was modified, checksum incorrect!', 'status': 'BAD'}]),
    (Path('logs/17.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/18.log'), [{'message': 'Log entry is fine!', 'status': 'OK'}]),
    (Path('logs/19.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/20.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/21.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/22.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/23.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
    (Path('logs/24.log'), [{'message': 'Log entry has no checksum!', 'status': 'NO'}]),
]

class TestLogchecker(unittest.TestCase):
    def test_logs(self):
        for log_file, expected in TESTS:
            with self.subTest(log=str(log_file)):
                actual = eac_logchecker.check_checksum(log_file, True)
                self.assertEqual(expected, actual) 


if __name__ == "__main__":
    unittest.main()
