#!/usr/bin/env python3

from pathlib import Path
import pytest

import eac_logchecker

LOG_GOOD = {'message': 'Log entry is fine!', 'status': 'OK'}
LOG_NO = {'message': 'Log entry has no checksum!', 'status': 'NO'}
LOG_BAD = {
    'message': 'Log entry was modified, checksum incorrect!',
    'status': 'BAD'
}


@pytest.mark.parametrize("log_path, log_statuses", [
    (Path('logs/01.log'), [LOG_GOOD, LOG_GOOD]),
    (Path('logs/02.log'), [LOG_GOOD]),
    (Path('logs/03.log'), [LOG_NO]),
    (Path('logs/04.log'), [LOG_GOOD, LOG_NO]),
    (Path('logs/05.log'), [LOG_GOOD, LOG_GOOD]),
    (Path('logs/06.log'), [LOG_NO]),
    (Path('logs/07.log'), [LOG_NO]),
    (Path('logs/08.log'), [LOG_BAD]),
    (Path('logs/09.log'), [LOG_NO]),
    (Path('logs/10.log'), [LOG_NO]),
    (Path('logs/11.log'), [LOG_NO]),
    (Path('logs/12.log'), [LOG_GOOD]),
    (Path('logs/13.log'), [LOG_GOOD]),
    (Path('logs/14.log'), [LOG_NO]),
    (Path('logs/15.log'), [LOG_BAD]),
    (Path('logs/16.log'), [LOG_BAD]),
    (Path('logs/17.log'), [LOG_NO]),
    (Path('logs/18.log'), [LOG_GOOD]),
    (Path('logs/19.log'), [LOG_NO]),
    (Path('logs/20.log'), [LOG_NO]),
    (Path('logs/21.log'), [LOG_NO]),
    (Path('logs/22.log'), [LOG_NO]),
    (Path('logs/23.log'), [LOG_NO]),
    (Path('logs/24.log'), [LOG_NO]),
    (Path('logs/25.log'), [LOG_GOOD, LOG_NO]),
    (Path('logs/26.log'), [LOG_BAD]),
    (Path('logs/27.log'), [LOG_GOOD, LOG_BAD, LOG_BAD, LOG_BAD])
])
def test_log(log_path, log_statuses):
    actual = eac_logchecker.check_checksum(log_path)
    assert log_statuses == actual
