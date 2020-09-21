#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
import re
import pprp

CHECKSUM_MIN_VERSION = ('V1.0', 'beta', '1')
EAC_KEY = '9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9'

__version__ = '0.8.1'


class Log:
    def __init__(self, text):
        self.text = text
        self.unsigned_text = self.text
        self.version = None
        self.modified = False
        self.old_checksum = None
        self.checksum = None


def eac_checksum(log):
    text = log.unsigned_text
    # Ignore newlines
    text = text.replace('\r', '').replace('\n', '')

    # Fuzzing reveals BOMs are also ignored
    text = text.replace('\ufeff', '').replace('\ufffe', '')

    # Setup Rijndael-256 with a 256-bit blocksize
    cipher = pprp.crypto_3.rijndael(
        # Probably SHA256('super secret password') but it doesn't
        # actually matter
        key=bytes.fromhex(EAC_KEY),
        block_size=256 // 8
    )

    # Encode the text as UTF-16-LE
    plaintext = text.encode('utf-16-le')

    # The IV is all zeroes so we don't have to handle it
    checksum = b'\x00' * 32

    # Process it block-by-block
    for i in range(0, len(plaintext), 32):
        # Zero-pad the last block, if necessary
        plaintext_block = plaintext[i:i + 32].ljust(32, b'\x00')

        # CBC mode (XOR the previous ciphertext block into the plaintext)
        cbc_plaintext = bytes(
            a ^ b for a, b in zip(checksum, plaintext_block)
        )

        # New checksum is the ciphertext.
        checksum = cipher.encrypt(cbc_plaintext)

    # Textual checksum is just the hex representation
    log.checksum = checksum.hex().upper()


def extract_info(log):
    if len(log.text) == 0:
        return log

    for line in log.text.splitlines():
        if line.startswith('Exact Audio Copy'):
            log.version = tuple(line.split()[3:6])
        elif re.match(r'[a-zA-Z]', line):
            break

    match = re.search('\n\n==== (.*) ([A-Z0-9]+) ====', log.text)
    if match:
        search = '\n\n==== {}'.format(match.group(1))
        log.unsigned_text, checksum_parts = re.split(search, log.text)
        log.old_checksum = checksum_parts.split()[0].strip()


def eac_verify(log):
    extract_info(log)
    eac_checksum(log)


def get_logs(data):
    text = data.decode('utf-16-le')

    # Strip off the BOM
    if text.startswith('\ufeff'):
        text = text[1:]

    # The checksum strips off the newlines anyway, so we can simplify them here
    # for our own regexes
    text = text.replace('\r\n', '\n')

    # Null bytes screw it up
    if '\x00' in text:
        text = text[:text.index('\x00')]

    # EAC crashes if there are more than 2^14 bytes in a line
    if any(len(l) + 1 > 2**13 for l in text.split('\n')):
        raise RuntimeError('EAC cannot handle lines longer than 2^13 chars')

    splits = re.split('(\n\n==== .* [A-Z0-9]+ ====)', text)
    logs = []
    for split in splits:
        if split.strip() != '':
            logs.append(split)

    if len(logs) > 1:
        length = len(logs) - 1 if len(logs) % 2 == 1 else len(logs)
        return_logs = []
        for i in range(0, length, 2):
            log = Log(logs[i] + logs[i+1])
            if i > 0:
                (log.text, matches) = re.subn(
                    r'[^-]-{60}[^-]',
                    '',
                    log.text,
                    1
                )
                if matches == 0:
                    log.modified = True
            return_logs.append(log)
        for i in range(length, len(logs)):
            return_logs.append(Log(logs[i]))
    else:
        return_logs = [Log(logs[0])]

    return return_logs


def check_checksum(arg_file):
    if not isinstance(arg_file, Path):
        arg_file = Path(arg_file)

    output = []

    if not arg_file.exists():
        output.append({
            'status': 'ERROR',
            'message': 'Could not find logfile to examine.'
        })
        return output

    try:
        with arg_file.open('rb') as open_file:
            logs = get_logs(open_file.read())

        for log in logs:
            eac_verify(log)

            if log.version is None or log.old_checksum is None:
                message = 'Log entry has no checksum!'
                status = "NO"
            elif log.modified or log.old_checksum != log.checksum:
                message = 'Log entry was modified, checksum incorrect!'
                status = "BAD"
            else:
                message = 'Log entry is fine!'
                status = "OK"

            output.append({
                "message": message,
                "status": status
            })
    except (UnicodeDecodeError, RuntimeError):
        message = 'Log entry has no checksum!'
        output.append({
            "message": message,
            "status": "NO"
        })

    return output


def main():
    parser = argparse.ArgumentParser(
        description='Verifies and resigns EAC logs'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s ' + __version__
    )
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('file', type=Path, help='input log file')

    args = parser.parse_args()

    output = {}
    if not args.json:
        print('Log Integrity Checker   (C) 2010 by Andre Wiethoff')
        print('')
    output = check_checksum(args.file)
    if args.json:
        print(json.dumps(output))
    else:
        for i in range(len(output)):
            print('{:d}. {:s}'.format(i+1, output[i]['message']))


if __name__ == '__main__':
    main()
