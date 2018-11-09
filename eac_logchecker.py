#!/usr/bin/env python3

import argparse
import contextlib
import json
from pathlib import Path
import re
import pprp

CHECKSUM_MIN_VERSION = ('V1.0', 'beta', '1')


def eac_checksum(text):
    # Ignore newlines
    text = text.replace('\r', '').replace('\n', '')

    # Fuzzing reveals BOMs are also ignored
    text = text.replace('\ufeff', '').replace('\ufffe', '')

    # Setup Rijndael-256 with a 256-bit blocksize
    cipher = pprp.crypto_3.rijndael(
        # Probably SHA256('super secret password') but it doesn't actually matter
        key=bytes.fromhex('9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9'),
        block_size=256 // 8
    )

    # Encode the text as UTF-16-LE
    plaintext = text.encode('utf-16-le')

    # The IV is all zeroes so we don't have to handle it
    signature = b'\x00' * 32

    # Process it block-by-block
    for i in range(0, len(plaintext), 32):
        # Zero-pad the last block, if necessary
        plaintext_block = plaintext[i:i + 32].ljust(32, b'\x00')

        # CBC mode (XOR the previous ciphertext block into the plaintext)
        cbc_plaintext = bytes(a ^ b for a, b in zip(signature, plaintext_block))

        # New signature is the ciphertext.
        signature = cipher.encrypt(cbc_plaintext)

    # Textual signature is just the hex representation
    return signature.hex().upper()


def extract_info(text):
    if len(text) == 0:
        return text, None, None

    version = text.splitlines()[0]

    if not version.startswith('Exact Audio Copy'):
        version = None
    else:
        version = tuple(version.split()[3:6])

    match = re.search('\n\n==== (.*) ([A-Z0-9]+) ====', text)
    if match:
        text, signature_parts = re.split('\n\n==== {}'.format(match.group(1)), text)
        signature = signature_parts.split()[0].strip()
    else:
        signature = None

    return text, version, signature


def eac_verify(text):
    unsigned_text, version, old_signature = extract_info(text)
    return unsigned_text, version, old_signature, eac_checksum(unsigned_text)


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

    return [x.strip() for x in re.split(r'[^-]-{60}[^-]', text)]


def check_checksum(arg_file, arg_json):
    if not isinstance(arg_file, Path):
        arg_file = Path(arg_file)
    
    output = []

    if not arg_file.exists():
        if not arg_json:
            print('Could not find logfile to examine.')

    try:
        with arg_file.open('rb') as open_file:
            logs = get_logs(open_file.read())

        for log in logs:
            data, version, old_signature, actual_signature = eac_verify(log)

            if version is None or old_signature is None:
                message = 'Log entry has no checksum!'
                status = "NO"
            elif old_signature != actual_signature:
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
    parser = argparse.ArgumentParser(description='Verifies and resigns EAC logs')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('file', type=Path, help='input log file')

    args = parser.parse_args()

    output = {}
    if not args.json:
        print('Log Integrity Checker   (C) 2010 by Andre Wiethoff')
        print('')
    output = check_checksum(args.file, args.json)
    if args.json:
        print(json.dumps(output))
    else:
        for i in range(len(output)):
            print('{:d}. {:s}'.format(i+1, output[i]['message']))

if __name__ == '__main__':
    main()
