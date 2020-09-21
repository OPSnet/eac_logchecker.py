# EAC Logchecker

![Travis-CI Status](https://img.shields.io/travis/com/OPSnet/eac_logchecker.py/master.svg)
![PyPI](https://img.shields.io/pypi/v/eac_logchecker.svg)

This is a transparent implementation of the Exact Audio Copy log checksum algorithm in Python 3.5+.

This is a fork of https://github.com/puddly/eac_logsigner, with modifications to have it
better match the output of the actual EAC Logchecker to be used in downstream applications. All
credit goes to puddly for reverse-engineering the closed source EAC to develop the base.

## Requirements

* Python 3.5+
* [pprp](http://pypi.org/project/pprp)==0.2.6

## Installation

From PyPI:

    $ pip install eac-logchecker

From source:

    $ git clone https://github.com/OPSnet/eac_logchecker.py
    $ cd eac_logchecker.py
    $ python setup.py install

## Usage

    usage: eac_logchecker.py [-h] [--json] file

    Verifies and resigns EAC logs

    positional arguments:
    file        input log file

    optional arguments:
    -h, --help  show this help message and exit
    --json      Output as JSON

## Example

    $ eac_logchecker logs/01.log
    Log Integrity Checker   (C) 2010 by Andre Wiethoff

    1. Log entry is fine!
    $ eac_logchecker logs/01.log
    $ eac_logchecker logs/05.log
    Log Integrity Checker   (C) 2010 by Andre Wiethoff

    1. Log entry is fine!
    2. Log entry is fine!
    $ eac_logchecker --json logs/05.log
    [{"message": "Log entry is fine!", "status": "OK"}, {"message": "Log entry is fine!", "status": "OK"}]

## Algorithm

 1. Strip the log file of newlines and BOMs.
 2. Cut off the existing signature block and (re-)encode the log text back into little-endian UTF-16
 3. Encrypt the log file with Rijndael-256:
    * in CBC mode
    * with a 256-bit block size (most AES implementations hard-code a 128-bit block size)
    * all-zeroes IV
    * zero-padding
    * the hex key `9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9`
 4. XOR together all of the resulting 256-bit ciphertext blocks. You can do it byte-by-byte, it doesn't matter in the end.
 5. Output the little-endian representation of the above number, in uppercase hex.
