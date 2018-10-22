# EAC Logchecker

This is a transparent implementation of the Exact Audio Copy log checksum algorithm in Python 3.4+.

This is a fork of https://github.com/puddly/eac_logsigner, with modifications to have it
better match the output of the actual EAC Logchecker to be used in downstream applications.

# Requirements

* Python 3.5+

# Installation

From PyPI:

    $ pip install eac-logchecker

From source:

    $ git clone https://github.com/OPSnet/eac_logchecker.py
    $ cd eac_logchecker.py
    $ python setup.py install

# Usage

    usage: eac_logchecker [-h] [--json] files [files ...]

    Verifies and resigns EAC logs

    positional arguments:
    files       input log file(s)

    optional arguments:
    -h, --help  show this help message and exit
    --json      Output as JSON


# Overview

The algorithm internally uses UTF-16 strings and XORs a refilling 32-byte buffer of characters with the internal state of what looks to be part of AES-256. The code is pretty short, go read it for more info. Open a pull request if you can figure out a way to simplify it.
