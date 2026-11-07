"""Command-line interface for SNOW.

Mirrors the original ``snow`` command-line tool: hide a message in a cover text
(optionally compressed and/or encrypted) or extract a hidden message.

Examples
--------
Hide a message::

    snow -C -p secret -m "hello world" cover.txt stego.txt

Extract it back::

    snow -C -p secret stego.txt

Show available capacity of a cover file::

    snow -S cover.txt
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import config
from .core import message_extract, message_fp_encode, message_string_encode, space_calculate
from .encrypt import password_set


def show_usage(argv0: str) -> None:
    print(f"Usage: {argv0} [-C] [-Q] [-S] [-V | --version] [-h | --help]\n\t[-p passwd] [-l line-len] [-f file | -m message]\n\t[infile [outfile]]")


def show_version() -> None:
    # keep original string
    print("20130616 Apache-2.0 Copyright (C) Matthew Kwan <mkwan@darkside.com.au>")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-C', action='store_true')
    parser.add_argument('-Q', action='store_true')
    parser.add_argument('-S', action='store_true')
    parser.add_argument('-V', action='store_true')
    parser.add_argument('--version', action='store_true')
    parser.add_argument('-h', action='store_true')
    parser.add_argument('--help', action='store_true')
    parser.add_argument('-p', type=str)
    parser.add_argument('-l', type=int, default=80)

    g = parser.add_mutually_exclusive_group()
    g.add_argument('-f', type=str)
    g.add_argument('-m', type=str)

    parser.add_argument('infile', nargs='?')
    parser.add_argument('outfile', nargs='?')

    args = parser.parse_args(argv)

    if args.help or args.h:
        show_usage(sys.argv[0])
        return 0
    if args.version or args.V or args.__dict__.get('version'):
        show_version()
        return 0

    config.compress_flag = bool(args.C)
    config.quiet_flag = bool(args.Q)

    if args.l < 8:
        print(f"Illegal line length value '{args.l}'", file=sys.stderr)
        return 1
    config.line_length = int(args.l)

    if args.p is not None:
        password_set(args.p)

    inf: TextIO
    outf_text: TextIO

    inf = sys.stdin if args.infile is None else open(args.infile, 'r', encoding='utf-8', errors='replace', newline='')
    outf_text = sys.stdout if args.outfile is None else open(args.outfile, 'w', encoding='utf-8', errors='replace', newline='')

    try:
        if args.S:
            space_calculate(inf)
            return 0

        if args.m is not None:
            ok = message_string_encode(args.m, inf, outf_text)
            return 0 if ok else 1

        if args.f is not None:
            with open(args.f, 'r', encoding='utf-8', errors='replace', newline='') as msg_fp:
                ok = message_fp_encode(msg_fp, inf, outf_text)
            return 0 if ok else 1

        # extract
        # output should be bytes; if stdout, use buffer
        outf_bin: BinaryIO
        if args.outfile is None:
            outf_bin = sys.stdout.buffer
        else:
            # when outfile is specified for extract, write raw bytes
            outf_bin = open(args.outfile, 'wb')

        try:
            ok = message_extract(inf, outf_bin)
            return 0 if ok else 1
        finally:
            if args.outfile is not None:
                outf_bin.close()

    finally:
        if inf is not sys.stdin:
            inf.close()
        if outf_text is not sys.stdout:
            outf_text.close()
