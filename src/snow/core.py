"""High-level SNOW operations: encode a message, extract a message, and
calculate available cover-text capacity.

These functions wire together the encoder, compressor and encryptor stages into
the full hide/extract pipeline.
"""

from __future__ import annotations

import sys
from typing import BinaryIO, TextIO

from . import config
from .compress import _Compressor, _Uncompressor
from .encoder import _Decoder, _Encoder, _tabpos, _wsgets_strip
from .encrypt import _Decryptor, _Encryptor


def _character_encode_byte(c: int, compressor: _Compressor, inf: TextIO, outf: TextIO) -> bool:
    for i in range(8):
        bit = 1 if (c & (128 >> i)) else 0
        if not compressor.bit(bit, inf, outf):
            return False
    return True


def message_string_encode(msg: str, inf: TextIO, outf: TextIO) -> bool:
    encoder = _Encoder()
    encryptor = _Encryptor(encoder)
    compressor = _Compressor(encryptor.bit, encryptor.flush)

    for ch in msg:
        if not _character_encode_byte(ord(ch) & 0xFF, compressor, inf, outf):
            return False

    return compressor.flush(inf, outf)


def message_fp_encode(msg_fp: TextIO, inf: TextIO, outf: TextIO) -> bool:
    encoder = _Encoder()
    encryptor = _Encryptor(encoder)
    compressor = _Compressor(encryptor.bit, encryptor.flush)

    while True:
        c = msg_fp.read(1)
        if c == "":
            break
        if not _character_encode_byte(ord(c) & 0xFF, compressor, inf, outf):
            return False

    return compressor.flush(inf, outf)


def message_extract(inf: TextIO, outf_bin: BinaryIO) -> bool:
    uncompressor = _Uncompressor(outf_bin)
    decryptor = _Decryptor(uncompressor)
    decoder = _Decoder()
    return decoder.extract(inf, decryptor.bit, decryptor.flush, outf_bin)


def space_calculate(inf: TextIO) -> None:
    # ported from encode.c
    n_lo = 0
    n_hi = 0

    def whitespace_storage(buf: str) -> None:
        nonlocal n_lo, n_hi
        ln = len(buf)
        if ln > config.line_length - 2:
            return
        if ln // 8 == config.line_length // 8:
            n_hi += 3
            return
        if (ln & 7) > 0:
            n_hi += 3
            ln = _tabpos(ln)
        if (config.line_length & 7) > 0:
            n_hi += 3
        n = ((config.line_length - ln) // 8) * 3
        n_hi += n
        n_lo += n

    for line in inf:
        buf = _wsgets_strip(line)
        whitespace_storage(buf)

    if n_lo > 0:
        n_lo -= 1
        n_hi -= 1

    if n_lo == n_hi:
        print(f"File has storage capacity of {n_lo} bits ({n_lo // 8} bytes)")
    else:
        print(f"File has storage capacity of between {n_lo} and {n_hi} bits.")
        print(f"Approximately {(n_lo + n_hi) // 16} bytes.")
