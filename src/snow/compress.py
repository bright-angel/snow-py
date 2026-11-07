"""Optional Huffman compression stage, ported from ``compress.c``.

When compression is enabled (``-C``), each 8-bit message byte is replaced by its
variable-length Huffman code before being handed to the encryption/encoding
stages. The decompressor matches incoming bits against the table to recover
bytes. When compression is disabled these classes pass bits straight through.
"""

from __future__ import annotations

import sys
from typing import BinaryIO, TextIO

from . import config
from .huffman import HUFFCODES


class _OutputBits:
    def __init__(self, outf: BinaryIO) -> None:
        self.outf = outf
        self.bit_count = 0
        self.value = 0

    def bit(self, bit: int) -> bool:
        self.value = ((self.value << 1) | (1 if bit else 0)) & 0xFF
        self.bit_count += 1
        if self.bit_count == 8:
            try:
                self.outf.write(bytes([self.value]))
            except OSError as e:
                print(f"Output file: {e}", file=sys.stderr)
                return False
            self.value = 0
            self.bit_count = 0
        return True

    def flush(self) -> bool:
        if self.bit_count > 2 and not config.quiet_flag:
            print(f"Warning: residual of {self.bit_count} bits not output", file=sys.stderr)
        return True


class _Uncompressor:
    def __init__(self, outf: BinaryIO) -> None:
        self.out_bits = _OutputBits(outf)
        self.buf = []  # list of '0'/'1'

    def bit(self, bit: int) -> bool:
        if not config.compress_flag:
            return self.out_bits.bit(bit)

        self.buf.append('1' if bit else '0')
        s = ''.join(self.buf)

        # find match (linear like C)
        try:
            code = HUFFCODES.index(s)
        except ValueError:
            code = -1

        if code >= 0:
            for i in range(8):
                b = 1 if (code & (128 >> i)) else 0
                if not self.out_bits.bit(b):
                    return False
            self.buf.clear()

        if len(self.buf) >= 255:
            print("Error: Huffman uncompress buffer overflow", file=sys.stderr)
            return False

        return True

    def flush(self) -> bool:
        if config.compress_flag and len(self.buf) > 2 and not config.quiet_flag:
            print(f"Warning: residual of {len(self.buf)} bits not uncompressed", file=sys.stderr)
        return self.out_bits.flush()


class _Compressor:
    def __init__(self, encrypt_bit_cb, encrypt_flush_cb) -> None:
        self.encrypt_bit_cb = encrypt_bit_cb
        self.encrypt_flush_cb = encrypt_flush_cb
        self.bit_count = 0
        self.value = 0
        self.bits_in = 0
        self.bits_out = 0

    def bit(self, bit: int, inf: TextIO, outf: TextIO) -> bool:
        if not config.compress_flag:
            return self.encrypt_bit_cb(bit, inf, outf)

        self.bits_in += 1
        self.value = ((self.value << 1) | (1 if bit else 0)) & 0xFF
        self.bit_count += 1
        if self.bit_count == 8:
            s = HUFFCODES[self.value]
            for ch in s:
                b = 1 if ch == '1' else 0
                if not self.encrypt_bit_cb(b, inf, outf):
                    return False
                self.bits_out += 1
            self.value = 0
            self.bit_count = 0
        return True

    def flush(self, inf: TextIO, outf: TextIO) -> bool:
        if self.bit_count != 0 and not config.quiet_flag:
            print(f"Warning: residual of {self.bit_count} bits not compressed", file=sys.stderr)

        if self.bits_out > 0 and not config.quiet_flag:
            cpc = (float(self.bits_in - self.bits_out) / float(self.bits_in) * 100.0) if self.bits_in else 0.0
            if cpc < 0.0:
                print(
                    f"Compression enlarged data by {-cpc:.2f}% - recommend not using compression",
                    file=sys.stderr,
                )
            else:
                print(f"Compressed by {cpc:.2f}%", file=sys.stderr)

        return self.encrypt_flush_cb(inf, outf)
