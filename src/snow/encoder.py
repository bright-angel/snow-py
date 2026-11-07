"""Whitespace steganography core, ported from ``encode.c``.

This module hides and extracts a stream of bits in the *trailing* whitespace of
each line of a cover text. Three bits are encoded per "unit" of trailing
whitespace using a combination of spaces and tabs. The pipeline is callback
based: encryption/compression stages sit in front of the encoder when hiding,
and in front of the decoder when extracting.
"""

from __future__ import annotations

import sys
from typing import BinaryIO, List, TextIO

from . import config


def _tabpos(n: int) -> int:
    return (n + 8) & ~7


def _wsgets_strip(line: str) -> str:
    # strip trailing spaces/tabs/newlines/carriage returns
    i = len(line) - 1
    while i >= 0 and line[i] in (' ', '\t', '\n', '\r'):
        i -= 1
    return line[: i + 1]


class _Encoder:
    def __init__(self) -> None:
        self.bit_count = 0
        self.value = 0
        self.buffer_loaded = False
        self.buffer = ""
        self.buffer_len = 0
        self.buffer_col = 0
        self.first_tab = False
        self.needs_tab = False
        self.bits_used = 0
        self.bits_available = 0
        self.lines_extra = 0

    def _whitespace_storage(self, buf: str, n_lo_hi: List[int]) -> None:
        # n_lo_hi: [n_lo, n_hi]
        n_lo, n_hi = n_lo_hi
        ln = len(buf)
        if ln > config.line_length - 2:
            n_lo_hi[0], n_lo_hi[1] = n_lo, n_hi
            return
        if ln // 8 == config.line_length // 8:
            n_hi += 3
            n_lo_hi[0], n_lo_hi[1] = n_lo, n_hi
            return
        if (ln & 7) > 0:
            n_hi += 3
            ln = _tabpos(ln)
        if (config.line_length & 7) > 0:
            n_hi += 3
        n = ((config.line_length - ln) // 8) * 3
        n_hi += n
        n_lo += n
        n_lo_hi[0], n_lo_hi[1] = n_lo, n_hi

    def _buffer_load(self, inf: TextIO) -> None:
        line = inf.readline()
        if line == "":
            self.buffer = ""
            self.lines_extra += 1
        else:
            self.buffer = _wsgets_strip(line)

        self.buffer_len = len(self.buffer)
        col = 0
        for ch in self.buffer:
            if ch == '\t':
                col = _tabpos(col)
            else:
                col += 1
        self.buffer_col = col
        self.buffer_loaded = True
        self.needs_tab = False

    def _wsputs(self, outf: TextIO) -> bool:
        try:
            outf.write(self.buffer + "\n")
        except OSError as e:
            print(f"Text output: {e}", file=sys.stderr)
            return False
        return True

    def _append_whitespace(self, nsp: int) -> bool:
        col = self.buffer_col
        if self.needs_tab:
            col = _tabpos(col)
        if nsp == 0:
            col = _tabpos(col)
        else:
            col += nsp
        if col >= config.line_length:
            return False

        if self.needs_tab:
            self.buffer += "\t"
            self.buffer_len += 1
            self.buffer_col = _tabpos(self.buffer_col)

        if nsp == 0:
            self.buffer += "\t"
            self.buffer_len += 1
            self.buffer_col = _tabpos(self.buffer_col)
            self.needs_tab = False
        else:
            self.buffer += " " * nsp
            self.buffer_len += nsp
            self.buffer_col += nsp
            self.needs_tab = True

        return True

    def _write_value(self, val: int, inf: TextIO, outf: TextIO) -> bool:
        if not self.buffer_loaded:
            self._buffer_load(inf)

        if not self.first_tab:
            while _tabpos(self.buffer_col) >= config.line_length:
                if not self._wsputs(outf):
                    return False
                self._buffer_load(inf)
            self.buffer += "\t"
            self.buffer_len += 1
            self.buffer_col = _tabpos(self.buffer_col)
            self.first_tab = True

        # reverse bit ordering (as in C)
        nspc = ((val & 1) << 2) | (val & 2) | ((val & 4) >> 2)

        while not self._append_whitespace(nspc):
            if not self._wsputs(outf):
                return False
            self._buffer_load(inf)

        if self.lines_extra == 0:
            self.bits_available += 3

        return True

    def bit(self, bit: int, inf: TextIO, outf: TextIO) -> bool:
        self.value = ((self.value << 1) | (1 if bit else 0)) & 0x7
        self.bits_used += 1
        self.bit_count += 1
        if self.bit_count == 3:
            if not self._write_value(self.value, inf, outf):
                return False
            self.value = 0
            self.bit_count = 0
        return True

    def flush(self, inf: TextIO, outf: TextIO) -> bool:
        if self.bit_count > 0:
            while self.bit_count < 3:
                self.value = (self.value << 1) & 0x7
                self.bit_count += 1
            if not self._write_value(self.value, inf, outf):
                return False

        # write remaining input
        if self.buffer_loaded:
            if not self._wsputs(outf):
                return False
            self.buffer_loaded = False
            self.buffer = ""
            self.buffer_len = 0
            self.buffer_col = 0

        n_lo_hi = [0, 0]
        for line in inf:
            buf = _wsgets_strip(line)
            self._whitespace_storage(buf, n_lo_hi)
            try:
                outf.write(buf + "\n")
            except OSError as e:
                print(f"Text output: {e}", file=sys.stderr)
                return False

        n_lo, n_hi = n_lo_hi
        self.bits_available += (n_lo + n_hi) // 2

        if not config.quiet_flag:
            if self.lines_extra > 0:
                pct = (float(self.bits_used) / float(self.bits_available) - 1.0) * 100.0 if self.bits_available else 0.0
                print(f"Message exceeded available space by approximately {pct:.2f}%.", file=sys.stderr)
                print(f"An extra {self.lines_extra} lines were added.", file=sys.stderr)
            else:
                pct = (float(self.bits_used) / float(self.bits_available) * 100.0) if self.bits_available else 0.0
                print(f"Message used approximately {pct:.2f}% of available space.", file=sys.stderr)

        return True


class _Decoder:
    def __init__(self) -> None:
        self.start_tab_found = False

    @staticmethod
    def _decode_bits(spc: int, decrypt_cb, outf: BinaryIO) -> bool:
        if spc > 7:
            print(f"Illegal encoding of {spc} spaces", file=sys.stderr)
            return False
        b1 = 1 if (spc & 1) else 0
        b2 = 1 if (spc & 2) else 0
        b3 = 1 if (spc & 4) else 0
        return decrypt_cb(b1, outf) and decrypt_cb(b2, outf) and decrypt_cb(b3, outf)

    def _decode_whitespace(self, s: str, decrypt_cb, outf: BinaryIO) -> bool:
        spc = 0
        for ch in s:
            if ch == ' ':
                spc += 1
            elif ch == '\t':
                if not self._decode_bits(spc, decrypt_cb, outf):
                    return False
                spc = 0
            else:
                # should not happen inside whitespace
                pass
        if spc > 0:
            if not self._decode_bits(spc, decrypt_cb, outf):
                return False
        return True

    def extract(self, inf: TextIO, decrypt_cb, decrypt_flush_cb, outf: BinaryIO) -> bool:
        for line in inf:
            # find last run of whitespace before newline
            line2 = line.rstrip('\n').rstrip('\r')
            last_ws_idx = None
            in_ws = False
            for i, ch in enumerate(line2):
                if ch in (' ', '\t'):
                    if not in_ws:
                        last_ws_idx = i
                        in_ws = True
                else:
                    in_ws = False
                    last_ws_idx = None

            if last_ws_idx is None:
                continue

            ws = line2[last_ws_idx:]

            if (not self.start_tab_found) and ws and ws[0] == ' ':
                continue

            if (not self.start_tab_found) and ws and ws[0] == '\t':
                self.start_tab_found = True
                ws = ws[1:]
                if ws == "":
                    continue

            if not self._decode_whitespace(ws, decrypt_cb, outf):
                return False

        return decrypt_flush_cb(outf)
