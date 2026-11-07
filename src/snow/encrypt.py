"""ICE encryption/decryption wrapper, ported from ``encrypt.c``.

This stage sits between the message bits and the whitespace encoder (when
hiding) or between the whitespace decoder and the decompressor (when
extracting). It runs ICE in a 1-bit CFB-like mode: each plaintext bit is XORed
with the top bit of ``E_k(IV)`` and the IV is rotated to feed the next bit.

The module-level ``_ice_key`` / ``_encrypt_iv_block`` hold the per-run cipher
state, initialised by :func:`password_set`.
"""

from __future__ import annotations

import sys
from typing import BinaryIO, List, Optional, TextIO

from . import config
from .ice import ICEKey, ice_key_create, ice_key_destroy, ice_key_encrypt, ice_key_set

# Per-run cipher state. Initialised by password_set().
_ice_key: Optional[ICEKey] = None
_encrypt_iv_block = bytearray(8)


def password_set(passwd: str) -> None:
    global _ice_key, _encrypt_iv_block

    level = (len(passwd) * 7 + 63) // 64
    if level == 0:
        if not config.quiet_flag:
            print("Warning: an empty password is being used", file=sys.stderr)
        level = 1
    elif level > 128:
        if not config.quiet_flag:
            print("Warning: password truncated to 1170 chars", file=sys.stderr)
        level = 128

    _ice_key = ice_key_create(level)
    if _ice_key is None:
        if not config.quiet_flag:
            print("Warning: failed to set password", file=sys.stderr)
        return

    buf = bytearray(1024)

    i = 0
    for ch in passwd:
        c = ord(ch) & 0x7F
        idx = i // 8
        bit = i & 7
        if bit == 0:
            buf[idx] = (c << 1) & 0xFF
        elif bit == 1:
            buf[idx] |= c & 0xFF
        else:
            buf[idx] |= (c >> (bit - 1)) & 0xFF
            buf[idx + 1] = (c << (9 - bit)) & 0xFF
        i += 7
        if i > 8184:
            break

    ice_key_set(_ice_key, bytes(buf))

    # IV = E_k(key) (first 8 bytes from buf as in C)
    _encrypt_iv_block[:] = ice_key_encrypt(_ice_key, bytes(buf[:8]))


class _Encryptor:
    def __init__(self, encoder: "_Encoder") -> None:
        self.encoder = encoder

    def bit(self, bit: int, inf: TextIO, outf: TextIO) -> bool:
        global _ice_key, _encrypt_iv_block
        if _ice_key is None:
            return self.encoder.bit(bit, inf, outf)

        ks = ice_key_encrypt(_ice_key, bytes(_encrypt_iv_block))
        if ks[0] & 0x80:
            bit = 0 if bit else 1

        # rotate IV one bit left
        iv = _encrypt_iv_block
        for i in range(8):
            nxt = iv[i + 1] if i < 7 else 0
            iv[i] = ((iv[i] << 1) & 0xFF) | (1 if (nxt & 0x80) else 0)
        iv[7] = (iv[7] & 0xFE) | (1 if bit else 0)

        return self.encoder.bit(bit, inf, outf)

    def flush(self, inf: TextIO, outf: TextIO) -> bool:
        global _ice_key
        ice_key_destroy(_ice_key)
        _ice_key = None
        return self.encoder.flush(inf, outf)


class _Decryptor:
    def __init__(self, uncompressor: "_Uncompressor") -> None:
        self.uncompressor = uncompressor

    def bit(self, bit: int, outf: BinaryIO) -> bool:
        global _ice_key, _encrypt_iv_block
        if _ice_key is None:
            return self.uncompressor.bit(bit)

        ks = ice_key_encrypt(_ice_key, bytes(_encrypt_iv_block))
        nbit = (0 if bit else 1) if (ks[0] & 0x80) else bit

        # rotate IV one bit left (with ciphertext bit)
        iv = _encrypt_iv_block
        for i in range(8):
            nxt = iv[i + 1] if i < 7 else 0
            iv[i] = ((iv[i] << 1) & 0xFF) | (1 if (nxt & 0x80) else 0)
        iv[7] = (iv[7] & 0xFE) | (1 if bit else 0)

        return self.uncompressor.bit(nbit)

    def flush(self, outf: BinaryIO) -> bool:
        global _ice_key
        ice_key_destroy(_ice_key)
        _ice_key = None
        return self.uncompressor.flush()
