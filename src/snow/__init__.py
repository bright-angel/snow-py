"""snow - Steganography in whitespace.

A Python implementation of SNOW (originally by Matthew Kwan), which hides data
in the trailing whitespace of text files. This package exposes the core
operations and the ICE cipher used for the optional encryption layer.

Typical use
-----------
Hide a message::

    import snow
    snow.password_set("secret")
    with open("cover.txt") as inf, open("stego.txt", "w") as outf:
        snow.message_string_encode("hello", inf, outf)

Extract it again::

    with open("stego.txt") as inf, open("out.bin", "wb") as outf:
        snow.message_extract(inf, outf)
"""

from __future__ import annotations

from .core import (
    message_extract,
    message_fp_encode,
    message_string_encode,
    space_calculate,
)
from .encrypt import password_set
from .ice import ICEKey, ice_key_create, ice_key_encrypt

__version__ = "20130616"

__all__ = [
    "message_string_encode",
    "message_fp_encode",
    "message_extract",
    "space_calculate",
    "password_set",
    "ice_key_create",
    "ice_key_encrypt",
    "ICEKey",
    "__version__",
]
