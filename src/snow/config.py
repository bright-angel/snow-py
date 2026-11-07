"""Shared runtime configuration for the snow package.

The original C program (and the single-file Python port) used a handful of
module-level globals to toggle behaviour (compression, quiet mode) and to
control the line length used when hiding data in whitespace.

To keep behavioural compatibility while moving to a package layout, those
globals now live in this dedicated module. Every other module reads and writes
them through the ``config`` namespace (e.g. ``config.compress_flag``) instead of
relying on scattered module globals.
"""

from __future__ import annotations

# Whether to apply Huffman compression before hiding data.
compress_flag: bool = False

# Whether to suppress informational messages on stderr.
quiet_flag: bool = False

# Maximum line length (in columns) of the cover text.
line_length: int = 80
