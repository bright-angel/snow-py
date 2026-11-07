# snow — Steganography in Whitespace

A faithful Python port of **SNOW** (by Matthew Kwan), which hides data in the
*trailing whitespace* of text files. The implementation is behaviourally
compatible with the original C program.

This repository refactors the original single-file `snow.py` into a standard
Python package layout.

## What it does

SNOW embeds a secret message into the spaces and tabs at the end of lines in a
"cover" text. Because trailing whitespace is normally invisible, the message is
concealed in plain sight. Optionally the message can be:

- **compressed** with a built-in Huffman coder (`-C`), and/or
- **encrypted** with the ICE cipher (`-p <password>`).

## Project structure

```
snow-py/
├── pyproject.toml          # PEP 621 metadata + build config
├── README.md
├── LICENSE                 # Apache-2.0
├── .gitignore
├── src/
│   └── snow/               # the importable package
│       ├── __init__.py     # public API + __version__
│       ├── __main__.py     # enables `python -m snow`
│       ├── config.py       # shared runtime flags
│       ├── huffman.py      # Huffman code table
│       ├── ice.py          # ICE cipher (from ice.c)
│       ├── encoder.py      # whitespace hide/extract (from encode.c)
│       ├── compress.py     # Huffman compress/decompress (from compress.c)
│       ├── encrypt.py      # ICE wrapper (from encrypt.c)
│       ├── core.py         # high-level pipeline
│       └── cli.py          # command-line interface
└── tests/
    ├── test_snow.py
    └── data/               # sample cover + stego fixtures
```

## Installation

From the repository root (requires Python 3.8+):

```bash
pip install -e .
```

This installs the `snow` command and makes the `snow` package importable.

To run without installing, set `PYTHONPATH` to `src`:

```bash
PYTHONPATH=src python -m snow --help
```

## Command-line usage

```
Usage: snow [-C] [-Q] [-S] [-V | --version] [-h | --help]
      [-p passwd] [-l line-len] [-f file | -m message]
      [infile [outfile]]
```

| Option | Meaning |
|--------|---------|
| `-C`   | Compress the message with Huffman coding |
| `-Q`   | Quiet — suppress informational messages |
| `-S`   | Calculate and print the storage capacity of `infile` |
| `-p`   | Password for ICE encryption/decryption |
| `-l`   | Line length of the cover text (default 80, minimum 8) |
| `-m`   | Hide the given message string |
| `-f`   | Hide the contents of the given message file |

### Examples

Hide and recover a message (compressed + encrypted):

```bash
snow -C -p 123456 -m "flag{aaa}" tests/data/test.txt testa.txt
snow -C -p 123456 testa.txt
# -> flag{aaa}
```

Hide without a password:

```bash
snow -C -m "flag{bbb}" tests/data/test.txt testb.txt
snow -C testb.txt
# -> flag{bbb}
```

Hide without compression:

```bash
snow -m "flag{ccc}" tests/data/test.txt testc.txt
snow testc.txt
# -> flag{ccc}
```

Show how much data a cover file can hold:

```bash
snow -S tests/data/test.txt
```

## Library usage

```python
import snow

snow.password_set("123456")

# Hide a message
with open("cover.txt", "r", encoding="utf-8", newline="") as inf, \
     open("stego.txt", "w", encoding="utf-8", newline="") as outf:
    snow.message_string_encode("flag{aaa}", inf, outf)

# Extract it
with open("stego.txt", "r", encoding="utf-8", newline="") as inf, \
     open("out.bin", "wb") as outf:
    snow.message_extract(inf, outf)
```

> Note: when reading/writing cover and stego text, open files with
> `newline=""` so line endings are preserved exactly, which is required for
> correct behaviour.

## Tests

```bash
pytest
```

The tests verify behavioural compatibility by decoding the original `testa/b/c`
fixtures and performing fresh encode→extract round trips.

## License

Apache-2.0. Original implementation Copyright (C) Matthew Kwan
<mkwan@darkside.com.au>.
