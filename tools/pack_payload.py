#!/usr/bin/env python3
"""Build a small encrypted capability payload for one server tier.

Usage:
    python tools/pack_payload.py <dll> <output>

Required environment variables:
    HIMITSU_PAYLOAD_MASTER_KEY   Base64-encoded 32-byte AES key
    HIMITSU_PAYLOAD_OUTER_SECRET Secret used by SecureJarTool for himitsu.jar
    HIMITSU_PAYLOAD_CLASS_SECRET Secret used by SecureJarTool for class blobs
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import sys

from Crypto.Cipher import AES


def required(name: str, minimum: int = 1) -> str:
    value = os.environ.get(name, "")
    if len(value) < minimum:
        raise SystemExit(f"{name} must contain at least {minimum} characters")
    return value


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)

    dll_path = Path(sys.argv[1]).resolve()
    output_path = Path(sys.argv[2]).resolve()
    if not dll_path.is_file():
        raise SystemExit(f"DLL not found: {dll_path}")

    try:
        key = base64.b64decode(required("HIMITSU_PAYLOAD_MASTER_KEY"), validate=True)
    except Exception as exception:
        raise SystemExit("HIMITSU_PAYLOAD_MASTER_KEY must be valid Base64") from exception
    if len(key) != 32:
        raise SystemExit("HIMITSU_PAYLOAD_MASTER_KEY must decode to exactly 32 bytes")

    payload = json.dumps(
        {
            "protocol": 1,
            "outer_secret": required("HIMITSU_PAYLOAD_OUTER_SECRET", 32),
            "class_secret": required("HIMITSU_PAYLOAD_CLASS_SECRET", 32),
            "dll_sha256": hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")

    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(nonce + ciphertext + tag)

    print(f"payload={output_path}")
    print(f"payload_sha256={hashlib.sha256(output_path.read_bytes()).hexdigest()}")
    print(f"dll_sha256={hashlib.sha256(dll_path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
