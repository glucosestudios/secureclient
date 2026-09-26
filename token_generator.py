#!/usr/bin/env python3
"""
token_generator.py

Generates a shared-secret keyfile (.token) used by secure_client.py as the
long-term pre-shared secret. This file is NOT a one-time pad - it is high
entropy keying material that secure_client.py runs through HKDF to derive a
fresh AES-256-GCM key for every message/file. It can be reused indefinitely
for as much data as you want (there's no "using it up").

All generation algorithms offered here are cryptographically sound CSPRNGs.
There is no "fast but weak" option - if you want a secure token, every choice
below is safe. The choices differ in construction, not in security margin:

  urandom     Direct OS CSPRNG output (os.urandom). Simplest, recommended
              default - this is what almost everything else (including the
              other two modes) ultimately draws its entropy from anyway.

  hmac_drbg   A NIST SP 800-90A style HMAC-DRBG, seeded from os.urandom.
              Useful if you specifically want a standards-documented
              deterministic-construction generator rather than raw OS output.

  chacha20    ChaCha20 keystream used as a DRBG, seeded from os.urandom.
              Useful if you want the token's generation to be auditable/
              reproducible from a logged seed (see --show-seed), independent
              of the OS RNG implementation.

Usage:
    python3 token_generator.py --length 20480 --algorithm urandom -o shared.token
    python3 token_generator.py --length 20KB --algorithm chacha20 -o shared.token --show-seed
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

MAGIC = b"TOK1"
ALGO_IDS = {"urandom": 0, "hmac_drbg": 1, "chacha20": 2}
ALGO_NAMES = {v: k for k, v in ALGO_IDS.items()}


def parse_length(s: str) -> int:
    """Accepts plain bytes ('20480'), or suffixed sizes ('20KB', '1MB')."""
    s = s.strip().upper()
    multipliers = {"KB": 1024, "MB": 1024 * 1024, "GB": 1024 * 1024 * 1024, "B": 1}
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)]) * mult)
    return int(s)


def gen_urandom(length: int) -> bytes:
    return os.urandom(length)


def gen_hmac_drbg(length: int) -> bytes:
    """
    Minimal HMAC-DRBG (SP 800-90A) instantiated with SHA-256, seeded from
    os.urandom. Not a full compliant implementation (no reseed counter /
    prediction-resistance handling needed for a one-shot generation like
    this), but the core generate function is the real construction.
    """
    entropy = os.urandom(32)
    nonce = os.urandom(16)
    key = b"\x00" * 32
    v = b"\x01" * 32

    def hmac_sha256(k, data):
        return hmac.new(k, data, hashlib.sha256).digest()

    # Instantiate
    key = hmac_sha256(key, v + b"\x00" + entropy + nonce)
    v = hmac_sha256(key, v)
    key = hmac_sha256(key, v + b"\x01" + entropy + nonce)
    v = hmac_sha256(key, v)

    out = b""
    while len(out) < length:
        v = hmac_sha256(key, v)
        out += v
    return out[:length]


def gen_chacha20(length: int, show_seed: bool = False) -> bytes:
    """ChaCha20 keystream as a DRBG: random key+nonce from os.urandom, then
    encrypt an all-zero buffer to produce pure keystream output."""
    key = os.urandom(32)
    nonce = os.urandom(16)  # cryptography's ChaCha20 uses a 16-byte nonce (4-byte counter + 12-byte nonce)
    if show_seed:
        print(f"[chacha20 seed] key={key.hex()} nonce={nonce.hex()}", file=sys.stderr)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(b"\x00" * length)


def create_token_file(output: str, length, algorithm: str = "urandom",
                       force: bool = False, show_seed: bool = False) -> int:
    """
    Core token-creation logic, shared by the CLI (below) and by tui.py.
    `length` may be an int (bytes) or a string accepted by parse_length
    ('20480', '20KB', '1MB', ...). Returns the number of material bytes
    written. Raises ValueError/FileExistsError on problems.
    """
    if algorithm not in ALGO_IDS:
        raise ValueError(f"Unknown algorithm '{algorithm}'. Choose from: {list(ALGO_IDS)}")

    length = length if isinstance(length, int) else parse_length(length)

    if os.path.exists(output) and not force:
        raise FileExistsError(f"{output} already exists. Pass force=True to overwrite.")

    if algorithm == "urandom":
        material = gen_urandom(length)
    elif algorithm == "hmac_drbg":
        material = gen_hmac_drbg(length)
    else:  # chacha20
        material = gen_chacha20(length, show_seed=show_seed)

    header = MAGIC + bytes([ALGO_IDS[algorithm]]) + struct.pack(">I", length)
    with open(output, "wb") as f:
        f.write(header)
        f.write(material)

    # Lock down permissions where the OS supports it - this file is a secret key.
    try:
        os.chmod(output, 0o600)
    except OSError:
        pass

    return length


def main():
    ap = argparse.ArgumentParser(description="Generate a shared-secret .token keyfile.")
    ap.add_argument("--length", "-l", required=True,
                     help="Token length, e.g. 20480, 20KB, 1MB")
    ap.add_argument("--algorithm", "-a", choices=list(ALGO_IDS.keys()), default="urandom",
                     help="Generation algorithm (default: urandom)")
    ap.add_argument("--output", "-o", default="shared.token",
                     help="Output filename (default: shared.token)")
    ap.add_argument("--show-seed", action="store_true",
                     help="(chacha20 only) print the seed key/nonce to stderr for audit logging")
    ap.add_argument("--force", action="store_true", help="Overwrite output file if it exists")
    args = ap.parse_args()

    length = parse_length(args.length)
    if length < 1024:
        print("Warning: tokens under 1KB provide very little long-term keying "
              "material headroom. Proceeding anyway.", file=sys.stderr)

    try:
        written = create_token_file(args.output, length, args.algorithm,
                                     force=args.force, show_seed=args.show_seed)
    except (FileExistsError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Wrote {args.output}: {written} bytes of '{args.algorithm}' keying material.")
    print("Distribute this file to both parties over a channel you already trust "
          "(it is not protected by anything itself). Keep it secret.")


if __name__ == "__main__":
    main()
