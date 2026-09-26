#!/usr/bin/env python3
"""
secure_client.py

The actual encryption/decryption client. Ingests a shared-secret .token file
(produced by token_generator.py) and uses it to encrypt/decrypt text or
files of arbitrary size.

Design summary:
  - Token file is treated as long-term keying material, NOT a one-time pad.
    It is never "used up" - every message derives its own single-use key.
  - Per-message key derivation: HKDF-SHA256(ikm=token_bytes, salt=random,
    info=context_string) -> 32-byte AES-256 key. Salt is random per message
    and travels in the ciphertext header (it's not secret).
  - Bulk cipher: AES-256-GCM (authenticated - confidentiality + integrity).
  - Large data is streamed in fixed-size chunks so memory use stays flat
    regardless of file size. Each chunk gets a unique nonce (derived from a
    random per-message base nonce XORed with a chunk counter) and is bound,
    via AAD, to its chunk index and to whether it's the final chunk - this
    stops an attacker from reordering, dropping, or truncating chunks
    without detection.

Usage:
    # Text
    python3 secure_client.py encrypt-text --token shared.token --in "hello world" --out msg.enc
    python3 secure_client.py decrypt-text --token shared.token --in msg.enc

    # Files
    python3 secure_client.py encrypt-file --token shared.token --in report.pdf --out report.pdf.enc
    python3 secure_client.py decrypt-file --token shared.token --in report.pdf.enc --out report.pdf
"""

import argparse
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC_TOKEN = b"TOK1"
MAGIC_MSG = b"ENCX"
VERSION = 1
CHUNK_SIZE = 1024 * 1024  # 1 MiB per chunk
SALT_LEN = 16
BASE_NONCE_LEN = 12
KEY_LEN = 32

HKDF_INFO_TEXT = b"secure_client:text:v1"
HKDF_INFO_FILE = b"secure_client:file:v1"


# ---------------------------------------------------------------------------
# Token handling
# ---------------------------------------------------------------------------

def load_token(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 9 or data[:4] != MAGIC_TOKEN:
        raise ValueError(f"{path} does not look like a valid .token file (bad magic).")
    declared_len = struct.unpack(">I", data[5:9])[0]
    material = data[9:]
    if len(material) != declared_len:
        raise ValueError(
            f"{path} is corrupt or truncated: header declares {declared_len} bytes, "
            f"found {len(material)}."
        )
    if len(material) < 32:
        raise ValueError("Token is too short to safely derive keys from (need >= 32 bytes).")
    return material


def derive_key(token_bytes: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=info)
    return hkdf.derive(token_bytes)


def chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """Derive a unique per-chunk nonce from a random per-message base nonce."""
    ctr = struct.pack(">Q", index)  # 8 bytes
    tail = bytes(a ^ b for a, b in zip(base_nonce[4:], ctr))
    return base_nonce[:4] + tail


def chunk_aad(index: int, is_last: bool) -> bytes:
    return struct.pack(">Q", index) + (b"\x01" if is_last else b"\x00")


# ---------------------------------------------------------------------------
# Text encrypt/decrypt (single AEAD call - text messages aren't chunked)
# ---------------------------------------------------------------------------

def encrypt_text(token_bytes: bytes, plaintext: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(BASE_NONCE_LEN)
    key = derive_key(token_bytes, salt, HKDF_INFO_TEXT)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return MAGIC_MSG + bytes([VERSION, 0]) + salt + nonce + ct  # mode byte 0 = text


def decrypt_text(token_bytes: bytes, blob: bytes) -> str:
    _check_header(blob, expected_mode=0)
    salt = blob[6:6 + SALT_LEN]
    nonce = blob[6 + SALT_LEN:6 + SALT_LEN + BASE_NONCE_LEN]
    ct = blob[6 + SALT_LEN + BASE_NONCE_LEN:]
    key = derive_key(token_bytes, salt, HKDF_INFO_TEXT)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt.decode("utf-8")


def _check_header(blob: bytes, expected_mode: int):
    if len(blob) < 6 or blob[:4] != MAGIC_MSG:
        raise ValueError("Not a valid secure_client message (bad magic).")
    version, mode = blob[4], blob[5]
    if version != VERSION:
        raise ValueError(f"Unsupported message version {version}.")
    if mode != expected_mode:
        raise ValueError("Wrong decrypt command for this message type (text vs file).")


# ---------------------------------------------------------------------------
# File encrypt/decrypt (chunked/streamed - safe for large files)
# ---------------------------------------------------------------------------

def encrypt_file(token_bytes: bytes, in_path: str, out_path: str):
    salt = os.urandom(SALT_LEN)
    base_nonce = os.urandom(BASE_NONCE_LEN)
    key = derive_key(token_bytes, salt, HKDF_INFO_FILE)
    aesgcm = AESGCM(key)

    filename = os.path.basename(in_path).encode("utf-8")
    if len(filename) > 65535:
        raise ValueError("Filename too long.")

    total_size = os.path.getsize(in_path)
    written = 0

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(MAGIC_MSG + bytes([VERSION, 1]))  # mode byte 1 = file
        fout.write(salt + base_nonce)
        fout.write(struct.pack(">H", len(filename)) + filename)

        index = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            written += len(chunk)
            is_last = written >= total_size
            nonce = chunk_nonce(base_nonce, index)
            aad = chunk_aad(index, is_last)
            ct = aesgcm.encrypt(nonce, chunk, associated_data=aad)
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)
            index += 1
            if is_last:
                break
        # Note: for a zero-byte input, fin.read() immediately returns b"",
        # written stays 0 >= total_size (0), so is_last is True on the very
        # first iteration and the loop above already emits exactly one
        # (empty-plaintext) chunk carrying the final-chunk marker. No special
        # casing needed - and adding one would reuse chunk index 0's nonce,
        # which is exactly the kind of bug this design is meant to prevent.

    print(f"Encrypted {in_path} ({total_size} bytes) -> {out_path} in {index} chunk(s).")


def decrypt_file(token_bytes: bytes, in_path: str, out_path: str = None) -> str:
    with open(in_path, "rb") as fin:
        header = fin.read(6)
        _check_header(header + b"\x00" * 100, expected_mode=1)  # pad for length check only
        salt = fin.read(SALT_LEN)
        base_nonce = fin.read(BASE_NONCE_LEN)
        name_len = struct.unpack(">H", fin.read(2))[0]
        orig_filename = fin.read(name_len).decode("utf-8")

        key = derive_key(token_bytes, salt, HKDF_INFO_FILE)
        aesgcm = AESGCM(key)

        final_out = out_path or orig_filename
        index = 0
        saw_last = False
        with open(final_out, "wb") as fout:
            while True:
                len_bytes = fin.read(4)
                if len(len_bytes) == 0:
                    break
                if len(len_bytes) != 4:
                    raise ValueError("Truncated/corrupt ciphertext (bad chunk length field).")
                ct_len = struct.unpack(">I", len_bytes)[0]
                ct = fin.read(ct_len)
                if len(ct) != ct_len:
                    raise ValueError("Truncated/corrupt ciphertext (short chunk).")

                nonce = chunk_nonce(base_nonce, index)
                # Try both AAD possibilities is wrong - we must know is_last up front,
                # so instead we peek: try last=False first, and if that fails AND
                # this is the final read, try last=True. Simpler: try False then True.
                pt = None
                last_error = None
                for is_last_guess in (False, True):
                    try:
                        aad = chunk_aad(index, is_last_guess)
                        pt = aesgcm.decrypt(nonce, ct, associated_data=aad)
                        saw_last = is_last_guess
                        break
                    except Exception as e:  # noqa: BLE001 - AEAD failure, try next guess
                        last_error = e
                if pt is None:
                    raise ValueError(
                        f"Authentication failed on chunk {index}: wrong token, or the "
                        f"file was corrupted/tampered with."
                    ) from last_error

                fout.write(pt)
                index += 1

        if not saw_last:
            raise ValueError(
                "File ended without a final-chunk marker - this looks like a "
                "truncated (incomplete) ciphertext, not the original file."
            )

    print(f"Decrypted {in_path} -> {final_out} ({index} chunk(s)).")
    return final_out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Encrypt/decrypt text or files using a shared .token secret.")
    ap.add_argument("command", choices=["encrypt-text", "decrypt-text", "encrypt-file", "decrypt-file"])
    ap.add_argument("--token", required=True, help="Path to the shared .token file")
    ap.add_argument("--in", dest="infile", required=True,
                     help="Input: literal text (encrypt-text) or a file path (all other commands)")
    ap.add_argument("--out", dest="outfile", default=None,
                     help="Output file path (optional for decrypt-file, defaults to stored original filename)")
    args = ap.parse_args()

    token_bytes = load_token(args.token)

    if args.command == "encrypt-text":
        blob = encrypt_text(token_bytes, args.infile)
        out = args.outfile or "message.enc"
        with open(out, "wb") as f:
            f.write(blob)
        print(f"Encrypted text -> {out} ({len(blob)} bytes).")

    elif args.command == "decrypt-text":
        with open(args.infile, "rb") as f:
            blob = f.read()
        pt = decrypt_text(token_bytes, blob)
        if args.outfile:
            with open(args.outfile, "w") as f:
                f.write(pt)
            print(f"Decrypted text -> {args.outfile}")
        else:
            print(pt)

    elif args.command == "encrypt-file":
        out = args.outfile or (args.infile + ".enc")
        encrypt_file(token_bytes, args.infile, out)

    elif args.command == "decrypt-file":
        decrypt_file(token_bytes, args.infile, args.outfile)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileNotFoundError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
