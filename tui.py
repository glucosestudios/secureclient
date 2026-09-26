#!/usr/bin/env python3
"""
tui.py

A menu-driven text UI wrapping token_generator.py and secure_client.py, so
you don't have to remember CLI flags. Built using ONLY the Python standard
library (plus `cryptography`, which the other two scripts already require)
so it needs nothing extra installed and behaves identically on Windows and
on Linux/macOS.

Keep this file in the same folder as token_generator.py and secure_client.py.

Run:
    python3 tui.py      (Linux/macOS)
    python tui.py       (Windows)
"""

import os
import sys
from pathlib import Path

# On Windows 10+, this call has the side effect of enabling ANSI escape-code
# processing in the console host (a well-known, harmless trick). On
# Linux/macOS terminals ANSI is already supported, so this is a no-op there.
if os.name == "nt":
    os.system("")

try:
    import token_generator as tg
    import secure_client as sc
except ImportError as e:
    print(f"Could not import token_generator.py / secure_client.py: {e}")
    print("Make sure both files are in the same folder as tui.py.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Terminal helpers (stdlib only)
# ---------------------------------------------------------------------------

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    DIM = "\033[2m"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner(title: str):
    clear()
    width = 66
    print(C.CYAN + C.BOLD + "=" * width + C.RESET)
    print(C.CYAN + C.BOLD + title.center(width) + C.RESET)
    print(C.CYAN + C.BOLD + "=" * width + C.RESET)
    print()


def ok(msg: str):
    print(f"{C.GREEN}[OK] {msg}{C.RESET}")


def err(msg: str):
    print(f"{C.RED}[ERROR] {msg}{C.RESET}")


def info(msg: str):
    print(f"{C.DIM}{msg}{C.RESET}")


def pause():
    input(f"\n{C.DIM}Press Enter to return to the menu...{C.RESET}")


def prompt(label: str, default: str = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{label}{suffix}: ").strip()
    return val if val else (default if default is not None else "")


def confirm(label: str, default_no: bool = True) -> bool:
    hint = "[y/N]" if default_no else "[Y/n]"
    val = input(f"{label} {hint}: ").strip().lower()
    if not val:
        return not default_no
    return val.startswith("y")


# ---------------------------------------------------------------------------
# Built-in file browser (stdlib only - no OS-native file dialogs available
# without extra dependencies, so this is a lightweight numbered-list browser)
# ---------------------------------------------------------------------------

def browse(start: str = ".") -> str:
    """Navigate directories by number; return a chosen file/directory path,
    or None if the user cancels."""
    try:
        current = Path(start).expanduser().resolve()
    except OSError:
        current = Path.cwd()

    while True:
        clear()
        print(f"{C.CYAN}{C.BOLD}Browsing: {current}{C.RESET}\n")
        try:
            entries = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            entries = []
            err("Permission denied listing this directory.")

        for i, e in enumerate(entries):
            tag = "DIR " if e.is_dir() else "FILE"
            print(f"  [{i}] {tag}  {e.name}")

        print()
        print("  [..]  up one directory")
        print("  [.]   select the current directory")
        print("  [q]   cancel / type a path manually instead")
        choice = input("\n> ").strip()

        if choice.lower() == "q":
            return None
        if choice == "..":
            current = current.parent
            continue
        if choice == ".":
            return str(current)
        if choice.isdigit() and 0 <= int(choice) < len(entries):
            sel = entries[int(choice)]
            if sel.is_dir():
                current = sel
                continue
            return str(sel)

        # Anything else: treat it as a manually typed path. If it names an
        # existing directory, navigate into it rather than "selecting" it -
        # only files (existing, or new filenames for output) get returned.
        manual = Path(choice).expanduser()
        if manual.is_dir():
            current = manual.resolve()
            continue
        return str(manual)


def prompt_path(label: str, default: str = None, must_exist: bool = False) -> str:
    """Prompt for a path; typing 'b' opens the built-in browser instead."""
    while True:
        val = prompt(f"{label} (or 'b' to browse)", default)
        if val.lower() == "b":
            picked = browse()
            if picked is None:
                continue
            return picked
        if must_exist and not Path(val).expanduser().exists():
            err(f"'{val}' does not exist.")
            if not confirm("Try again?", default_no=False):
                return val
            continue
        return val


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def action_generate_token():
    banner("Generate Shared Token")
    print("This creates the shared-secret .token file both sides need.")
    print("It's long-term keying material, not a one-time pad - it never")
    print("gets 'used up', however much data you encrypt with it.\n")

    length_str = prompt("Token length (e.g. 20KB, 20480, 1MB)", "20KB")
    print("\nAlgorithms (all are real CSPRNGs, none are weak):")
    print("  urandom    - direct OS random output (recommended default)")
    print("  hmac_drbg  - NIST SP 800-90A style HMAC-DRBG")
    print("  chacha20   - ChaCha20 keystream as a DRBG")
    algo = prompt("Algorithm", "urandom").strip().lower()
    if algo not in tg.ALGO_IDS:
        err(f"Unknown algorithm '{algo}', falling back to 'urandom'.")
        algo = "urandom"

    out_path = prompt_path("Output token path", "shared.token")
    force = False
    if Path(out_path).exists():
        force = confirm(f"{out_path} already exists. Overwrite?")
        if not force:
            info("Cancelled.")
            pause()
            return

    print()
    try:
        length = tg.parse_length(length_str)
        if length < 1024:
            print(f"{C.YELLOW}Warning: tokens under 1KB give very little headroom.{C.RESET}")
        written = tg.create_token_file(out_path, length, algo, force=force)
        ok(f"Wrote {out_path}: {written} bytes ('{algo}').")
        info("Distribute this file to both parties over a channel you already trust.")
    except Exception as e:
        err(str(e))
    pause()


def action_encrypt_text():
    banner("Encrypt Text")
    token_path = prompt_path("Token file", "shared.token", must_exist=True)
    print("\nEnter the text to encrypt (single line):")
    plaintext = input("> ")
    out_path = prompt_path("Output file", "message.enc")

    try:
        token_bytes = sc.load_token(token_path)
        blob = sc.encrypt_text(token_bytes, plaintext)
        with open(out_path, "wb") as f:
            f.write(blob)
        ok(f"Encrypted -> {out_path} ({len(blob)} bytes).")
    except Exception as e:
        err(str(e))
    pause()


def action_decrypt_text():
    banner("Decrypt Text")
    token_path = prompt_path("Token file", "shared.token", must_exist=True)
    in_path = prompt_path("Encrypted file", "message.enc", must_exist=True)

    try:
        token_bytes = sc.load_token(token_path)
        with open(in_path, "rb") as f:
            blob = f.read()
        pt = sc.decrypt_text(token_bytes, blob)
        print()
        ok("Decrypted successfully. Contents:\n")
        print(f"{C.BOLD}{pt}{C.RESET}")
    except Exception as e:
        err(str(e))
    pause()


def action_encrypt_file():
    banner("Encrypt File")
    token_path = prompt_path("Token file", "shared.token", must_exist=True)
    in_path = prompt_path("File to encrypt", must_exist=True)
    default_out = in_path + ".enc"
    out_path = prompt_path("Output file", default_out)

    try:
        token_bytes = sc.load_token(token_path)
        size = Path(in_path).stat().st_size
        info(f"Encrypting {size:,} bytes...")
        sc.encrypt_file(token_bytes, in_path, out_path)
        ok(f"Encrypted -> {out_path}")
    except Exception as e:
        err(str(e))
    pause()


def action_decrypt_file():
    banner("Decrypt File")
    token_path = prompt_path("Token file", "shared.token", must_exist=True)
    in_path = prompt_path("Encrypted file", must_exist=True)
    out_path = prompt("Output file (blank = use the stored original filename)", "")

    try:
        token_bytes = sc.load_token(token_path)
        result_path = sc.decrypt_file(token_bytes, in_path, out_path or None)
        ok(f"Decrypted -> {result_path}")
    except Exception as e:
        err(str(e))
    pause()


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

MENU = [
    ("1", "Generate a new shared token", action_generate_token),
    ("2", "Encrypt text", action_encrypt_text),
    ("3", "Decrypt text", action_decrypt_text),
    ("4", "Encrypt a file", action_encrypt_file),
    ("5", "Decrypt a file", action_decrypt_file),
    ("q", "Quit", None),
]


def main():
    while True:
        banner("Secure Client - Main Menu")
        for key, label, _ in MENU:
            print(f"  [{key}] {label}")
        print()
        choice = input("> ").strip().lower()

        if choice == "q":
            clear()
            print("Goodbye.")
            break

        matched = next((m for m in MENU if m[0] == choice), None)
        if matched is None:
            err("Not a valid option.")
            pause()
            continue

        _, _, action = matched
        try:
            action()
        except KeyboardInterrupt:
            print()
            info("Cancelled.")
            pause()
        except EOFError:
            # Input stream closed (Ctrl+D on Linux/macOS, Ctrl+Z+Enter on
            # Windows) mid-prompt. Nothing more can be read, so exit cleanly
            # instead of crashing with a raw traceback.
            print("\nInput closed, exiting.")
            return


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")
