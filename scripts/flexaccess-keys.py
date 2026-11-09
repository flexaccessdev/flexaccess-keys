#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["cryptography>=3.0"]
# ///
"""Generate and inspect FlexAccess Ed25519 authentication keys with Python.

Usage:
  uv run flexaccess-keys.py generate-auth-key [COMMENT] [-o FILE [--force]] [--json]
  uv run flexaccess-keys.py show-auth-key --private-key-file FILE [-c COMMENT] [--json]

`uv run` installs the `cryptography` dependency declared above into a
throwaway environment. Without uv, run it with `python3` after
`pip install cryptography`.

Commands, flags, and output match the flexaccess-keys binary; see
https://github.com/flexaccessdev/flexaccess-keys/blob/main/docs/key-format.md
"""

import argparse
import base64
import datetime
import json
import os
import re
import secrets
import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.exit(
        "Error: the 'cryptography' package is required; run this script with "
        "`uv run`, or `pip install cryptography` first"
    )

PRIVATE_PREFIX = "ed25519-sec:"
PUBLIC_PREFIX = "ed25519-pub:"
PUBLIC_HEADER = "# Public key:"
# 32 bytes encode to 43 characters; the last one carries two zero bits.
KEY_B64URL = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")


class CliError(Exception):
    pass


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def public_b64(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64url(raw)


def validate_comment(comment):
    if "\r" in comment or "\n" in comment:
        raise CliError("Authorized-key comment must not contain line breaks")
    return comment.strip()


def authorized_key(public, comment):
    entry = PUBLIC_PREFIX + public
    return f"{entry} {comment}" if comment else entry


def dump_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def write_and_sync(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())


def write_private_key_file(path, content, force):
    """Create the file with mode 0600, never overwriting unless forced; forced
    overwrites replace the target atomically via a temporary file."""
    directory, name = os.path.split(path)
    try:
        if directory:
            os.makedirs(directory, exist_ok=True)
        if not force:
            try:
                write_and_sync(path, content)
            except FileExistsError:
                raise CliError(f"File already exists: {path}. Use --force to overwrite.")
            return
        temp = os.path.join(directory, f".{name}.{secrets.token_urlsafe(8)}.tmp")
        try:
            write_and_sync(temp, content)
            os.replace(temp, path)
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise
    except OSError as error:
        raise CliError(f"Failed to write private key file {path}: {error.strerror}")


def generate_auth_key(args):
    if args.force and args.output is None:
        raise CliError("--force requires --output")
    comment = validate_comment(args.comment)
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    private_token = PRIVATE_PREFIX + b64url(seed)
    entry = authorized_key(public_b64(private_key), comment)

    if args.json:
        print(dump_json({"authorized_key": entry, "private_key": private_token}))
        return

    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    key_file = (
        "# Ed25519 authentication key\n"
        f"# Created: {created}\n"
        f"{PUBLIC_HEADER} {entry}\n"
        f"{private_token}\n"
    )
    if args.output is None or args.output == "-":
        sys.stdout.write(key_file)
    else:
        write_private_key_file(os.path.expanduser(args.output), key_file, args.force)


def show_auth_key(args):
    path = os.path.expanduser(args.private_key_file)
    try:
        with open(path, encoding="utf-8") as file:
            lines = [line.strip() for line in file.read().split("\n")]
    except OSError as error:
        raise CliError(f"Failed to read private key file {path}: {error.strerror}")

    key_lines = [line for line in lines if line and not line.startswith("#")]
    if not key_lines:
        raise CliError(f"No authentication private key found in {path}")
    if len(key_lines) > 1:
        raise CliError(f"Invalid authentication private key in {path}: multiple key lines")
    if not key_lines[0].startswith(PRIVATE_PREFIX):
        raise CliError(
            f"Invalid authentication private key in {path}: "
            f"Private key must start with '{PRIVATE_PREFIX}'"
        )
    encoded = key_lines[0][len(PRIVATE_PREFIX):]
    if not KEY_B64URL.fullmatch(encoded):
        raise CliError(
            f"Invalid authentication private key in {path}: "
            "Ed25519 private key must be 43 base64url characters encoding 32 bytes"
        )
    seed = base64.urlsafe_b64decode(encoded + "=")
    public = public_b64(Ed25519PrivateKey.from_private_bytes(seed))

    if args.comment is not None:
        comment = validate_comment(args.comment)
    else:
        # A `# Public key:` header naming this key contributes its comment; a
        # stale header for a different key is ignored.
        comment = ""
        token = PUBLIC_PREFIX + public
        for line in lines:
            if not line.startswith(PUBLIC_HEADER):
                continue
            rest = line[len(PUBLIC_HEADER):].lstrip()
            after = rest[len(token):]
            if rest.startswith(token) and after[:1].isspace():
                comment = after.strip()
                break

    entry = authorized_key(public, comment)
    print(dump_json({"authorized_key": entry}) if args.json else entry)


def parser():
    root = argparse.ArgumentParser(
        prog="flexaccess-keys.py",
        description="Manage shared FlexAccess Ed25519 authentication keys",
    )
    commands = root.add_subparsers(dest="command", metavar="COMMAND", required=True)

    generate = commands.add_parser(
        "generate-auth-key", help="Generate an Ed25519 authentication private key"
    )
    generate.add_argument(
        "comment", nargs="?", default="", help="Comment appended to the authorized-key entry"
    )
    output = generate.add_mutually_exclusive_group()
    output.add_argument(
        "-o", "--output", help='Path where the private key file is saved ("-" means stdout)'
    )
    output.add_argument(
        "--json",
        action="store_true",
        help="Print the authorized-key entry and private key as JSON",
    )
    generate.add_argument(
        "--force", action="store_true", help="Overwrite an existing output file"
    )
    generate.set_defaults(run=generate_auth_key)

    show = commands.add_parser(
        "show-auth-key", help="Derive an authorized-key entry from a private key file"
    )
    show.add_argument(
        "--private-key-file",
        required=True,
        help="Path to the Ed25519 authentication private key file",
    )
    show.add_argument(
        "-c", "--comment", help="Replace the comment stored in the key file header"
    )
    show.add_argument(
        "--json", action="store_true", help="Print the authorized-key entry as JSON"
    )
    show.set_defaults(run=show_auth_key)
    return root


def main():
    args = parser().parse_args()
    try:
        args.run(args)
    except CliError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
