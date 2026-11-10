#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=50.0.0"]
# ///
"""Generate and inspect FlexAccess Ed25519 authentication keys with Python 3.11
or newer (any non-end-of-life release).

Usage:
  uv run flexaccess-keys.py generate-auth-key [COMMENT] [-o FILE [--force]] [--json]
  uv run flexaccess-keys.py show-auth-key --private-key-file FILE [-c COMMENT] [--json]

`uv run` installs the `cryptography` dependency declared above into a
throwaway environment. Without uv, run it with `python3` after
`pip install 'cryptography>=50.0.0'`.

Commands, flags, and output match the flexaccess-keys binary; see
https://github.com/flexaccessdev/flexaccess-keys/blob/main/docs/key-format.md
"""

import sys

# The oldest Python release line that still receives security updates. Checked
# before anything else so older interpreters get a clear message.
MIN_PYTHON = (3, 11)
if sys.version_info < MIN_PYTHON:
    sys.exit(
        "Error: Python {}.{} or newer is required (found {}); older releases are "
        "end-of-life and no longer receive security updates".format(
            *MIN_PYTHON, sys.version.split()[0]
        )
    )

import argparse
import base64
import datetime
import importlib.metadata
import json
import os
import re
import secrets

# Keep in sync with the inline metadata above. Every cryptography release
# before this one has a published security advisory. `uv run` enforces the
# floor itself; this check covers running the script with a plain `python3`.
MIN_CRYPTOGRAPHY = (50, 0, 0)
INSTALL_HINT = "run this script with `uv run`, or `pip install 'cryptography>=50.0.0'` first"


def installed_version(distribution):
    try:
        version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None, None
    parts = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    return version, tuple(int(part or 0) for part in parts.groups()) if parts else ()


cryptography_version, cryptography_parts = installed_version("cryptography")
if cryptography_version is None:
    sys.exit(f"Error: the 'cryptography' package is required; {INSTALL_HINT}")
if cryptography_parts < MIN_CRYPTOGRAPHY:
    sys.exit(
        f"Error: cryptography {cryptography_version} has known security "
        f"vulnerabilities; {INSTALL_HINT}"
    )

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

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
    if hasattr(os, "fchmod"):
        # The creation mode is filtered by the umask; set 0600 explicitly.
        os.fchmod(fd, 0o600)
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

    created = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
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
        with open(path, "rb") as file:
            raw = file.read()
    except OSError as error:
        raise CliError(f"Failed to read private key file {path}: {error.strerror}")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CliError(
            f"Failed to read private key file {path}: stream did not contain valid UTF-8"
        )
    # Split on LF only (like the reference parser) so a stray CR stays inside
    # its line and is rejected, rather than silently starting a new line.
    lines = [line.strip() for line in content.split("\n")]

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
                comment = validate_comment(after)
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
