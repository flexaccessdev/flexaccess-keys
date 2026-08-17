# FlexAccess authentication key format

This document is the normative specification of the shared Ed25519
authentication key format. `flexaccess-keys` is the canonical implementation;
consumers (such as tunnel-rs) must treat this repository as the single source
of truth for key encoding, key files, and authorized-keys documents, and must
not reimplement them.

## Tokens

A key token is a prefix followed by exactly 32 raw bytes encoded as URL-safe
base64 without padding (RFC 4648 §5, `=` removed):

```text
ed25519-sec:<base64url(32-byte private seed)>
ed25519-pub:<base64url(32-byte public key)>
```

The encoded portion is always 43 characters. Parsers must reject tokens with
a missing or unknown prefix, non-base64url characters, or a decoded length
other than 32 bytes. Public keys must additionally be valid Ed25519 points;
signatures are verified strictly (`verify_strict`).

## Private-key file

The canonical private-key file is the private token preceded by three `#`
header lines:

```text
# Ed25519 authentication key
# Created: <RFC 3339 UTC instant, e.g. 2026-08-17T19:00:00Z>
# Public key: ed25519-pub:<public key> <comment>
ed25519-sec:<private seed>
```

Parsing rules:

- Each line is trimmed of surrounding whitespace.
- Blank lines and lines starting with `#` are ignored.
- Exactly one key line must remain; zero or more than one is an error.
- The headers are optional: a file containing only the bare `ed25519-sec:`
  token is valid.

When deriving an authorized-key entry from a private-key file, an explicitly
supplied comment always wins. Otherwise, a `# Public key:` header whose token
matches the public key derived from the private key contributes its trailing
comment; a header naming a different key (stale after the key line was
replaced) is ignored.

Files are created with mode `0600` on Unix, are not overwritten unless the
caller forces it, and forced overwrites replace the target atomically.

## Comments

A comment is free-form UTF-8 attached to a public key, as in OpenSSH
authorized-keys files. Comments are trimmed of surrounding whitespace and must
not contain CR or LF. An empty comment is valid.

## Authorized-keys document

An authorized-keys document lists the public keys an application accepts, one
entry per line:

```text
# clients
ed25519-pub:<public key> alice laptop
ed25519-pub:<public key> build server
```

Parsing rules:

- Each line is trimmed; blank lines and lines starting with `#` are ignored.
- The first whitespace-delimited field is the public-key token; everything
  after it, trimmed, is the entry's comment (possibly empty).
- An invalid token or comment is an error that names the source and line
  number.
- If the same public key appears on multiple lines, the last entry wins.

## Signing

The key format carries no message framing. Each application defines its own
domain-separated transcript and passes those bytes to the raw sign/verify
operations; two applications sharing a key can never accept each other's
signatures as long as their domains differ.
