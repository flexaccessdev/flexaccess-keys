# flexaccess-keys

Shared Ed25519 authentication key format and Rust tooling for FlexAccess
applications.

This repository is the canonical home for:

- the app-independent `ed25519-sec:` private-key and `ed25519-pub:` public-key
  tokens;
- generated private-key files and SSH-like authorized-key entries;
- key generation, parsing, derivation, raw signing, and strict verification;
- common `generate-auth-key` and `show-auth-key` command behavior.

Application authentication protocols are intentionally out of scope. A
consumer must define its own domain-separated signed message and wire protocol;
the library only signs or verifies the bytes supplied by that consumer.

## Key format

Both tokens hold exactly 32 raw bytes as unpadded URL-safe base64:

```text
ed25519-sec:<private seed>
ed25519-pub:<public key>
```

A generated private-key file is self-describing while remaining parseable as a
single secret token:

```text
# Ed25519 authentication key
# Created: 2026-08-17T19:00:00Z
# Public key: ed25519-pub:<public key> alice laptop
ed25519-sec:<private seed>
```

An authorized-keys document contains one public token per line, optionally
followed by a comment. Blank lines and `#` comments are ignored:

```text
ed25519-pub:<public key> alice laptop
ed25519-pub:<public key> build server
```

Private key files created with `--output` use mode `0600` on Unix.

## CLI

Run without installing:

```bash
cargo run --release --features cli -- generate-auth-key "alice laptop" > client.key
cargo run --release --features cli -- show-auth-key --private-key-file client.key
```

Or install the standalone binary:

```bash
cargo install --git https://github.com/flexaccessdev/flexaccess-keys --features cli \
  flexaccess-keys

flexaccess-keys generate-auth-key "alice laptop" > client.key
flexaccess-keys show-auth-key --private-key-file client.key > authorized_keys

# 0.5-compatible structured generation for automation
flexaccess-keys generate-auth-key "alice laptop" --json
# {"authorized_key":"ed25519-pub:... alice laptop","private_key":"ed25519-sec:..."}
```

Like `age-keygen`, `generate-auth-key` writes a self-describing private-key file
to stdout by default; its `# Public key:` header includes the authorized-key
entry and comment. Use `--output client.key` to create the private-key file with
mode `0600` on Unix instead. Successful generation writes nothing to stderr.
The explicit `--json` mode retains the 0.5 command behavior: it writes both the
authorized-key entry and private-key token to stdout as one JSON object without
creating a file.

Public-key output is deliberately separate. `show-auth-key` derives the entry
from the private key and writes it to stdout; add `--json` and select
`.authorized_key` with `jq` for structured automation. Stderr is reserved for
errors in every mode.

If the binary is unavailable, the same tokens can be produced with OpenSSL or
Python; see [docs/fallback-key-generation.md](docs/fallback-key-generation.md).

## Library

Before the first tagged release, consumers can use the Git repository directly:

```toml
[dependencies]
flexaccess-keys = { git = "https://github.com/flexaccessdev/flexaccess-keys", default-features = false }
```

Add a `rev` for reproducible builds.

### Features

The default feature set is empty so library consumers compile only the key
format, Ed25519 operations, secure randomness, and file handling they use.

- `commands` adds shared command output helpers and JSON serialization.
- `cli` adds the standalone binary and implies `commands`.
- `fast` enables ed25519-dalek's larger precomputed verification tables.

Applications embedding the shared command helpers can opt in without pulling
in Clap:

```toml
flexaccess-keys = { git = "https://github.com/flexaccessdev/flexaccess-keys", features = ["commands"] }
```

The primary API consists of:

- `PrivateKey`: generate, parse, serialize, derive a public key, and sign an
  application-defined message;
- `PublicKey`: parse, serialize, and strictly verify a signature;
- `AuthorizedKey` and `AuthorizedKeys`: comments and authorized-key parsing;
- private-key and authorized-key file loaders;
- shared implementations of the two CLI operations.

The optional `cli` feature enables the standalone binary and its Clap parser;
the default library feature set remains empty.

## Consumers

- [tunnel-rs](https://github.com/flexaccessdev/tunnel-rs) uses this crate for
  client authentication key management while retaining its own challenge
  transcript.
- [flextunnel](https://github.com/flexaccessdev/flextunnel) is the planned
  phase-2 consumer.
