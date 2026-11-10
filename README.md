# flexaccess-keys

Shared Ed25519 authentication key format for FlexAccess applications, with a
Rust library, a CLI binary, and standalone Node.js and Python scripts
for generating keys.

This repository is the canonical home for:

- the app-independent `ed25519-sec:` private-key and `ed25519-pub:` public-key
  tokens;
- generated private-key files and SSH-like authorized-key entries;
- key generation, parsing, derivation, raw signing, and strict verification;
- common `generate-auth-key` and `show-auth-key` command behavior, provided by
  both the `flexaccess-keys` binary and standalone Node.js and Python scripts.

Application authentication protocols are intentionally out of scope. A
consumer must define its own domain-separated signed message and wire protocol;
the library only signs or verifies the bytes supplied by that consumer.

## Key format

[docs/key-format.md](docs/key-format.md) is the normative specification;
consumers must not reimplement the format. In short, both tokens hold exactly
32 raw bytes as unpadded URL-safe base64:

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

## Generating keys

Use whichever tool you already have. The `flexaccess-keys` binary and the
standalone scripts have the same commands, flags, and output, so a key made
with one works with all the others.

| Tool | Requires | Command |
| --- | --- | --- |
| `flexaccess-keys` binary | nothing | `flexaccess-keys` |
| [`flexaccess-keys.mjs`](scripts/flexaccess-keys.mjs) | Node.js 22, 24, or 26+, no packages | `node flexaccess-keys.mjs` |
| [`flexaccess-keys.py`](scripts/flexaccess-keys.py) | Python 3.11+ and `cryptography` | `uv run flexaccess-keys.py` |

### Binary

The binary has no runtime dependencies. It is also the Rust library's
reference implementation (see [Library](#library)).

**Linux & macOS:**

```bash
curl -sSL https://flexaccessdev.github.io/flexaccess-keys/install.sh | bash
```

**Windows:**

```powershell
irm https://flexaccessdev.github.io/flexaccess-keys/install.ps1 | iex
```

This puts `flexaccess-keys` in your `PATH`.

<details>
<summary>Advanced binary installation options</summary>

Install a specific release:

```bash
# Linux/macOS
curl -sSL https://flexaccessdev.github.io/flexaccess-keys/install.sh | bash -s v0.0.2
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://flexaccessdev.github.io/flexaccess-keys/install.ps1))) v0.0.2
```

By default the installer pulls the latest stable release. Use `--prerelease`
on Linux/macOS or `-PreRelease` on Windows to install the newest prerelease.

> **Note:** Prerelease artifacts may not include Windows binaries. If one is
> unavailable, use a stable release or build from source.

Build from source with Cargo:

```bash
cargo install --git https://github.com/flexaccessdev/flexaccess-keys --features cli \
  flexaccess-keys
```

Or run from a local checkout without installing:

```bash
cargo run --release --features cli -- generate-auth-key "alice laptop" > client.key
cargo run --release --features cli -- show-auth-key --private-key-file client.key
```

</details>

### Scripts

Each script is one self-contained file you can read before running. There is
nothing to install: download the one that fits your machine and run it.

**Node.js:**

```bash
curl -fsSLO https://flexaccessdev.github.io/flexaccess-keys/flexaccess-keys.mjs
node flexaccess-keys.mjs generate-auth-key "alice laptop" --output client.key
node flexaccess-keys.mjs show-auth-key --private-key-file client.key > authorized_keys
```

**Python:**

```bash
curl -fsSLO https://flexaccessdev.github.io/flexaccess-keys/flexaccess-keys.py
uv run flexaccess-keys.py generate-auth-key "alice laptop" --output client.key
uv run flexaccess-keys.py show-auth-key --private-key-file client.key > authorized_keys
```

[uv](https://docs.astral.sh/uv/) reads the dependency declared in the script and
installs `cryptography` in a throwaway environment. Without uv, run
`pip install 'cryptography>=50.0.0'` and then use `python3 flexaccess-keys.py`.

Both scripts run on Linux, macOS, and Windows. On Windows, use
`Invoke-WebRequest -OutFile` in place of `curl -fsSLO` if `curl` is not
available.

See [docs/scripts.md](docs/scripts.md) for how the scripts work and for
copy-paste recipes that build the same keys inside your own tooling.

## Commands

The examples below use the binary. They work unchanged with any of the scripts:
replace `flexaccess-keys` with `node flexaccess-keys.mjs` or
`uv run flexaccess-keys.py`.

Generate a private key and derive its authorized-key entry:

```bash
flexaccess-keys generate-auth-key "alice laptop" > client.key
flexaccess-keys show-auth-key --private-key-file client.key > authorized_keys

# 0.5-compatible structured generation for automation
flexaccess-keys generate-auth-key "alice laptop" --json
# {"authorized_key":"ed25519-pub:... alice laptop","private_key":"ed25519-sec:..."}
```

Like `age-keygen`, `generate-auth-key` writes a self-describing private-key file
to stdout by default; its `# Public key:` header includes the authorized-key
entry and comment. Use `--output client.key` to create the private-key file with
mode `0600` on Unix instead; add `--force` to replace an existing file.
Successful generation writes nothing to stderr. The explicit `--json` mode
retains the 0.5 command behavior: it writes both the authorized-key entry and
private-key token to stdout as one JSON object without creating a file.

Public-key output is deliberately separate. `show-auth-key` derives the entry
from the private key and writes it to stdout; pass `--comment` to replace the
stored comment, or add `--json` and select `.authorized_key` with `jq` for
structured automation. Stderr is reserved for errors in every mode.

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

## License

MIT — see [LICENSE](LICENSE).
