# Generating keys with scripts

You can generate FlexAccess keys without installing anything. The
[`scripts/`](../scripts) directory has two standalone scripts. Each one is a
single file and a full alternative to the `flexaccess-keys` binary:

| Script | Requires | Run with |
| --- | --- | --- |
| [`flexaccess-keys.mjs`](../scripts/flexaccess-keys.mjs) | Node.js 22, 24, or 26+ (built-in `node:crypto` only) | `node flexaccess-keys.mjs` |
| [`flexaccess-keys.py`](../scripts/flexaccess-keys.py) | Python 3.11+ and [`cryptography`](https://pypi.org/project/cryptography/) | `uv run flexaccess-keys.py` |

Both have the binary's commands and flags, and they write the same
key-file format:

```text
generate-auth-key [COMMENT] [-o FILE [--force]] [--json]
show-auth-key --private-key-file FILE [-c COMMENT] [--json]
```

So a key made by either script can be read by the binary, by the Rust library,
and by the other script. The same goes the other way.

## Getting a script

Each script is published next to the binary installers:

```bash
curl -fsSLO https://flexaccessdev.github.io/flexaccess-keys/flexaccess-keys.mjs
curl -fsSLO https://flexaccessdev.github.io/flexaccess-keys/flexaccess-keys.py
```

On Windows PowerShell:

```powershell
Invoke-WebRequest https://flexaccessdev.github.io/flexaccess-keys/flexaccess-keys.mjs -OutFile flexaccess-keys.mjs
```

You can also copy the files from a checkout of this repository. The scripts are
short; read the one you use before generating keys with it.

## Usage

Write a private key file with mode `0600` and append its authorized-key entry:

```bash
node flexaccess-keys.mjs generate-auth-key "alice laptop" --output client.key
node flexaccess-keys.mjs show-auth-key --private-key-file client.key >> authorized_keys
```

Swap `node flexaccess-keys.mjs` for `uv run flexaccess-keys.py`; nothing else
changes. Without `--output`, the key file goes to stdout. `--output` refuses to
overwrite an existing file unless you pass `--force`, which replaces the file
atomically. `--json` prints machine-readable output:

```bash
node flexaccess-keys.mjs generate-auth-key "build server" --json
# {"authorized_key":"ed25519-pub:... build server","private_key":"ed25519-sec:..."}
```

Notes per script:

- **Node.js:** needs no packages and runs on any platform Node supports,
  including Windows.
- **Python:** the script declares its dependency inline
  ([PEP 723](https://peps.python.org/pep-0723/)), so `uv run` installs
  `cryptography` into a throwaway environment. Without
  [uv](https://docs.astral.sh/uv/), `pip install 'cryptography>=50.0.0'` and run
  `python3 flexaccess-keys.py`.

## Doing it by hand

Each recipe below makes the same tokens using only the underlying tools. Use
one when you are building key generation into your own tooling and would rather
not ship a script. Both tokens are exactly 32 raw bytes encoded as unpadded
URL-safe base64 (`+` → `-`, `/` → `_`, trailing `=` removed); see
[key-format.md](key-format.md) for the full format.

### OpenSSL

Requires OpenSSL 1.1.1 or newer (Ed25519 support).

#### Generate a key pair

```bash
umask 077  # every file below, including client.pem, is created private
openssl genpkey -algorithm ed25519 -out client.pem

# The last 32 bytes of the PKCS#8 private DER are the raw seed; the last
# 32 bytes of the SubjectPublicKeyInfo DER are the raw public key.
seed=$(openssl pkey -in client.pem -outform DER | tail -c 32 \
  | openssl base64 -A | tr '+/' '-_' | tr -d '=')
pub=$(openssl pkey -in client.pem -pubout -outform DER | tail -c 32 \
  | openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "ed25519-sec:$seed"
echo "ed25519-pub:$pub"
```

To write a private-key file the tooling parses (only the token line is
required; `#` header lines are optional). Unlike the binary, the `>`
redirection overwrites an existing file, so pick a path that is not in use:

```bash
{
  echo "# Ed25519 authentication key"
  echo "# Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Public key: ed25519-pub:$pub alice laptop"
  echo "ed25519-sec:$seed"
} > client.key
shred -u client.pem 2>/dev/null || rm -f client.pem
```

#### Derive the public token from an existing private token

The equivalent of `show-auth-key`: rebuild the PKCS#8 DER by prepending the
fixed 16-byte Ed25519 header to the decoded seed, then let OpenSSL derive the
public half. A 32-byte seed always encodes to 43 base64 characters, so exactly
one `=` restores the padding for decoding.

```bash
tok=$(grep -m 1 '^[[:space:]]*ed25519-sec:' client.key | tr -d '[:space:]')
pub=$(
  {
    printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
    printf '%s=' "${tok#ed25519-sec:}" | tr '_-' '/+' | openssl base64 -d -A
  } | openssl pkey -inform DER -pubout -outform DER | tail -c 32 \
    | openssl base64 -A | tr '+/' '-_' | tr -d '='
)
echo "ed25519-pub:$pub"
```

### Node.js

The built-in `node:crypto` module supports Ed25519 with no third-party
packages, and its JWK export fields (`d` for the seed, `x` for
the public key) are already unpadded URL-safe base64 — the token encoding.
Use a Node.js release that still receives security updates (22, 24, or 26 or
newer; 23 and 25 are end-of-life), as the `flexaccess-keys.mjs` script requires.

#### Generate a key pair

```bash
node -e '
const { generateKeyPairSync } = require("node:crypto");
const { privateKey } = generateKeyPairSync("ed25519");
const jwk = privateKey.export({ format: "jwk" });
console.log("ed25519-sec:" + jwk.d);
console.log("ed25519-pub:" + jwk.x);
'
```

#### Derive the public token from an existing private token

As with OpenSSL, rebuild the PKCS#8 DER around the decoded seed and let the
platform derive the public half:

```js
const { createPrivateKey, createPublicKey } = require("node:crypto");
const { readFileSync } = require("node:fs");

const tok = readFileSync("client.key", "utf8")
  .split("\n")
  .map((line) => line.trim())
  .find((line) => line && !line.startsWith("#"));

const der = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  Buffer.from(tok.replace("ed25519-sec:", ""), "base64url"),
]);
const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
console.log("ed25519-pub:" + publicJwk.x);
```

### Python

Requires Python 3.11 or newer, the oldest release line that still receives
security updates, and the
[`cryptography`](https://pypi.org/project/cryptography/) package; the standard
library alone cannot do Ed25519. With [uv](https://docs.astral.sh/uv/)
the scripts below run in a throwaway environment without touching the system
Python:

```bash
uv run --with 'cryptography>=50.0.0' generate.py
```

Or with an explicit virtual environment:

```bash
uv venv
uv pip install 'cryptography>=50.0.0'
uv run generate.py
```

#### Generate a key pair

Save as `generate.py`:

```python
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def token(prefix, raw):
    return prefix + base64.urlsafe_b64encode(raw).decode().rstrip("=")

private_key = Ed25519PrivateKey.generate()
seed = private_key.private_bytes(
    serialization.Encoding.Raw,
    serialization.PrivateFormat.Raw,
    serialization.NoEncryption(),
)
public = private_key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)

print(token("ed25519-sec:", seed))
print(token("ed25519-pub:", public))
```

#### Derive the public token from an existing private token

Save as `derive.py` and run the same way:

```python
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

with open("client.key") as file:
    tok = next(
        line
        for line in map(str.strip, file)
        if line and not line.startswith("#")
    )

seed = base64.urlsafe_b64decode(tok.removeprefix("ed25519-sec:") + "=")
public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
print("ed25519-pub:" + base64.urlsafe_b64encode(public).decode().rstrip("="))
```

## Cross-checking

Any tool can confirm a key made by another. For example:

```bash
node flexaccess-keys.mjs show-auth-key --private-key-file client.key
flexaccess-keys show-auth-key --private-key-file client.key
```

Every tool prints the same entry for the same key file. The entry starts with
the `ed25519-pub:` token, followed by the comment from the key file's
`# Public key:` header, if there is one.
