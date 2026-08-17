# Fallback key generation with standard tools

If the `flexaccess-keys` binary is unavailable or not working, the same
`ed25519-sec:` / `ed25519-pub:` tokens can be produced with OpenSSL or Python.
Both tokens are exactly 32 raw bytes encoded as unpadded URL-safe base64
(`+` → `-`, `/` → `_`, trailing `=` removed); see the README for the full
format.

Every recipe below produces byte-identical output to the binary: a key
generated one way can be read, derived, and verified by any of the others.

## OpenSSL

Requires OpenSSL 1.1.1 or newer (Ed25519 support).

### Generate a key pair

```bash
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
required; `#` header lines are optional):

```bash
umask 077
{
  echo "# Ed25519 authentication key"
  echo "# Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Public key: ed25519-pub:$pub alice laptop"
  echo "ed25519-sec:$seed"
} > client.key
shred -u client.pem 2>/dev/null || rm -f client.pem
```

### Derive the public token from an existing private token

The equivalent of `show-auth-key`: rebuild the PKCS#8 DER by prepending the
fixed 16-byte Ed25519 header to the decoded seed, then let OpenSSL derive the
public half. A 32-byte seed always encodes to 43 base64 characters, so exactly
one `=` restores the padding for decoding.

```bash
tok=$(grep -v '^#' client.key)
pub=$(
  {
    printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
    printf '%s=' "${tok#ed25519-sec:}" | tr '_-' '/+' | openssl base64 -d -A
  } | openssl pkey -inform DER -pubout -outform DER | tail -c 32 \
    | openssl base64 -A | tr '+/' '-_' | tr -d '='
)
echo "ed25519-pub:$pub"
```

## Node.js

The easiest fallback: the built-in `node:crypto` module supports Ed25519 with
no third-party packages, and its JWK export fields (`d` for the seed, `x` for
the public key) are already unpadded URL-safe base64 — the token encoding.
Requires Node 16 or newer.

### Generate a key pair

```bash
node -e '
const { generateKeyPairSync } = require("node:crypto");
const { privateKey } = generateKeyPairSync("ed25519");
const jwk = privateKey.export({ format: "jwk" });
console.log("ed25519-sec:" + jwk.d);
console.log("ed25519-pub:" + jwk.x);
'
```

### Derive the public token from an existing private token

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

## Python

Requires the [`cryptography`](https://pypi.org/project/cryptography/) package;
the standard library alone cannot do Ed25519. With [uv](https://docs.astral.sh/uv/)
the scripts below run in a throwaway environment without touching the system
Python:

```bash
uv run --with cryptography generate.py
```

Or with an explicit virtual environment:

```bash
uv venv
uv pip install cryptography
uv run generate.py
```

### Generate a key pair

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

### Derive the public token from an existing private token

```python
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

with open("client.key") as file:
    tok = next(
        line.strip()
        for line in file
        if line.strip() and not line.startswith("#")
    )

seed = base64.urlsafe_b64decode(tok.removeprefix("ed25519-sec:") + "=")
public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
print("ed25519-pub:" + base64.urlsafe_b64encode(public).decode().rstrip("="))
```

## Cross-checking

When the binary works again, confirm a fallback-generated key matches:

```bash
flexaccess-keys show-auth-key --private-key-file client.key
```

The printed `ed25519-pub:` token must equal the one computed above.
