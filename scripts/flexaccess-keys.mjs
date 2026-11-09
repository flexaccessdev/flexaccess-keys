#!/usr/bin/env node
// flexaccess-keys.mjs: generate and inspect FlexAccess Ed25519 authentication
// keys with Node.js 18 or newer. No packages to install.
//
// Usage:
//   node flexaccess-keys.mjs generate-auth-key [COMMENT] [-o FILE [--force]] [--json]
//   node flexaccess-keys.mjs show-auth-key --private-key-file FILE [-c COMMENT] [--json]
//
// Commands, flags, and output match the flexaccess-keys binary; see
// https://github.com/flexaccessdev/flexaccess-keys/blob/main/docs/key-format.md

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { parseArgs } from "node:util";

const PRIVATE_PREFIX = "ed25519-sec:";
const PUBLIC_PREFIX = "ed25519-pub:";
const PKCS8_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");
// 32 bytes encode to 43 characters; the last one carries two zero bits.
const KEY_B64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

const USAGE = `Manage shared FlexAccess Ed25519 authentication keys (requires Node.js 18+)

Usage:
  flexaccess-keys.mjs generate-auth-key [COMMENT] [-o FILE [--force]] [--json]
  flexaccess-keys.mjs show-auth-key --private-key-file FILE [-c COMMENT] [--json]

generate-auth-key options:
  [COMMENT]            Comment appended to the authorized-key entry
  -o, --output FILE    Path where the private key file is saved ("-" means stdout)
      --force          Overwrite an existing output file
      --json           Print the authorized-key entry and private key as JSON

show-auth-key options:
      --private-key-file FILE  Path to the Ed25519 authentication private key file
  -c, --comment COMMENT        Replace the comment stored in the key file header
      --json                   Print the authorized-key entry as JSON
`;

class CliError extends Error {}

function expandTilde(path) {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

function validateComment(comment) {
  if (/[\r\n]/.test(comment)) {
    throw new CliError("Authorized-key comment must not contain line breaks");
  }
  return comment.trim();
}

function authorizedKey(publicB64, comment) {
  return comment ? `${PUBLIC_PREFIX}${publicB64} ${comment}` : `${PUBLIC_PREFIX}${publicB64}`;
}

function derivePublic(seedB64) {
  const der = Buffer.concat([PKCS8_HEADER, Buffer.from(seedB64, "base64url")]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return createPublicKey(privateKey).export({ format: "jwk" }).x;
}

function rfc3339Utc(date) {
  return date.toISOString().replace(/\.\d+Z$/, "Z");
}

function writeAndSync(path, content, mode) {
  const fd = openSync(path, "wx", mode);
  try {
    writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

// Created with mode 0600, never overwritten unless forced; forced overwrites
// replace the target atomically via a temporary file.
function writePrivateKeyFile(path, content, force) {
  const fail = (error) =>
    new CliError(`Failed to write private key file ${path}: ${error.message}`);
  try {
    mkdirSync(dirname(path), { recursive: true });
  } catch (error) {
    throw fail(error);
  }
  if (!force) {
    try {
      writeAndSync(path, content, 0o600);
    } catch (error) {
      if (error.code === "EEXIST") {
        throw new CliError(`File already exists: ${path}. Use --force to overwrite.`);
      }
      throw fail(error);
    }
    return;
  }
  const temp = join(
    dirname(path),
    `.${basename(path)}.${randomBytes(8).toString("base64url")}.tmp`,
  );
  try {
    writeAndSync(temp, content, 0o600);
    renameSync(temp, path);
  } catch (error) {
    try {
      unlinkSync(temp);
    } catch {}
    throw fail(error);
  }
}

function parse(args, options) {
  try {
    return parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (error) {
    throw new CliError(error.message);
  }
}

function generateAuthKey(args) {
  const { values, positionals } = parse(args, {
    output: { type: "string", short: "o" },
    force: { type: "boolean" },
    json: { type: "boolean" },
    help: { type: "boolean", short: "h" },
  });
  if (values.help) return void process.stdout.write(USAGE);
  if (positionals.length > 1) throw new CliError(`unexpected argument '${positionals[1]}'`);
  if (values.force && values.output === undefined) throw new CliError("--force requires --output");
  if (values.json && values.output !== undefined) {
    throw new CliError("--json cannot be used with --output");
  }

  const comment = validateComment(positionals[0] ?? "");
  const { privateKey } = generateKeyPairSync("ed25519");
  const { d: seed, x: publicB64 } = privateKey.export({ format: "jwk" });
  const entry = authorizedKey(publicB64, comment);

  if (values.json) {
    console.log(JSON.stringify({ authorized_key: entry, private_key: PRIVATE_PREFIX + seed }));
    return;
  }

  const keyFile =
    "# Ed25519 authentication key\n" +
    `# Created: ${rfc3339Utc(new Date())}\n` +
    `# Public key: ${entry}\n` +
    `${PRIVATE_PREFIX}${seed}\n`;
  if (values.output === undefined || values.output === "-") {
    process.stdout.write(keyFile);
  } else {
    writePrivateKeyFile(expandTilde(values.output), keyFile, Boolean(values.force));
  }
}

function showAuthKey(args) {
  const { values, positionals } = parse(args, {
    "private-key-file": { type: "string" },
    comment: { type: "string", short: "c" },
    json: { type: "boolean" },
    help: { type: "boolean", short: "h" },
  });
  if (values.help) return void process.stdout.write(USAGE);
  if (positionals.length > 0) throw new CliError(`unexpected argument '${positionals[0]}'`);
  if (values["private-key-file"] === undefined) {
    throw new CliError(
      "the following required arguments were not provided: --private-key-file <FILE>",
    );
  }

  const path = expandTilde(values["private-key-file"]);
  let content;
  try {
    content = readFileSync(path, "utf8");
  } catch (error) {
    throw new CliError(`Failed to read private key file ${path}: ${error.message}`);
  }
  const lines = content.split("\n").map((line) => line.trim());

  const keyLines = lines.filter((line) => line && !line.startsWith("#"));
  if (keyLines.length === 0) throw new CliError(`No authentication private key found in ${path}`);
  if (keyLines.length > 1) {
    throw new CliError(`Invalid authentication private key in ${path}: multiple key lines`);
  }
  if (!keyLines[0].startsWith(PRIVATE_PREFIX)) {
    throw new CliError(
      `Invalid authentication private key in ${path}: Private key must start with '${PRIVATE_PREFIX}'`,
    );
  }
  const seed = keyLines[0].slice(PRIVATE_PREFIX.length);
  if (!KEY_B64URL.test(seed)) {
    throw new CliError(
      `Invalid authentication private key in ${path}: ` +
        "Ed25519 private key must be 43 base64url characters encoding 32 bytes",
    );
  }
  const publicB64 = derivePublic(seed);

  let comment = "";
  if (values.comment !== undefined) {
    comment = validateComment(values.comment);
  } else {
    // A `# Public key:` header naming this key contributes its comment; a
    // stale header for a different key is ignored.
    const token = PUBLIC_PREFIX + publicB64;
    for (const line of lines) {
      if (!line.startsWith("# Public key:")) continue;
      const rest = line.slice("# Public key:".length).trimStart();
      if (rest.startsWith(token) && /^\s/.test(rest.slice(token.length))) {
        comment = rest.slice(token.length).trim();
        break;
      }
    }
  }

  const entry = authorizedKey(publicB64, comment);
  console.log(values.json ? JSON.stringify({ authorized_key: entry }) : entry);
}

function main(argv) {
  const [command, ...args] = argv;
  switch (command) {
    case "generate-auth-key":
      return generateAuthKey(args);
    case "show-auth-key":
      return showAuthKey(args);
    case "-h":
    case "--help":
    case "help":
      return void process.stdout.write(USAGE);
    case undefined:
      process.stderr.write(USAGE);
      process.exit(2);
    default:
      process.stderr.write(USAGE);
      throw new CliError(`unrecognized subcommand '${command}'`);
  }
}

try {
  main(process.argv.slice(2));
} catch (error) {
  if (!(error instanceof CliError)) throw error;
  console.error(`Error: ${error.message}`);
  process.exit(1);
}
