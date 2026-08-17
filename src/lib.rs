//! Shared Ed25519 authentication keys for FlexAccess applications.
//!
//! This crate owns the app-independent `ed25519-sec:` / `ed25519-pub:` key
//! format, key-file rendering, authorized-key parsing, and raw signing and
//! verification. Applications remain responsible for their own
//! domain-separated authentication transcripts and wire protocols.

use std::collections::HashMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const PRIVATE_KEY_PREFIX: &str = "ed25519-sec:";
pub const PUBLIC_KEY_PREFIX: &str = "ed25519-pub:";
pub const KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

pub type KeyBytes = [u8; KEY_LENGTH];
pub type SignatureBytes = [u8; SIGNATURE_LENGTH];

#[derive(Debug)]
pub enum Error {
    Invalid(String),

    ReadFile {
        kind: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },

    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    FileExists(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::ReadFile { kind, path, source } => {
                write!(formatter, "Failed to read {kind} file {}: {source}", path.display())
            }
            Self::WriteFile { path, source } => write!(
                formatter,
                "Failed to write private key file {}: {source}",
                path.display()
            ),
            Self::FileExists(path) => write!(
                formatter,
                "File already exists: {}. Use --force to overwrite.",
                path.display()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } | Self::WriteFile { source, .. } => Some(source),
            Self::Invalid(_) | Self::FileExists(_) => None,
        }
    }
}

/// A validated Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(KeyBytes);

impl PublicKey {
    pub fn from_bytes(bytes: KeyBytes) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes)
            .map_err(|error| Error::Invalid(format!("Invalid Ed25519 public key: {error}")))?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &KeyBytes {
        &self.0
    }

    pub fn to_bytes(self) -> KeyBytes {
        self.0
    }

    pub fn to_token(self) -> String {
        format!("{PUBLIC_KEY_PREFIX}{}", BASE64.encode(self.0))
    }

    /// Strictly verify an Ed25519 signature over an application-defined
    /// domain-separated message.
    pub fn verify(self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature): std::result::Result<SignatureBytes, _> = signature.try_into() else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        verifying_key
            .verify_strict(message, &Signature::from_bytes(&signature))
            .is_ok()
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(token: &str) -> Result<Self> {
        let encoded = token.strip_prefix(PUBLIC_KEY_PREFIX).ok_or_else(|| {
            Error::Invalid(format!(
                "Public key must start with '{PUBLIC_KEY_PREFIX}'"
            ))
        })?;
        let bytes = BASE64
            .decode(encoded)
            .map_err(|error| Error::Invalid(format!("Public key is not valid base64url: {error}")))?;
        let bytes: KeyBytes = bytes.try_into().map_err(|bytes: Vec<u8>| {
            Error::Invalid(format!(
                "Ed25519 public key must decode to {KEY_LENGTH} bytes, got {}",
                bytes.len()
            ))
        })?;
        Self::from_bytes(bytes)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_token())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.to_token()).finish()
    }
}

/// An Ed25519 private signing key.
#[derive(Clone)]
pub struct PrivateKey(SigningKey);

impl PrivateKey {
    pub fn generate() -> Result<Self> {
        let mut seed = [0; KEY_LENGTH];
        getrandom::fill(&mut seed).map_err(|error| {
            Error::Invalid(format!("Failed to generate an Ed25519 private key: {error}"))
        })?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: KeyBytes) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn seed(&self) -> KeyBytes {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn to_token(&self) -> String {
        format!("{PRIVATE_KEY_PREFIX}{}", BASE64.encode(self.seed()))
    }

    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        self.0.sign(message).to_bytes()
    }

    pub fn authorized_key(&self, comment: &str) -> Result<AuthorizedKey> {
        AuthorizedKey::new(self.public_key(), comment)
    }

    /// Render the canonical key file with its public authorized-key entry.
    pub fn to_key_file(&self, comment: &str, created: SystemTime) -> Result<String> {
        let authorized_key = self.authorized_key(comment)?;
        Ok(format!(
            "# Ed25519 authentication key\n\
             # Created: {}\n\
             # Public key: {}\n\
             {}\n",
            rfc3339_utc(created),
            authorized_key,
            self.to_token()
        ))
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(token: &str) -> Result<Self> {
        let encoded = token.strip_prefix(PRIVATE_KEY_PREFIX).ok_or_else(|| {
            Error::Invalid(format!(
                "Private key must start with '{PRIVATE_KEY_PREFIX}'"
            ))
        })?;
        let bytes = BASE64.decode(encoded).map_err(|error| {
            Error::Invalid(format!("Private key is not valid base64url: {error}"))
        })?;
        let seed: KeyBytes = bytes.try_into().map_err(|bytes: Vec<u8>| {
            Error::Invalid(format!(
                "Ed25519 private key must decode to {KEY_LENGTH} bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self::from_seed(seed))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}

/// A public key plus its optional authorized-keys comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKey {
    public_key: PublicKey,
    comment: String,
}

impl AuthorizedKey {
    pub fn new(public_key: PublicKey, comment: &str) -> Result<Self> {
        let comment = validate_comment(comment)?;
        Ok(Self {
            public_key,
            comment: comment.to_string(),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }
}

impl fmt::Display for AuthorizedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.public_key)?;
        if !self.comment.is_empty() {
            write!(f, " {}", self.comment)?;
        }
        Ok(())
    }
}

/// Ed25519 public keys accepted by an application, indexed by raw key bytes.
#[derive(Clone, Default)]
pub struct AuthorizedKeys {
    keys: HashMap<PublicKey, String>,
}

impl AuthorizedKeys {
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn comment(&self, public_key: &PublicKey) -> Option<&str> {
        self.keys.get(public_key).map(String::as_str)
    }

    pub fn contains(&self, public_key: &PublicKey) -> bool {
        self.keys.contains_key(public_key)
    }

    pub fn iter(&self) -> impl Iterator<Item = AuthorizedKey> + '_ {
        self.keys.iter().map(|(public_key, comment)| AuthorizedKey {
            public_key: *public_key,
            comment: comment.clone(),
        })
    }
}

impl fmt::Debug for AuthorizedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedKeys")
            .field("key_count", &self.keys.len())
            .finish()
    }
}

/// Parse a bare private-key token or a complete generated key file.
pub fn parse_private_key(content: &str, origin: &str) -> Result<PrivateKey> {
    let mut private_key_line = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if private_key_line.is_some() {
            return Err(Error::Invalid(format!(
                "Invalid authentication private key in {origin}: multiple key lines"
            )));
        }
        private_key_line = Some(line);
    }
    let private_key_line = private_key_line.ok_or_else(|| {
        Error::Invalid(format!(
            "No authentication private key found in {origin}"
        ))
    })?;
    PrivateKey::from_str(private_key_line).map_err(|error| {
        Error::Invalid(format!(
            "Invalid authentication private key in {origin}: {error}"
        ))
    })
}

pub fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        kind: "private key",
        path: path.to_path_buf(),
        source,
    })?;
    parse_private_key(&content, &path.display().to_string())
}

/// Parse an authorized-keys document. Blank lines and lines whose first
/// non-whitespace character is `#` are ignored. The first whitespace-delimited
/// field is the public-key token; the rest is its optional comment.
pub fn parse_authorized_keys(content: &str, origin: &str) -> Result<AuthorizedKeys> {
    let mut keys = HashMap::new();
    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token_end = line.find(char::is_whitespace).unwrap_or(line.len());
        let (token, comment) = line.split_at(token_end);
        let comment = comment.trim();
        let public_key = PublicKey::from_str(token).map_err(|error| {
            Error::Invalid(format!(
                "Invalid authorized key at {origin}:{line_number}: {error}"
            ))
        })?;
        let authorized_key = AuthorizedKey::new(public_key, comment).map_err(|error| {
            Error::Invalid(format!(
                "Invalid authorized key at {origin}:{line_number}: {error}"
            ))
        })?;
        keys.insert(authorized_key.public_key, authorized_key.comment);
    }
    Ok(AuthorizedKeys { keys })
}

pub fn parse_authorized_key_entries(entries: &[String], origin: &str) -> Result<AuthorizedKeys> {
    parse_authorized_keys(&entries.join("\n"), origin)
}

pub fn load_authorized_keys(path: &Path) -> Result<AuthorizedKeys> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        kind: "authorized keys",
        path: path.to_path_buf(),
        source,
    })?;
    parse_authorized_keys(&content, &path.display().to_string())
}

/// Derive an authorized-key entry from a generated key file. A supplied
/// comment overrides the header comment. Without one, a matching
/// `# Public key:` header contributes its comment; a stale header is ignored.
pub fn authorized_key_from_private_file(
    content: &str,
    origin: &str,
    comment: Option<&str>,
) -> Result<AuthorizedKey> {
    let private_key = parse_private_key(content, origin)?;
    let public_key = private_key.public_key();
    let comment = match comment {
        Some(comment) => validate_comment(comment)?.to_string(),
        None => header_comment(content, public_key).unwrap_or_default(),
    };
    AuthorizedKey::new(public_key, &comment)
}

fn header_comment(content: &str, public_key: PublicKey) -> Option<String> {
    let public_key = public_key.to_token();
    content.lines().find_map(|line| {
        let header = line.trim().strip_prefix("# Public key:")?.trim_start();
        let comment = header.strip_prefix(&public_key)?;
        let comment = comment.strip_prefix(char::is_whitespace)?.trim();
        Some(comment.to_string())
    })
}

fn validate_comment(comment: &str) -> Result<&str> {
    let comment = comment.trim();
    if comment.contains(['\n', '\r']) {
        return Err(Error::Invalid(
            "Authorized-key comment must not contain line breaks".to_string(),
        ));
    }
    Ok(comment)
}

/// Write a private key file without overwriting by default. On Unix the file
/// is created and retained with mode `0600`, including forced overwrites.
pub fn write_private_key_file(path: &Path, content: &str, force: bool) -> Result<()> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|source| Error::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    }

    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|source| {
        if !force && source.kind() == std::io::ErrorKind::AlreadyExists {
            Error::FileExists(path.to_path_buf())
        } else {
            Error::WriteFile {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| Error::WriteFile {
                path: path.to_path_buf(),
                source,
            })?;
    }

    file.write_all(content.as_bytes())
        .map_err(|source| Error::WriteFile {
            path: path.to_path_buf(),
            source,
        })
}

/// Shared implementation for application and standalone `generate-auth-key`
/// commands.
#[cfg(feature = "commands")]
pub fn generate_auth_key_command(
    output: Option<&Path>,
    force: bool,
    comment: &str,
    json: bool,
) -> Result<()> {
    let private_key = PrivateKey::generate()?;
    if json {
        let authorized_key = private_key.authorized_key(comment)?.to_string();
        println!(
            "{}",
            serde_json::json!({
                "authorized_key": authorized_key,
                "private_key": private_key.to_token(),
            })
        );
        return Ok(());
    }

    let key_file = private_key.to_key_file(comment, SystemTime::now())?;
    if let Some(path) = output.filter(|path| path.as_os_str() != "-") {
        write_private_key_file(path, &key_file, force)?;
    } else {
        print!("{key_file}");
    }
    Ok(())
}

/// Shared implementation for application and standalone `show-auth-key`
/// commands.
#[cfg(feature = "commands")]
pub fn show_auth_key_command(path: &Path, comment: Option<&str>, json: bool) -> Result<()> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        kind: "private key",
        path: path.to_path_buf(),
        source,
    })?;
    let authorized_key =
        authorized_key_from_private_file(&content, &path.display().to_string(), comment)?
            .to_string();
    if json {
        println!(
            "{}",
            serde_json::json!({ "authorized_key": authorized_key })
        );
    } else {
        println!("{authorized_key}");
    }
    Ok(())
}

/// Format a timestamp as an RFC 3339 UTC instant without pulling a time crate
/// into every consumer.
pub fn rfc3339_utc(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_secs())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let seconds_of_day = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    let year = year_of_era as i64 + era * 400;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_public_tokens_round_trip() {
        let private_key = PrivateKey::from_seed([42; KEY_LENGTH]);
        let private_token = private_key.to_token();
        let public_token = private_key.public_key().to_token();

        assert_eq!(PrivateKey::from_str(&private_token).unwrap().to_token(), private_token);
        assert_eq!(PublicKey::from_str(&public_token).unwrap().to_token(), public_token);
    }

    #[test]
    fn signatures_are_strict_and_app_defined() {
        let private_key = PrivateKey::from_seed([42; KEY_LENGTH]);
        let signature = private_key.sign(b"app-domain\0message");

        assert!(private_key.public_key().verify(b"app-domain\0message", &signature));
        assert!(!private_key.public_key().verify(b"other-domain\0message", &signature));
        assert!(!private_key.public_key().verify(b"app-domain\0message", &signature[..63]));
    }

    #[test]
    fn key_file_and_authorized_keys_round_trip() {
        let private_key = PrivateKey::from_seed([42; KEY_LENGTH]);
        let file = private_key
            .to_key_file("alice laptop", UNIX_EPOCH)
            .unwrap();
        let parsed = parse_private_key(&file, "fixture").unwrap();
        let entry = authorized_key_from_private_file(&file, "fixture", None).unwrap();
        let authorized = parse_authorized_keys(&entry.to_string(), "fixture").unwrap();

        assert_eq!(parsed.to_token(), private_key.to_token());
        assert_eq!(entry.comment(), "alice laptop");
        assert_eq!(authorized.comment(&private_key.public_key()), Some("alice laptop"));
    }

    #[test]
    fn authorized_keys_accept_whitespace_and_comments() {
        let a = PrivateKey::from_seed([1; KEY_LENGTH]);
        let b = PrivateKey::from_seed([2; KEY_LENGTH]);
        let content = format!(
            "  # clients\n\n{}\n\t{}   bob workstation  \n",
            a.public_key(),
            b.public_key()
        );
        let authorized = parse_authorized_keys(&content, "fixture").unwrap();

        assert_eq!(authorized.len(), 2);
        assert_eq!(authorized.comment(&a.public_key()), Some(""));
        assert_eq!(authorized.comment(&b.public_key()), Some("bob workstation"));
    }

    #[test]
    fn rejects_invalid_material_and_multiline_comments() {
        assert!(PrivateKey::from_str("ed25519-sec:!!!").is_err());
        assert!(PublicKey::from_str("ed25519-pub:AA").is_err());
        assert!(
            PrivateKey::generate()
                .unwrap()
                .authorized_key("alice\nbob")
                .is_err()
        );
        assert!(parse_private_key("ed25519-sec:AA\ned25519-sec:AA", "fixture").is_err());
    }

    #[test]
    fn stale_public_header_does_not_supply_a_comment() {
        let private_key = PrivateKey::from_seed([42; KEY_LENGTH]);
        let other = PrivateKey::from_seed([43; KEY_LENGTH]);
        let content = format!(
            "# Public key: {} wrong comment\n{}\n",
            other.public_key(),
            private_key.to_token()
        );
        let entry = authorized_key_from_private_file(&content, "fixture", None).unwrap();

        assert_eq!(entry.public_key(), private_key.public_key());
        assert_eq!(entry.comment(), "");
    }

    #[test]
    fn writes_without_overwriting() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested/client.key");
        write_private_key_file(&path, "first", false).unwrap();
        assert!(matches!(
            write_private_key_file(&path, "second", false),
            Err(Error::FileExists(_))
        ));
        write_private_key_file(&path, "second", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(feature = "commands")]
    #[test]
    fn command_writes_a_parseable_private_key_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.key");
        generate_auth_key_command(Some(&path), false, "alice", false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let private_key = parse_private_key(&content, "fixture").unwrap();
        assert_eq!(
            authorized_key_from_private_file(&content, "fixture", None).unwrap(),
            private_key.authorized_key("alice").unwrap()
        );
    }

    #[test]
    fn formats_the_unix_epoch() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }
}
