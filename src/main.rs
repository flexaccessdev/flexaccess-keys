use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "flexaccess-keys")]
#[command(version)]
#[command(about = "Manage shared FlexAccess Ed25519 authentication keys")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 authentication private key
    GenerateAuthKey {
        /// Comment appended to the authorized-key entry
        comment: Option<String>,

        /// Path where the private key file is saved ("-" means stdout)
        #[arg(short, long, conflicts_with = "json")]
        output: Option<PathBuf>,

        /// Overwrite an existing output file
        #[arg(long, requires = "output")]
        force: bool,

        /// Print the authorized-key entry and private key as JSON
        #[arg(long)]
        json: bool,
    },

    /// Derive an authorized-key entry from a private key file
    ShowAuthKey {
        /// Path to the Ed25519 authentication private key file
        #[arg(long)]
        private_key_file: PathBuf,

        /// Replace the comment stored in the key file header
        #[arg(short, long)]
        comment: Option<String>,

        /// Print the authorized-key entry as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Expand a leading `~` so quoted paths like `"~/keys/client.key"` work even
/// though the shell never saw the tilde.
fn expand_tilde(path: PathBuf) -> PathBuf {
    let home = || {
        let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        std::env::var_os(variable).map(PathBuf::from)
    };
    match path.to_str() {
        Some("~") => home().unwrap_or(path),
        Some(text) => match text.strip_prefix("~/").and_then(|rest| Some(home()?.join(rest))) {
            Some(expanded) => expanded,
            None => path,
        },
        None => path,
    }
}

fn main() -> flexaccess_keys::Result<()> {
    match Args::parse().command {
        Command::GenerateAuthKey {
            comment,
            output,
            force,
            json,
        } => flexaccess_keys::generate_auth_key_command(
            output.map(expand_tilde).as_deref(),
            force,
            comment.as_deref().unwrap_or_default(),
            json,
        ),
        Command::ShowAuthKey {
            private_key_file,
            comment,
            json,
        } => flexaccess_keys::show_auth_key_command(
            &expand_tilde(private_key_file),
            comment.as_deref(),
            json,
        ),
    }
}
