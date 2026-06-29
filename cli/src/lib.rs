//! zip4n6 CLI logic. Humble Object: every decision lives in testable functions
//! here; `main.rs` is a thin, irreducible shell.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::Write;

/// Errors surfaced by the CLI.
#[derive(Debug)]
pub enum CliError {
    /// Wrong/insufficient arguments; carries the usage text.
    Usage(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(u) => write!(f, "{u}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Dispatch a parsed argv to a subcommand, writing output to `out`.
pub fn dispatch(_args: &[String], _out: &mut dyn Write) -> Result<(), CliError> {
    // RED stub — implemented in the GREEN commit.
    Err(CliError::Usage("unimplemented".to_string()))
}
