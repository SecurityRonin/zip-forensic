//! zip4n6 CLI logic. Humble Object: every decision lives in testable functions
//! here; `main.rs` is a thin, irreducible shell.
//!
//! Subcommands:
//! - `zip4n6 list <file>`  — enumerate entries (name, method, uncompressed size).
//! - `zip4n6 audit <file>` — run the forensic audit and print graded findings.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::Write;

use zip_core::ZipArchive;

const USAGE: &str = "usage: zip4n6 <list|audit> <file.zip>";

/// Errors surfaced by the CLI.
#[derive(Debug)]
pub enum CliError {
    /// Wrong/insufficient arguments; carries the usage text.
    Usage(String),
    /// An I/O error while writing output or opening the archive.
    Io(std::io::Error),
    /// The archive could not be parsed/read by zip-core.
    Zip(zip_core::ZipCoreError),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(u) => write!(f, "{u}"),
            CliError::Io(e) => write!(f, "I/O error: {e}"),
            CliError::Zip(e) => write!(f, "zip error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<zip_core::ZipCoreError> for CliError {
    fn from(e: zip_core::ZipCoreError) -> Self {
        CliError::Zip(e)
    }
}

/// Dispatch a parsed argv to a subcommand, writing output to `out`.
pub fn dispatch(args: &[String], out: &mut dyn Write) -> Result<(), CliError> {
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("list"), Some(path)) => list(path, out),
        (Some("audit"), Some(path)) => audit(path, out),
        _ => Err(CliError::Usage(USAGE.to_string())),
    }
}

/// `list`: enumerate entries with method and uncompressed size.
fn list(path: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let mut archive = ZipArchive::new(std::fs::File::open(path)?)?;
    for i in 0..archive.len() {
        let e = archive.by_index(i)?;
        writeln!(out, "{:>10}  {:?}  {}", e.size(), e.compression(), e.name())?;
    }
    Ok(())
}

/// `audit`: run the forensic audit and print each finding (or a clean message).
fn audit(path: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let findings = zip_forensic::audit_path(std::path::Path::new(path))?;
    if findings.is_empty() {
        writeln!(out, "no anomalies found")?;
        return Ok(());
    }
    for a in &findings {
        writeln!(out, "[{:?}] {}: {}", a.severity, a.code, a.note)?;
    }
    Ok(())
}
