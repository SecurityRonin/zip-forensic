//! Forensic ZIP anomaly auditor.
//!
//! Surfaces structural disagreements a happy-path reader would normalize away:
//! central-directory vs local-file-header field mismatches (a classic post-hoc
//! edit signal), path-traversal/absolute entry names, and data prepended before
//! the first member (polyglot / self-extractor stub). Each anomaly is an
//! OBSERVATION graded by severity ("consistent with", never a verdict) and
//! converts to a [`forensicnomicon::report::Finding`] via [`Observation`].
//!
//! Depends on `zip-core` for the parsed types and its `structural_view` seam;
//! the analyzer never re-implements the container parser.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::{Read, Seek};
use std::path::Path;

use forensicnomicon::report::{Category, Evidence, Observation, Severity};
use zip_core::{EntryLayout, ZipArchive, ZipCoreError};

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "zip-forensic";

/// Classification of a ZIP forensic anomaly, carrying the evidence to reproduce
/// it (the offending values + location, per CLAUDE.md "Show the unrecognized
/// value").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A field disagrees between the central directory and the local file header
    /// for the same entry — consistent with a post-hoc edit of one copy.
    CdLfhMismatch {
        /// Entry index (central-directory order).
        index: usize,
        /// Entry name (central-directory copy).
        name: String,
        /// Which field disagreed (`name`, `method`, `crc32`, ...).
        field: &'static str,
        /// Value recorded in the central directory.
        central: String,
        /// Value recorded in the local file header.
        local: String,
    },
    /// An entry name contains `..` traversal components — consistent with a
    /// Zip-Slip attempt to write outside the extraction root.
    NameTraversal {
        /// Entry index.
        index: usize,
        /// The offending raw name.
        name: String,
    },
    /// An entry name is absolute or carries a drive-letter prefix — consistent
    /// with an attempt to write to a fixed location.
    NameAbsolute {
        /// Entry index.
        index: usize,
        /// The offending raw name.
        name: String,
    },
    /// Bytes exist before the first local file header — consistent with a
    /// self-extractor stub or a polyglot (often benign; graded low).
    PrependedData {
        /// Number of bytes before the first local file header.
        length: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::CdLfhMismatch { .. } | AnomalyKind::NameTraversal { .. } => Severity::High,
            AnomalyKind::NameAbsolute { .. } => Severity::Medium,
            AnomalyKind::PrependedData { .. } => Severity::Low,
        }
    }

    /// Stable, scheme-prefixed machine code (published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::CdLfhMismatch { .. } => "ZIP-CD-LFH-MISMATCH",
            AnomalyKind::NameTraversal { .. } => "ZIP-NAME-TRAVERSAL",
            AnomalyKind::NameAbsolute { .. } => "ZIP-NAME-ABSOLUTE",
            AnomalyKind::PrependedData { .. } => "ZIP-PREPENDED-DATA",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::CdLfhMismatch { .. } => Category::Integrity,
            AnomalyKind::NameTraversal { .. } | AnomalyKind::NameAbsolute { .. } => {
                Category::Threat
            }
            AnomalyKind::PrependedData { .. } => Category::Structure,
        }
    }

    /// Human-readable, "consistent with" note including the offending values.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::CdLfhMismatch {
                index,
                name,
                field,
                central,
                local,
            } => format!(
                "entry {index} ({name}): central-directory {field} ({central}) disagrees with the \
                 local file header ({local}) — consistent with a post-hoc edit of one copy"
            ),
            AnomalyKind::NameTraversal { index, name } => format!(
                "entry {index}: name `{name}` contains `..` traversal — consistent with a Zip-Slip \
                 attempt to write outside the extraction root"
            ),
            AnomalyKind::NameAbsolute { index, name } => format!(
                "entry {index}: name `{name}` is absolute / drive-rooted — consistent with an \
                 attempt to write to a fixed location"
            ),
            AnomalyKind::PrependedData { length } => format!(
                "{length} byte(s) precede the first local file header — consistent with a \
                 self-extractor stub or polyglot (often benign)"
            ),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::CdLfhMismatch {
                field,
                central,
                local,
                ..
            } => vec![
                Evidence {
                    field: format!("central.{field}"),
                    value: central.clone(),
                    location: None,
                },
                Evidence {
                    field: format!("local.{field}"),
                    value: local.clone(),
                    location: None,
                },
            ],
            AnomalyKind::NameTraversal { name, .. } | AnomalyKind::NameAbsolute { name, .. } => {
                vec![Evidence {
                    field: "name".to_string(),
                    value: name.clone(),
                    location: None,
                }]
            }
            AnomalyKind::PrependedData { length } => vec![Evidence {
                field: "prepended_bytes".to_string(),
                value: length.to_string(),
                location: None,
            }],
        }
    }
}

/// A ZIP forensic anomaly: an observation graded by severity, with a stable code
/// and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

/// Audit an open seekable archive reader for structural anomalies.
pub fn audit_reader<R: Read + Seek>(reader: R) -> Result<Vec<Anomaly>, ZipCoreError> {
    let mut archive = ZipArchive::new(reader)?;
    let layout = archive.structural_view()?;
    Ok(audit_layout(&layout))
}

/// Audit a ZIP file on disk for structural anomalies.
pub fn audit_path(path: &Path) -> Result<Vec<Anomaly>, ZipCoreError> {
    audit_reader(std::fs::File::open(path)?)
}

/// The pure audit over a structural view — the testable heart of the analyzer.
#[must_use]
pub fn audit_layout(_layout: &[EntryLayout]) -> Vec<Anomaly> {
    // RED stub — implemented in the GREEN commit.
    Vec::new()
}

#[allow(dead_code)]
fn audit_layout_impl(layout: &[EntryLayout]) -> Vec<Anomaly> {
    let mut out = Vec::new();

    // Data prepended before the first member (smallest LFH offset > 0).
    if let Some(first) = layout.iter().map(|e| e.lfh_offset).min() {
        if first > 0 {
            out.push(Anomaly::new(AnomalyKind::PrependedData { length: first }));
        }
    }

    for e in layout {
        out.extend(audit_entry(e));
    }
    out
}

fn audit_entry(e: &EntryLayout) -> Vec<Anomaly> {
    let mut out = Vec::new();
    let name = &e.central.name;

    // Suspicious names (use the central-directory copy — the authoritative name).
    if has_traversal(name) {
        out.push(Anomaly::new(AnomalyKind::NameTraversal {
            index: e.index,
            name: name.clone(),
        }));
    }
    if is_absolute(name) {
        out.push(Anomaly::new(AnomalyKind::NameAbsolute {
            index: e.index,
            name: name.clone(),
        }));
    }

    // Central-directory vs local-file-header field disagreements.
    if e.central.name != e.local.name {
        out.push(mismatch(e, "name", &e.central.name, &e.local.name));
    }
    if e.central.method != e.local.method {
        out.push(mismatch(
            e,
            "method",
            &format!("{:?}", e.central.method),
            &format!("{:?}", e.local.method),
        ));
    }

    // CRC/sizes live in the data descriptor when GP flag bit 3 is set, so the LFH
    // copies are legitimately zero then; and a 0xFFFFFFFF LFH size is a zip64
    // sentinel, not a tamper. Compare only when the LFH copy is authoritative.
    let lfh_has_descriptor = e.local.flags & 0x0008 != 0;
    if !lfh_has_descriptor {
        if e.central.crc32 != e.local.crc32 {
            out.push(mismatch(
                e,
                "crc32",
                &format!("{:#010x}", e.central.crc32),
                &format!("{:#010x}", e.local.crc32),
            ));
        }
        compare_size(
            e,
            "compressed_size",
            e.central.compressed_size,
            e.local.compressed_size,
            &mut out,
        );
        compare_size(
            e,
            "uncompressed_size",
            e.central.uncompressed_size,
            e.local.uncompressed_size,
            &mut out,
        );
    }
    out
}

const U32_SENTINEL: u64 = 0xFFFF_FFFF;

fn compare_size(
    e: &EntryLayout,
    field: &'static str,
    central: u64,
    local: u64,
    out: &mut Vec<Anomaly>,
) {
    if local == U32_SENTINEL {
        return; // zip64 sentinel in the LFH — the real value lives in the extra field
    }
    if central != local {
        out.push(mismatch(e, field, &central.to_string(), &local.to_string()));
    }
}

fn mismatch(e: &EntryLayout, field: &'static str, central: &str, local: &str) -> Anomaly {
    Anomaly::new(AnomalyKind::CdLfhMismatch {
        index: e.index,
        name: e.central.name.clone(),
        field,
        central: central.to_string(),
        local: local.to_string(),
    })
}

/// `..` traversal component, treating both `/` and `\` as separators.
fn has_traversal(name: &str) -> bool {
    name.split(['/', '\\']).any(|c| c == "..")
}

/// Absolute (leading separator) or drive-letter (`C:`) name.
fn is_absolute(name: &str) -> bool {
    if name.starts_with('/') || name.starts_with('\\') {
        return true;
    }
    let b = name.as_bytes();
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}
