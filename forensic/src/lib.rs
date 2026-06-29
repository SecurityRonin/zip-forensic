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
use zip_core::{ArchiveSummary, EntryLayout, ZipArchive, ZipCoreError};

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
    /// Bytes exist after the End Of Central Directory record — consistent with
    /// appended/hidden data (often benign; graded low).
    TrailingData {
        /// Number of bytes after the EOCD record.
        length: u64,
    },
    /// Two members' data ranges overlap — structurally impossible for a normal
    /// archive; consistent with a crafted/concealment layout.
    Overlap {
        /// First entry index.
        index_a: usize,
        /// Second entry index.
        index_b: usize,
        /// Byte where the overlap begins.
        at: u64,
    },
    /// Non-zero disk numbers in a single-file archive — consistent with spanning
    /// markers where none are expected.
    SpanningAnomaly {
        /// EOCD disk number.
        disk_number: u32,
        /// Disk on which the central directory starts.
        cd_start_disk: u32,
    },
    /// An entry name contains an RTL/bidi override codepoint — consistent with a
    /// filename-spoofing attack (e.g. `...\u{202e}gpj.exe`).
    NameBidi {
        /// Entry index.
        index: usize,
        /// The offending raw name.
        name: String,
    },
    /// An entry name contains control characters or NUL — consistent with display
    /// spoofing or path-handling exploits.
    NameControl {
        /// Entry index.
        index: usize,
        /// The offending raw name.
        name: String,
    },
    /// The decoded entry's CRC-32 disagrees with the recorded value — consistent
    /// with corruption or tampering of the entry data.
    CrcMismatch {
        /// Entry index.
        index: usize,
        /// Entry name.
        name: String,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::CdLfhMismatch { .. }
            | AnomalyKind::NameTraversal { .. }
            | AnomalyKind::NameBidi { .. }
            | AnomalyKind::CrcMismatch { .. } => Severity::High,
            AnomalyKind::NameAbsolute { .. }
            | AnomalyKind::Overlap { .. }
            | AnomalyKind::SpanningAnomaly { .. }
            | AnomalyKind::NameControl { .. } => Severity::Medium,
            AnomalyKind::PrependedData { .. } | AnomalyKind::TrailingData { .. } => Severity::Low,
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
            AnomalyKind::TrailingData { .. } => "ZIP-TRAILING-DATA",
            AnomalyKind::Overlap { .. } => "ZIP-OVERLAP",
            AnomalyKind::SpanningAnomaly { .. } => "ZIP-SPANNING-ANOMALY",
            AnomalyKind::NameBidi { .. } => "ZIP-NAME-BIDI",
            AnomalyKind::NameControl { .. } => "ZIP-NAME-CONTROL",
            AnomalyKind::CrcMismatch { .. } => "ZIP-CRC-MISMATCH",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::CdLfhMismatch { .. } | AnomalyKind::CrcMismatch { .. } => {
                Category::Integrity
            }
            AnomalyKind::NameTraversal { .. } | AnomalyKind::NameAbsolute { .. } => {
                Category::Threat
            }
            AnomalyKind::NameBidi { .. } | AnomalyKind::NameControl { .. } => Category::Concealment,
            AnomalyKind::PrependedData { .. }
            | AnomalyKind::TrailingData { .. }
            | AnomalyKind::Overlap { .. }
            | AnomalyKind::SpanningAnomaly { .. } => Category::Structure,
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
            AnomalyKind::TrailingData { length } => format!(
                "{length} byte(s) follow the End Of Central Directory record — consistent with \
                 appended or hidden data (often benign)"
            ),
            AnomalyKind::Overlap {
                index_a,
                index_b,
                at,
            } => format!(
                "entries {index_a} and {index_b} have overlapping data ranges at offset {at} — \
                 structurally impossible for a normal archive"
            ),
            AnomalyKind::SpanningAnomaly {
                disk_number,
                cd_start_disk,
            } => format!(
                "non-zero disk numbers (disk {disk_number}, cd-start disk {cd_start_disk}) in a \
                 single-file archive — consistent with unexpected spanning markers"
            ),
            AnomalyKind::NameBidi { index, name } => format!(
                "entry {index}: name `{name}` contains an RTL/bidi override codepoint — consistent \
                 with filename-extension spoofing"
            ),
            AnomalyKind::NameControl { index, name } => format!(
                "entry {index}: name `{name:?}` contains control characters or NUL — consistent \
                 with display spoofing or path-handling exploits"
            ),
            AnomalyKind::CrcMismatch { index, name } => format!(
                "entry {index} ({name}): decoded data CRC-32 disagrees with the recorded value — \
                 consistent with corruption or tampering of the entry data"
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
            AnomalyKind::NameTraversal { name, .. }
            | AnomalyKind::NameAbsolute { name, .. }
            | AnomalyKind::NameBidi { name, .. }
            | AnomalyKind::NameControl { name, .. } => vec![Evidence {
                field: "name".to_string(),
                value: format!("{name:?}"),
                location: None,
            }],
            AnomalyKind::PrependedData { length } => vec![Evidence {
                field: "prepended_bytes".to_string(),
                value: length.to_string(),
                location: None,
            }],
            AnomalyKind::TrailingData { length } => vec![Evidence {
                field: "trailing_bytes".to_string(),
                value: length.to_string(),
                location: None,
            }],
            AnomalyKind::Overlap { at, .. } => vec![Evidence {
                field: "overlap_offset".to_string(),
                value: at.to_string(),
                location: None,
            }],
            AnomalyKind::SpanningAnomaly {
                disk_number,
                cd_start_disk,
            } => vec![Evidence {
                field: "disk_numbers".to_string(),
                value: format!("disk={disk_number}, cd_start_disk={cd_start_disk}"),
                location: None,
            }],
            AnomalyKind::CrcMismatch { name, .. } => vec![Evidence {
                field: "entry".to_string(),
                value: name.clone(),
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
    let summary = archive.summary().clone();

    let mut out = audit_layout(&layout);
    out.extend(audit_container(&summary, &layout));

    // CRC-32 verification: decode each entry; a CrcMismatch (and only that) is an
    // integrity finding. Other decode errors are not asserted here — they surface
    // through the reader API where the caller drives extraction.
    for (i, entry_layout) in layout.iter().enumerate() {
        if let Ok(mut entry) = archive.by_index(i) {
            let mut sink = std::io::sink();
            if let Err(e) = std::io::copy(&mut entry, &mut sink) {
                if matches!(
                    e.get_ref()
                        .and_then(|inner| inner.downcast_ref::<ZipCoreError>()),
                    Some(ZipCoreError::CrcMismatch { .. })
                ) {
                    out.push(Anomaly::new(AnomalyKind::CrcMismatch {
                        index: i,
                        name: entry_layout.central.name.clone(),
                    }));
                }
            }
        }
    }
    Ok(out)
}

/// Container-level audits from the archive summary: trailing data after the EOCD
/// and unexpected spanning disk numbers.
#[must_use]
pub fn audit_container(summary: &ArchiveSummary, _layout: &[EntryLayout]) -> Vec<Anomaly> {
    let mut out = Vec::new();
    if summary.file_len > summary.eocd_end_offset {
        out.push(Anomaly::new(AnomalyKind::TrailingData {
            length: summary.file_len - summary.eocd_end_offset,
        }));
    }
    // 0xFFFFFFFF is the zip64 disk sentinel, not a real spanning marker.
    let span = |d: u32| d != 0 && d != 0xFFFF_FFFF;
    if span(summary.disk_number) || span(summary.cd_start_disk) {
        out.push(Anomaly::new(AnomalyKind::SpanningAnomaly {
            disk_number: summary.disk_number,
            cd_start_disk: summary.cd_start_disk,
        }));
    }
    out
}

/// Audit a ZIP file on disk for structural anomalies.
pub fn audit_path(path: &Path) -> Result<Vec<Anomaly>, ZipCoreError> {
    audit_reader(std::fs::File::open(path)?)
}

/// The pure audit over a structural view — the testable heart of the analyzer.
#[must_use]
pub fn audit_layout(layout: &[EntryLayout]) -> Vec<Anomaly> {
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
    out.extend(audit_overlaps(layout));
    out
}

/// Detect members whose `[data_start, data_start + compressed_size)` ranges
/// overlap — structurally impossible in a normal archive.
fn audit_overlaps(layout: &[EntryLayout]) -> Vec<Anomaly> {
    let mut spans: Vec<(usize, u64, u64)> = layout
        .iter()
        .map(|e| {
            let end = e.data_start.saturating_add(e.central.compressed_size);
            (e.index, e.data_start, end)
        })
        .collect();
    spans.sort_by_key(|&(_, start, _)| start);

    let mut out = Vec::new();
    for pair in spans.windows(2) {
        let (a_idx, _a_start, a_end) = pair[0];
        let (b_idx, b_start, _b_end) = pair[1];
        if b_start < a_end {
            out.push(Anomaly::new(AnomalyKind::Overlap {
                index_a: a_idx,
                index_b: b_idx,
                at: b_start,
            }));
        }
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
    if has_bidi_override(name) {
        out.push(Anomaly::new(AnomalyKind::NameBidi {
            index: e.index,
            name: name.clone(),
        }));
    }
    if has_control_chars(name) {
        out.push(Anomaly::new(AnomalyKind::NameControl {
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

/// Unicode bidirectional control codepoints used to disguise file extensions
/// (RLO/LRO/RLE/LRE/PDF and the isolate family).
fn has_bidi_override(name: &str) -> bool {
    name.chars().any(|c| {
        matches!(c,
            '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
            | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
            | '\u{200E}' | '\u{200F}') // LRM, RLM
    })
}

/// Control characters (C0/C1) or NUL embedded in a name.
fn has_control_chars(name: &str) -> bool {
    name.chars().any(char::is_control)
}
