//! Pure-Rust ZIP container parser: EOCD + central directory + local file headers,
//! with a decoding entry reader that verifies CRC-32 on EOF.
//!
//! Mirrors the zip-rs surface (`ZipArchive::new` / `by_index` / `by_name` /
//! `ZipFile` with `name()`/`compression()`/`size()`/`data_start()`) so fleet
//! consumers migrate with a near-mechanical `zip::` -> `zip_core::` rename.

use std::io::{self, Read, Seek, SeekFrom};

use crate::bytes::Reader;
use crate::codec::Decoder;
use crate::{FormatError, ZipCoreError};

const EOCD_SIG: u32 = 0x0605_4b50;
const CD_HEADER_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;

/// Minimum EOCD record length (no comment).
const EOCD_MIN: usize = 22;
/// Largest region we scan back from EOF for the EOCD (record + max comment).
const EOCD_SCAN_MAX: usize = EOCD_MIN + u16::MAX as usize;
/// Fixed portion of a local file header.
const LFH_FIXED: usize = 30;
/// Ceiling on entries we will parse, guarding against a lying EOCD count.
const MAX_ENTRIES: usize = 16_000_000;

/// ZIP compression method, mirroring zip-rs `CompressionMethod` for the common
/// methods plus an `Unknown(raw)` that preserves the offending value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// Method 0 — no compression (raw passthrough / in-place window).
    Stored,
    /// Method 8 — classic DEFLATE.
    Deflated,
    /// Method 9 — Deflate64 / "enhanced deflate".
    Deflate64,
    /// Method 12 — bzip2.
    Bzip2,
    /// Method 14 — LZMA (with the 4-byte ZIP wrapper prefix).
    Lzma,
    /// Method 93 — Zstandard.
    Zstd,
    /// Method 95 — XZ.
    Xz,
    /// Any other method id — value preserved so callers can report it.
    Unknown(u16),
}

impl CompressionMethod {
    pub(crate) fn from_u16(raw: u16) -> Self {
        match raw {
            0 => Self::Stored,
            8 => Self::Deflated,
            9 => Self::Deflate64,
            12 => Self::Bzip2,
            14 => Self::Lzma,
            93 => Self::Zstd,
            95 => Self::Xz,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed central-directory metadata for one entry.
#[derive(Debug, Clone)]
pub(crate) struct CentralEntry {
    pub(crate) name: String,
    pub(crate) method: CompressionMethod,
    pub(crate) flags: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) lfh_offset: u64,
}

impl CentralEntry {
    fn is_dir(&self) -> bool {
        self.name.ends_with('/') || self.name.ends_with('\\')
    }
}

/// A parsed ZIP archive over a seekable reader.
pub struct ZipArchive<R> {
    reader: R,
    entries: Vec<CentralEntry>,
}

impl<R: Read + Seek> ZipArchive<R> {
    /// Parse the EOCD and central directory of `reader`.
    pub fn new(mut reader: R) -> Result<Self, ZipCoreError> {
        let file_len = reader.seek(SeekFrom::End(0))?;
        let entries = parse_central_directory(&mut reader, file_len)?;
        Ok(Self { reader, entries })
    }

    /// Number of entries in the central directory.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the archive has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entry names in central-directory order.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    /// Open the entry at index `i` for decoding (mirrors zip-rs `by_index`).
    pub fn by_index(&mut self, i: usize) -> Result<ZipFile<'_, R>, ZipCoreError> {
        let meta = self
            .entries
            .get(i)
            .ok_or(ZipCoreError::IndexOutOfBounds(i))?
            .clone();
        self.open(meta)
    }

    /// Open the named entry for decoding (mirrors zip-rs `by_name`).
    pub fn by_name(&mut self, name: &str) -> Result<ZipFile<'_, R>, ZipCoreError> {
        let meta = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| ZipCoreError::EntryNotFound(name.to_string()))?
            .clone();
        self.open(meta)
    }

    fn open(&mut self, meta: CentralEntry) -> Result<ZipFile<'_, R>, ZipCoreError> {
        let data_start = resolve_data_start(&mut self.reader, &meta)?;
        self.reader.seek(SeekFrom::Start(data_start))?;
        let limited = (&mut self.reader).take(meta.compressed_size);
        let decoder = Decoder::new(meta.method, limited)?;
        Ok(ZipFile {
            meta,
            data_start,
            decoder,
            hasher: crc32fast::Hasher::new(),
            bytes_out: 0,
            verified: false,
        })
    }
}

/// Read the local file header at `meta.lfh_offset` and return the absolute offset
/// of the entry's first data byte (`lfh_offset + 30 + name_len + extra_len`).
fn resolve_data_start<R: Read + Seek>(
    reader: &mut R,
    meta: &CentralEntry,
) -> Result<u64, ZipCoreError> {
    reader.seek(SeekFrom::Start(meta.lfh_offset))?;
    let mut fixed = [0u8; LFH_FIXED];
    reader.read_exact(&mut fixed)?;
    let mut r = Reader::new(&fixed);
    if r.u32()? != LFH_SIG {
        return Err(FormatError::BadSignature {
            what: "local file header",
            offset: meta.lfh_offset,
        }
        .into());
    }
    // version(2) flags(2) method(2) time(2) date(2) crc(4) csize(4) usize(4)
    r.skip(22)?;
    let name_len = u64::from(r.u16()?);
    let extra_len = u64::from(r.u16()?);
    Ok(meta.lfh_offset + LFH_FIXED as u64 + name_len + extra_len)
}

/// Locate + parse the EOCD, then read and parse the central directory.
fn parse_central_directory<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
) -> Result<Vec<CentralEntry>, ZipCoreError> {
    let scan_len = file_len.min(EOCD_SCAN_MAX as u64);
    if scan_len < EOCD_MIN as u64 {
        return Err(FormatError::NoEocd.into());
    }
    let scan_start = file_len - scan_len;
    reader.seek(SeekFrom::Start(scan_start))?;
    let mut tail = vec![0u8; scan_len as usize];
    reader.read_exact(&mut tail)?;

    let eocd_rel = find_eocd(&tail).ok_or(FormatError::NoEocd)?;
    let (cd_offset, cd_size, total_entries) = parse_eocd(&tail[eocd_rel..])?;

    if cd_offset == u64::from(u32::MAX) {
        // Zip64 sentinel: real 64-bit offsets live in the zip64 EOCD record.
        return Err(FormatError::Zip64Unsupported.into());
    }
    match cd_offset.checked_add(cd_size) {
        Some(end) if end <= file_len => {}
        _ => return Err(FormatError::CentralDirOutOfRange { cd_offset, cd_size }.into()),
    }
    if total_entries > MAX_ENTRIES {
        return Err(FormatError::TooManyEntries(total_entries).into());
    }

    reader.seek(SeekFrom::Start(cd_offset))?;
    let mut cd = vec![0u8; cd_size as usize];
    reader.read_exact(&mut cd)?;

    parse_cd_entries(&cd, total_entries)
}

/// Scan backward for the EOCD signature, returning its offset within `tail`.
fn find_eocd(tail: &[u8]) -> Option<usize> {
    if tail.len() < EOCD_MIN {
        return None;
    }
    let sig = EOCD_SIG.to_le_bytes();
    // The EOCD starts at most EOCD_MIN bytes before EOF; scan from the latest.
    (0..=tail.len() - EOCD_MIN)
        .rev()
        .find(|&i| tail[i..i + 4] == sig)
}

/// Parse the fixed EOCD fields. Returns `(cd_offset, cd_size, total_entries)`.
fn parse_eocd(buf: &[u8]) -> Result<(u64, u64, usize), ZipCoreError> {
    let mut r = Reader::new(buf);
    if r.u32()? != EOCD_SIG {
        return Err(FormatError::NoEocd.into());
    }
    let _disk = r.u16()?;
    let _cd_disk = r.u16()?;
    let _entries_this_disk = r.u16()?;
    let total_entries = r.u16()?;
    let cd_size = r.u32()?;
    let cd_offset = r.u32()?;
    Ok((
        u64::from(cd_offset),
        u64::from(cd_size),
        usize::from(total_entries),
    ))
}

/// Parse `total_entries` central-directory file headers from `cd`.
fn parse_cd_entries(cd: &[u8], total_entries: usize) -> Result<Vec<CentralEntry>, ZipCoreError> {
    let mut r = Reader::new(cd);
    let mut entries = Vec::new();
    for _ in 0..total_entries {
        if r.remaining() < 46 {
            return Err(FormatError::Truncated.into());
        }
        if r.u32()? != CD_HEADER_SIG {
            return Err(FormatError::BadSignature {
                what: "central directory header",
                offset: (cd.len() - r.remaining()) as u64,
            }
            .into());
        }
        let _version_made_by = r.u16()?;
        let _version_needed = r.u16()?;
        let flags = r.u16()?;
        let method = CompressionMethod::from_u16(r.u16()?);
        let _mod_time = r.u16()?;
        let _mod_date = r.u16()?;
        let crc32 = r.u32()?;
        let compressed_size = u64::from(r.u32()?);
        let uncompressed_size = u64::from(r.u32()?);
        let name_len = usize::from(r.u16()?);
        let extra_len = usize::from(r.u16()?);
        let comment_len = usize::from(r.u16()?);
        let _disk_start = r.u16()?;
        let _internal_attrs = r.u16()?;
        let _external_attrs = r.u32()?;
        let lfh_offset = u64::from(r.u32()?);

        let name_bytes = r.take(name_len)?;
        let _extra = r.take(extra_len)?;
        let _comment = r.take(comment_len)?;

        // Filename: UTF-8 when GP flag bit 11 is set, else CP437. We accept either
        // as best-effort UTF-8 here; a full CP437 table is a follow-up (it only
        // affects display of non-ASCII names, not entry location).
        let name = decode_name(name_bytes, flags);

        entries.push(CentralEntry {
            name,
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
            lfh_offset,
        });
    }
    Ok(entries)
}

/// Decode an entry filename. UTF-8 (flag bit 11) is taken verbatim; otherwise we
/// map the CP437 high range so non-ASCII names are still legible.
fn decode_name(bytes: &[u8], flags: u16) -> String {
    if flags & 0x0800 != 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    if bytes.is_ascii() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    bytes.iter().map(|&b| crate::cp437::decode(b)).collect()
}

/// A decoding reader over one ZIP entry. Implements `Read`, yielding decompressed
/// bytes and verifying CRC-32 at EOF (fail loud on mismatch).
pub struct ZipFile<'a, R: Read> {
    meta: CentralEntry,
    data_start: u64,
    decoder: Decoder<'a, R>,
    hasher: crc32fast::Hasher,
    bytes_out: u64,
    verified: bool,
}

impl<R: Read> ZipFile<'_, R> {
    /// Entry name (path within the archive).
    pub fn name(&self) -> &str {
        &self.meta.name
    }

    /// Compression method.
    pub fn compression(&self) -> CompressionMethod {
        self.meta.method
    }

    /// Uncompressed size in bytes (from the central directory).
    pub fn size(&self) -> u64 {
        self.meta.uncompressed_size
    }

    /// Compressed size in bytes (from the central directory).
    pub fn compressed_size(&self) -> u64 {
        self.meta.compressed_size
    }

    /// Stored CRC-32 (from the central directory).
    pub fn crc32(&self) -> u32 {
        self.meta.crc32
    }

    /// Absolute offset of the entry's first data byte in the archive. For a
    /// `Stored` entry this is the start of the in-place, zero-copy window.
    pub fn data_start(&self) -> u64 {
        self.data_start
    }

    /// General-purpose flag bits (bit 0 encryption, bit 3 data descriptor, ...).
    pub fn flags(&self) -> u16 {
        self.meta.flags
    }

    /// Whether the entry names a directory.
    pub fn is_dir(&self) -> bool {
        self.meta.is_dir()
    }
}

impl<R: Read> Read for ZipFile<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.decoder.read(buf)?;
        if n == 0 {
            if !self.verified {
                self.verified = true;
                let actual = self.hasher.clone().finalize();
                if actual != self.meta.crc32 {
                    return Err(io::Error::other(ZipCoreError::CrcMismatch {
                        entry: self.meta.name.clone(),
                        expected: self.meta.crc32,
                        actual,
                    }));
                }
            }
            return Ok(0);
        }
        self.hasher.update(&buf[..n]);
        self.bytes_out += n as u64;
        Ok(n)
    }
}
