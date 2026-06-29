//! Pure-Rust ZIP container parser: EOCD + central directory + local file headers,
//! with a decoding entry reader that verifies CRC-32 on EOF.
//!
//! Mirrors the zip-rs surface (`ZipArchive::new` / `by_index` / `by_name` /
//! `ZipFile` with `name()`/`compression()`/`size()`/`data_start()`) so fleet
//! consumers migrate with a near-mechanical `zip::` -> `zip_core::` rename.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::bytes::Reader;
use crate::codec::Decoder;
use crate::crypto::{AesInfo, AesReader, ZipCryptoReader};
use crate::{FormatError, ZipCoreError};

const EOCD_SIG: u32 = 0x0605_4b50;
const CD_HEADER_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
/// Header id of the Zip64 extended-information extra field.
const ZIP64_EXTRA_ID: u16 = 0x0001;
/// 32-bit sentinel: the real value lives in a Zip64 record/extra field.
const U32_SENTINEL: u32 = 0xFFFF_FFFF;
/// 16-bit sentinel for counts.
const U16_SENTINEL: u16 = 0xFFFF;

/// Minimum EOCD record length (no comment).
const EOCD_MIN: usize = 22;
/// Largest region we scan back from EOF for the EOCD (record + max comment).
const EOCD_SCAN_MAX: usize = EOCD_MIN + u16::MAX as usize;
/// Zip64 EOCD locator record length.
const ZIP64_LOCATOR_LEN: usize = 20;
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
    /// Method 1 — legacy Shrink (not decoded; recognized so it can be named).
    Shrunk,
    /// Methods 2–5 — legacy Reduce (not decoded).
    Reduced,
    /// Method 6 — legacy Implode (not decoded).
    Imploded,
    /// Method 10 — PKWARE DCL Implode (not decoded).
    DclImploded,
    /// Method 16 — IBM z/OS CMPSC (not decoded).
    IbmCmpsc,
    /// Method 18 — IBM TERSE (not decoded).
    IbmTerse,
    /// Method 19 — IBM LZ77 / PFS (not decoded).
    IbmLz77,
    /// Method 94 — MP3 (not decoded).
    Mp3,
    /// Method 96 — JPEG variant (not decoded).
    Jpeg,
    /// Method 97 — WavPack (not decoded).
    WavPack,
    /// Method 98 — PPMd (not decoded).
    Ppmd,
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
            1 => Self::Shrunk,
            2..=5 => Self::Reduced,
            6 => Self::Imploded,
            10 => Self::DclImploded,
            16 => Self::IbmCmpsc,
            18 => Self::IbmTerse,
            19 => Self::IbmLz77,
            94 => Self::Mp3,
            96 => Self::Jpeg,
            97 => Self::WavPack,
            98 => Self::Ppmd,
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
    /// DOS mod-time (the ZipCrypto password-check byte when a data descriptor is
    /// used).
    pub(crate) last_mod_time: u16,
    /// WinZip AES parameters when this entry is method-99 encrypted.
    pub(crate) aes: Option<AesInfo>,
    /// Disk number holding this entry's local header (0 = this disk).
    pub(crate) disk_start: u16,
}

impl CentralEntry {
    fn is_dir(&self) -> bool {
        self.name.ends_with('/') || self.name.ends_with('\\')
    }
}

/// Container-level offsets/counts, for the forensic analyzer's structural audits
/// (trailing data, spanning, etc.). Returned by [`ZipArchive::summary`].
#[derive(Debug, Clone)]
pub struct ArchiveSummary {
    /// Total file length.
    pub file_len: u64,
    /// Absolute offset of the central directory.
    pub central_dir_offset: u64,
    /// Declared central-directory size in bytes.
    pub central_dir_size: u64,
    /// Absolute offset just past the end of the 32-bit EOCD record (incl. its
    /// comment) — bytes beyond this are trailing data.
    pub eocd_end_offset: u64,
    /// EOCD archive-comment length.
    pub comment_len: u16,
    /// Disk number recorded in the EOCD (0 for a single-file archive).
    pub disk_number: u32,
    /// Disk on which the central directory starts (0 for a single-file archive).
    pub cd_start_disk: u32,
}

/// A parsed ZIP archive over a seekable reader.
pub struct ZipArchive<R> {
    reader: R,
    entries: Vec<CentralEntry>,
    summary: ArchiveSummary,
}

impl<R: Read + Seek> ZipArchive<R> {
    /// Parse the EOCD and central directory of `reader`.
    pub fn new(mut reader: R) -> Result<Self, ZipCoreError> {
        let file_len = reader.seek(SeekFrom::End(0))?;
        let (entries, summary) = parse_central_directory(&mut reader, file_len)?;
        Ok(Self {
            reader,
            entries,
            summary,
        })
    }

    /// Container-level offsets/counts for structural audits.
    pub fn summary(&self) -> &ArchiveSummary {
        &self.summary
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
    pub fn by_index(&mut self, i: usize) -> Result<ZipFile<'_>, ZipCoreError> {
        let meta = self
            .entries
            .get(i)
            .ok_or(ZipCoreError::IndexOutOfBounds(i))?
            .clone();
        self.open(meta)
    }

    /// Open the named entry for decoding (mirrors zip-rs `by_name`).
    pub fn by_name(&mut self, name: &str) -> Result<ZipFile<'_>, ZipCoreError> {
        let meta = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| ZipCoreError::EntryNotFound(name.to_string()))?
            .clone();
        self.open(meta)
    }

    /// Open the entry at index `i`, decrypting it with `password` (ZipCrypto or
    /// WinZip AES). Errors with `WrongPassword` if the password fails the check.
    pub fn by_index_decrypt(
        &mut self,
        i: usize,
        password: &[u8],
    ) -> Result<ZipFile<'_>, ZipCoreError> {
        let meta = self
            .entries
            .get(i)
            .ok_or(ZipCoreError::IndexOutOfBounds(i))?
            .clone();
        self.open_decrypt(meta, password)
    }

    /// Open the named entry, decrypting it with `password`.
    pub fn by_name_decrypt(
        &mut self,
        name: &str,
        password: &[u8],
    ) -> Result<ZipFile<'_>, ZipCoreError> {
        let meta = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| ZipCoreError::EntryNotFound(name.to_string()))?
            .clone();
        self.open_decrypt(meta, password)
    }

    /// Raw structural view for the forensic analyzer: per entry, the header
    /// fields as recorded in BOTH the central directory and the local file
    /// header, plus offsets. This is the seam that lets `zip-forensic` compare
    /// the two copies (tamper signal) without re-implementing a second parser.
    pub fn structural_view(&mut self) -> Result<Vec<EntryLayout>, ZipCoreError> {
        let metas = self.entries.clone();
        let mut out = Vec::with_capacity(metas.len());
        for (index, m) in metas.iter().enumerate() {
            let (local, data_start) = read_lfh_fields(&mut self.reader, m.lfh_offset)?;
            out.push(EntryLayout {
                index,
                lfh_offset: m.lfh_offset,
                data_start,
                central: HeaderFields {
                    name: m.name.clone(),
                    method: m.method,
                    flags: m.flags,
                    crc32: m.crc32,
                    compressed_size: m.compressed_size,
                    uncompressed_size: m.uncompressed_size,
                },
                local,
            });
        }
        Ok(out)
    }

    fn open(&mut self, meta: CentralEntry) -> Result<ZipFile<'_>, ZipCoreError> {
        check_local_disk(&meta)?;
        if meta.flags & 0x0001 != 0 {
            return Err(ZipCoreError::EncryptedNoPassword(meta.name.clone()));
        }
        let (_local, data_start) = read_lfh_fields(&mut self.reader, meta.lfh_offset)?;
        self.reader.seek(SeekFrom::Start(data_start))?;
        let limited: Box<dyn Read + '_> = Box::new((&mut self.reader).take(meta.compressed_size));
        let decoder = Decoder::new(meta.method, meta.uncompressed_size, limited)?;
        Ok(ZipFile {
            data_start,
            decoder,
            hasher: crc32fast::Hasher::new(),
            bytes_out: 0,
            verified: false,
            verify_crc: true,
            meta,
        })
    }

    fn open_decrypt(
        &mut self,
        meta: CentralEntry,
        password: &[u8],
    ) -> Result<ZipFile<'_>, ZipCoreError> {
        check_local_disk(&meta)?;
        // Not encrypted -> the password is irrelevant; read normally.
        if meta.flags & 0x0001 == 0 && meta.aes.is_none() {
            return self.open(meta);
        }
        // PKWARE Strong Encryption (GP bit 6) and masked/central-directory
        // encryption (GP bit 13) are unsupported — fail loud rather than misread
        // the stream as traditional ZipCrypto. Only ZipCrypto + WinZip AES decode.
        if meta.aes.is_none() && meta.flags & 0x0040 != 0 {
            return Err(ZipCoreError::UnsupportedEncryption {
                entry: meta.name,
                reason: "PKWARE strong encryption (GP flag bit 6)".to_string(),
            });
        }
        if meta.flags & 0x2000 != 0 {
            return Err(ZipCoreError::UnsupportedEncryption {
                entry: meta.name,
                reason: "masked / central-directory encryption (GP flag bit 13)".to_string(),
            });
        }
        let (_local, data_start) = read_lfh_fields(&mut self.reader, meta.lfh_offset)?;
        self.reader.seek(SeekFrom::Start(data_start))?;
        let take = (&mut self.reader).take(meta.compressed_size);
        let (reader, method, verify_crc): (Box<dyn Read + '_>, CompressionMethod, bool) =
            if let Some(aes) = meta.aes {
                let r = AesReader::new(take, password, aes, meta.compressed_size, &meta.name)?;
                // AE-2 zeroes the CRC field; its integrity is the HMAC (checked by
                // AesReader). AE-1 keeps the CRC, so verify it.
                (
                    Box::new(r),
                    CompressionMethod::from_u16(aes.actual_method),
                    !aes.is_ae2,
                )
            } else {
                // Traditional ZipCrypto: the check byte is the CRC high byte, or the
                // mod-time high byte when a data descriptor is used (bit 3).
                let check = zipcrypto_check_byte(meta.flags, meta.crc32, meta.last_mod_time);
                let r = ZipCryptoReader::new(take, password, check, &meta.name)?;
                (Box::new(r), meta.method, true)
            };
        let decoder = Decoder::new(method, meta.uncompressed_size, reader)?;
        Ok(ZipFile {
            data_start,
            decoder,
            hasher: crc32fast::Hasher::new(),
            bytes_out: 0,
            verified: false,
            verify_crc,
            meta,
        })
    }
}

/// Header fields as recorded in one header copy (central directory OR local file
/// header). Exposed via [`ZipArchive::structural_view`] for the forensic seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderFields {
    /// Entry name (decoded).
    pub name: String,
    /// Compression method.
    pub method: CompressionMethod,
    /// General-purpose flag bits.
    pub flags: u16,
    /// CRC-32 as recorded in this header copy.
    pub crc32: u32,
    /// Compressed size as recorded in this header copy.
    pub compressed_size: u64,
    /// Uncompressed size as recorded in this header copy.
    pub uncompressed_size: u64,
}

/// One entry's raw structural layout: the central-directory and local-file-header
/// copies of its fields plus offsets, for cross-checking (tamper detection).
#[derive(Debug, Clone)]
pub struct EntryLayout {
    /// Index in central-directory order.
    pub index: usize,
    /// Absolute offset of the local file header.
    pub lfh_offset: u64,
    /// Absolute offset of the entry's first data byte.
    pub data_start: u64,
    /// Fields as recorded in the central directory.
    pub central: HeaderFields,
    /// Fields as recorded in the local file header.
    pub local: HeaderFields,
}

/// Read and parse the local file header at `lfh_offset`, returning its fields and
/// the absolute offset of the entry's first data byte
/// (`lfh_offset + 30 + name_len + extra_len`).
fn read_lfh_fields<R: Read + Seek>(
    reader: &mut R,
    lfh_offset: u64,
) -> Result<(HeaderFields, u64), ZipCoreError> {
    reader.seek(SeekFrom::Start(lfh_offset))?;
    let mut fixed = [0u8; LFH_FIXED];
    reader.read_exact(&mut fixed)?;
    let mut r = Reader::new(&fixed);
    if r.u32()? != LFH_SIG {
        return Err(FormatError::BadSignature {
            what: "local file header",
            offset: lfh_offset,
        }
        .into());
    }
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

    let mut name_buf = vec![0u8; name_len];
    reader.read_exact(&mut name_buf)?;
    let name = decode_name(&name_buf, flags);
    let data_start = lfh_offset + LFH_FIXED as u64 + name_len as u64 + extra_len as u64;

    Ok((
        HeaderFields {
            name,
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
        },
        data_start,
    ))
}

/// Locate + parse the EOCD, then read and parse the central directory.
/// The 32-bit EOCD fields. Any size/offset/count may be a sentinel for Zip64.
struct Eocd32 {
    disk_number: u16,
    cd_start_disk: u16,
    total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
    comment_len: u16,
}

fn parse_central_directory<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
) -> Result<(Vec<CentralEntry>, ArchiveSummary), ZipCoreError> {
    let scan_len = file_len.min(EOCD_SCAN_MAX as u64);
    if scan_len < EOCD_MIN as u64 {
        return Err(FormatError::NoEocd.into());
    }
    let scan_start = file_len - scan_len;
    reader.seek(SeekFrom::Start(scan_start))?;
    let mut tail = vec![0u8; scan_len as usize];
    reader.read_exact(&mut tail)?;

    let eocd_rel = find_eocd(&tail).ok_or(FormatError::NoEocd)?;
    let eocd = parse_eocd(&tail[eocd_rel..])?;
    // Absolute end of the 32-bit EOCD record incl. its comment; the EOCD is always
    // the last structure, so anything past this is trailing data.
    let eocd_end_offset =
        scan_start + eocd_rel as u64 + EOCD_MIN as u64 + u64::from(eocd.comment_len);

    // Promote to Zip64 when any base field is a sentinel: the real 64-bit
    // offset/size/count/disk live in the Zip64 EOCD record reached via its locator.
    let (cd_offset, cd_size, total_entries, disk_number, cd_start_disk) = if eocd.cd_offset
        == U32_SENTINEL
        || eocd.cd_size == U32_SENTINEL
        || eocd.total_entries == U16_SENTINEL
    {
        resolve_zip64_eocd(reader, &tail, eocd_rel)?
    } else {
        (
            u64::from(eocd.cd_offset),
            u64::from(eocd.cd_size),
            usize::from(eocd.total_entries),
            u32::from(eocd.disk_number),
            u32::from(eocd.cd_start_disk),
        )
    };

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

    let entries = parse_cd_entries(&cd, total_entries)?;
    let summary = ArchiveSummary {
        file_len,
        central_dir_offset: cd_offset,
        central_dir_size: cd_size,
        eocd_end_offset,
        comment_len: eocd.comment_len,
        disk_number,
        cd_start_disk,
    };
    Ok((entries, summary))
}

/// Scan backward for the EOCD signature, returning its offset within `tail`.
fn find_eocd(tail: &[u8]) -> Option<usize> {
    if tail.len() < EOCD_MIN {
        return None; // cov:unreachable: parse_central_directory guards scan_len >= EOCD_MIN
    }
    let sig = EOCD_SIG.to_le_bytes();
    // The EOCD starts at most EOCD_MIN bytes before EOF; scan from the latest.
    (0..=tail.len() - EOCD_MIN)
        .rev()
        .find(|&i| tail[i..i + 4] == sig)
}

/// Parse the fixed EOCD fields. Any size/offset/count may be a Zip64 sentinel.
fn parse_eocd(buf: &[u8]) -> Result<Eocd32, ZipCoreError> {
    let mut r = Reader::new(buf);
    if r.u32()? != EOCD_SIG {
        return Err(FormatError::NoEocd.into()); // cov:unreachable: find_eocd matched this signature
    }
    let disk_number = r.u16()?;
    let cd_start_disk = r.u16()?;
    let _entries_this_disk = r.u16()?;
    let total_entries = r.u16()?;
    let cd_size = r.u32()?;
    let cd_offset = r.u32()?;
    let comment_len = r.u16()?;
    Ok(Eocd32 {
        disk_number,
        cd_start_disk,
        total_entries,
        cd_size,
        cd_offset,
        comment_len,
    })
}

/// Resolve the real central-directory location from the Zip64 EOCD record. The
/// Zip64 EOCD locator sits immediately before the 32-bit EOCD; it points at the
/// Zip64 EOCD record holding the true 64-bit offset/size/count.
fn resolve_zip64_eocd<R: Read + Seek>(
    reader: &mut R,
    tail: &[u8],
    eocd_rel: usize,
) -> Result<(u64, u64, usize, u32, u32), ZipCoreError> {
    if eocd_rel < ZIP64_LOCATOR_LEN {
        return Err(FormatError::Zip64Unsupported.into());
    }
    let mut loc = Reader::new(&tail[eocd_rel - ZIP64_LOCATOR_LEN..eocd_rel]);
    if loc.u32()? != ZIP64_LOCATOR_SIG {
        return Err(FormatError::Zip64Unsupported.into());
    }
    let _disk = loc.u32()?;
    let z64_eocd_offset = loc.u64()?;

    reader.seek(SeekFrom::Start(z64_eocd_offset))?;
    let mut rec = [0u8; 56];
    reader.read_exact(&mut rec)?;
    let mut r = Reader::new(&rec);
    if r.u32()? != ZIP64_EOCD_SIG {
        return Err(FormatError::BadSignature {
            what: "Zip64 EOCD record",
            offset: z64_eocd_offset,
        }
        .into());
    }
    let _record_size = r.u64()?;
    let _version_made_by = r.u16()?;
    let _version_needed = r.u16()?;
    let disk_number = r.u32()?;
    let cd_start_disk = r.u32()?;
    let _entries_this_disk = r.u64()?;
    let total_entries = r.u64()?;
    let cd_size = r.u64()?;
    let cd_offset = r.u64()?;
    let total =
        usize::try_from(total_entries).map_err(|_| FormatError::TooManyEntries(usize::MAX))?;
    Ok((cd_offset, cd_size, total, disk_number, cd_start_disk))
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
        let method_raw = r.u16()?;
        let method = CompressionMethod::from_u16(method_raw);
        let last_mod_time = r.u16()?;
        let _mod_date = r.u16()?;
        let crc32 = r.u32()?;
        let compressed_size32 = r.u32()?;
        let uncompressed_size32 = r.u32()?;
        let name_len = usize::from(r.u16()?);
        let extra_len = usize::from(r.u16()?);
        let comment_len = usize::from(r.u16()?);
        let disk_start = r.u16()?;
        let _internal_attrs = r.u16()?;
        let _external_attrs = r.u32()?;
        let lfh_offset32 = r.u32()?;

        let name_bytes = r.take(name_len)?;
        let extra = r.take(extra_len)?;
        let _comment = r.take(comment_len)?;

        // Resolve any 0xFFFFFFFF sentinels from the Zip64 extended-information
        // extra field (header id 0x0001). Fields appear in a FIXED order and only
        // when their base field is a sentinel.
        let mut uncompressed_size = u64::from(uncompressed_size32);
        let mut compressed_size = u64::from(compressed_size32);
        let mut lfh_offset = u64::from(lfh_offset32);
        if uncompressed_size32 == U32_SENTINEL
            || compressed_size32 == U32_SENTINEL
            || lfh_offset32 == U32_SENTINEL
        {
            apply_zip64_extra(
                extra,
                uncompressed_size32 == U32_SENTINEL,
                compressed_size32 == U32_SENTINEL,
                lfh_offset32 == U32_SENTINEL,
                &mut uncompressed_size,
                &mut compressed_size,
                &mut lfh_offset,
            )?;
        }

        // Filename: UTF-8 when GP flag bit 11 is set, else CP437. We accept either
        // as best-effort UTF-8 here; a full CP437 table is a follow-up (it only
        // affects display of non-ASCII names, not entry location).
        let name = decode_name(name_bytes, flags);
        // Method 99 = WinZip AES; the AE-x extra field (0x9901) carries the real
        // method + key strength.
        let aes = if method_raw == 99 {
            parse_aes_extra(extra)
        } else {
            None
        };

        entries.push(CentralEntry {
            name,
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
            lfh_offset,
            last_mod_time,
            aes,
            disk_start,
        });
    }
    Ok(entries)
}

/// Override sentinel CD fields from the Zip64 extended-information extra field
/// (header id 0x0001). The 64-bit fields appear in a fixed order — original size,
/// compressed size, relative header offset — and ONLY when their base field is a
/// sentinel. A sentinel with no matching extra field is a malformed Zip64 archive.
fn apply_zip64_extra(
    extra: &[u8],
    need_uncompressed: bool,
    need_compressed: bool,
    need_offset: bool,
    uncompressed_size: &mut u64,
    compressed_size: &mut u64,
    lfh_offset: &mut u64,
) -> Result<(), ZipCoreError> {
    let mut r = Reader::new(extra);
    while r.remaining() >= 4 {
        let id = r.u16()?;
        let size = usize::from(r.u16()?);
        if id == ZIP64_EXTRA_ID {
            let mut z = Reader::new(r.take(size)?);
            if need_uncompressed {
                *uncompressed_size = z.u64()?;
            }
            if need_compressed {
                *compressed_size = z.u64()?;
            }
            if need_offset {
                *lfh_offset = z.u64()?;
            }
            return Ok(());
        }
        r.skip(size)?;
    }
    Err(FormatError::Zip64Inconsistent.into())
}

/// Parse the WinZip AE-x extra field (header id 0x9901) from an entry's extra
/// data: version (AE-1/AE-2), vendor "AE", AES strength, and the real method.
fn parse_aes_extra(extra: &[u8]) -> Option<AesInfo> {
    let mut r = Reader::new(extra);
    while r.remaining() >= 4 {
        let id = r.u16().ok()?;
        let size = usize::from(r.u16().ok()?);
        if id == 0x9901 {
            let data = r.take(size).ok()?;
            let mut d = Reader::new(data);
            let version = d.u16().ok()?; // 1 = AE-1, 2 = AE-2
            let _vendor = d.u16().ok()?; // "AE"
            let strength = d.take(1).ok()?[0];
            let actual_method = d.u16().ok()?;
            return Some(AesInfo {
                strength,
                actual_method,
                is_ae2: version == 2,
            });
        }
        r.skip(size).ok()?;
    }
    None
}

/// The ZipCrypto password-verification byte: the CRC-32 high byte, or the
/// mod-time high byte when the entry uses a data descriptor (GP flag bit 3),
/// matching what the encrypter used (PKWARE APPNOTE 6.1.6).
fn zipcrypto_check_byte(flags: u16, crc32: u32, last_mod_time: u16) -> u8 {
    if flags & 0x0008 != 0 {
        (last_mod_time >> 8) as u8
    } else {
        (crc32 >> 24) as u8
    }
}

/// Decode an entry filename. UTF-8 (flag bit 11) is taken verbatim; otherwise we
/// map the CP437 high range so non-ASCII names are still legible.
fn decode_name(bytes: &[u8], flags: u16) -> String {
    // UTF-8 flag (bit 11) set, or pure ASCII: take the bytes as UTF-8 (lossy).
    if flags & 0x0800 != 0 || bytes.is_ascii() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    bytes.iter().map(|&b| crate::cp437::decode(b)).collect()
}

/// A decoding reader over one ZIP entry. Implements `Read`, yielding decompressed
/// bytes and verifying CRC-32 at EOF (fail loud on mismatch).
pub struct ZipFile<'a> {
    meta: CentralEntry,
    data_start: u64,
    decoder: Decoder<Box<dyn Read + 'a>>,
    hasher: crc32fast::Hasher,
    bytes_out: u64,
    verified: bool,
    /// Whether to verify CRC-32 at EOF. False for `WinZip` AE-2, whose integrity
    /// is the HMAC (checked by the AES reader) and whose CD CRC field is zero.
    verify_crc: bool,
}

impl ZipFile<'_> {
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

    /// A safe relative path for extraction, or `None` if the entry name escapes
    /// the destination (parent-dir traversal, absolute, or drive-letter path).
    /// The raw [`name`](Self::name) is always preserved as evidence; this is the
    /// secure-by-default view a caller should join onto an output directory.
    pub fn enclosed_name(&self) -> Option<PathBuf> {
        enclosed_name(&self.meta.name)
    }
}

/// Fail loud if an entry's data lives on another disk of a spanned archive — we
/// don't reassemble split volumes, so reading from the current file would return
/// the wrong bytes.
fn check_local_disk(meta: &CentralEntry) -> Result<(), ZipCoreError> {
    if meta.disk_start != 0 {
        return Err(ZipCoreError::SpannedArchive {
            entry: meta.name.clone(),
            disk: u32::from(meta.disk_start),
        });
    }
    Ok(())
}

/// Compute a traversal-safe relative path from a ZIP entry name, treating both
/// `/` and `\` as separators (ZIP names may use either) so the check holds on
/// every platform regardless of `std::path` separator conventions.
fn enclosed_name(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('\0') {
        return None;
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return None; // absolute / UNC-style
    }
    let b = name.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return None; // drive-letter prefix (C:\...)
    }
    let mut out = PathBuf::new();
    for comp in name.split(['/', '\\']) {
        match comp {
            "" | "." => {}
            ".." => return None,
            other => out.push(other),
        }
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    Some(out)
}

impl Read for ZipFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.decoder.read(buf)?;
        if n == 0 {
            if !self.verified {
                self.verified = true;
                let actual = self.hasher.clone().finalize();
                if self.verify_crc && actual != self.meta.crc32 {
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

#[cfg(test)]
mod tests {
    use super::zipcrypto_check_byte;

    #[test]
    fn check_byte_selects_crc_or_modtime() {
        // No data descriptor (bit 3 clear) -> CRC-32 high byte.
        assert_eq!(zipcrypto_check_byte(0x0000, 0xAB12_3456, 0x7890), 0xAB);
        // Data descriptor (bit 3 set) -> mod-time high byte.
        assert_eq!(zipcrypto_check_byte(0x0008, 0xAB12_3456, 0xCD90), 0xCD);
    }
}
