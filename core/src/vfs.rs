//! `impl FileSystem for ZipVfs` — the forensic-vfs adapter (behind the `vfs`
//! feature) so a ZIP archive's file tree composes as `Arc<dyn FileSystem>` in the
//! forensic-vfs engine, like the AD1 / DAR archive adapters.
//!
//! A ZIP central directory is a flat list of full `/`-separated entry names, the
//! same shape as AD1 / DAR — so the directory tree is derived: a synthetic root
//! (node 0) plus one node per catalogue entry, wired parent→children by splitting
//! each name on `/`. Intermediate directories are *synthesized* when a name's
//! prefix has no explicit entry (some producers omit the trailing-`/` directory
//! records), so `a/b/c.txt` yields walkable `a` and `a/b` directories even when
//! only the file was listed. Nodes are addressed by [`FileId::Opaque`] carrying an
//! index into an internal node vector built at [`ZipVfs::open`]; each file node
//! keeps the central-directory index of its backing entry so [`FileSystem::read_at`]
//! reads it through [`ZipArchive::by_index`].
//!
//! The reader's `by_index` takes `&mut self` (it seeks and builds a decoder), so
//! [`ZipArchive`] is wrapped in a poison-recovering [`Mutex`] and one handle serves
//! N workers. ZIP entries are compressed, and `read_at` may be called repeatedly at
//! different offsets, so a per-node decompressed-content cache (like the DAR
//! adapter's) inflates each entry at most once.
//!
//! ## Mapping notes / known limits
//! - **`FsKind`.** `forensic-vfs`'s `FsKind` has no ZIP/archive variant (it is
//!   `#[non_exhaustive]`, and this crate must not add one), so
//!   [`FileSystem::kind`] reports [`FsKind::Other`].
//! - **Sector sizes.** A ZIP archive is a byte stream with no media geometry;
//!   [`FileSystem::sector_sizes`] reports 512 for all three fields (a neutral
//!   default, not a real on-media block).
//! - **Times.** ZIP's native per-entry stamp is an MS-DOS date/time, which the
//!   reader does not surface. The Info-ZIP extended-timestamp (extra id `0x5455`,
//!   Unix seconds) and NTFS (`0x000a`, Windows `FILETIME`) extra fields, which the
//!   reader *does* surface, are UTC-anchored — so [`FsMeta::times`] carries
//!   `modified`/`accessed` and `born` (the ZIP "ctime" extra fields record the
//!   *creation* time) when present, and [`FileSystem::timestamp_zone`] is
//!   [`TimeZonePolicy::Utc`]. `changed` (inode-change time) has no ZIP equivalent
//!   and is always `None`; an entry carrying only the MS-DOS time has all times
//!   `None` — honestly absent, not a fabricated epoch.
//! - **Ownership metadata.** The reader does not surface uid/gid/mode, so those
//!   `FsMeta` fields are `None`.
//! - **Single stream.** A ZIP entry has one data stream; a non-`Default`
//!   [`StreamId`] is refused loud.
//! - **Names are raw evidence.** Entry names are surfaced verbatim (raw bytes,
//!   including any `..`/absolute components) and reads go through opaque node ids,
//!   never a filesystem path this adapter writes — so a zip-slip name cannot escape
//!   (the adapter never extracts to disk).
//! - **Encrypted entries.** Metadata and the tree are built from the central
//!   directory (no decryption), so an encrypted entry is navigable; reading its
//!   bytes is refused loud (no password) rather than returning garbage.
//! - **Extents (first cut).** An archive exposes no on-media allocation runs, so
//!   [`FileSystem::extents`] yields a single logical run (`image_offset` = 0,
//!   `len` = the entry's uncompressed size) rather than true on-disk runs.
//!   Surfacing the stored deflate-block layout is future work.
//! - **Symlinks.** The reader does not surface symlink targets, so
//!   [`FileSystem::read_link`] returns an empty target (matching the AD1 / DAR
//!   convention).
//! - **Deleted/unallocated (first cut).** ZIP carving of orphaned local headers and
//!   free-space enumeration are not yet surfaced, so [`FileSystem::deleted`] /
//!   [`FileSystem::unallocated`] are empty streams. Future work, not fabricated
//!   data.

use std::collections::HashMap;
use std::io::{Read, Seek};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use forensic_vfs::{
    Allocation, ByteRun, DirEntry as VfsDirEntry, DirStream, ExtentStream, FileId, FileSystem,
    FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo,
    SectorSizes, StreamId, TimeResolution, TimeSource, TimeStamp, TimeZonePolicy, VfsError,
    VfsResult,
};

use crate::{EntryLayout, ExtraFields, FormatError, ZipArchive, ZipCoreError};

/// A neutral logical block size for an archive byte stream (no media geometry).
const ARCHIVE_BLOCK: u32 = 512;

/// One node in the derived directory tree. The synthetic root is node 0
/// (`entry_idx` `None`); every catalogue entry becomes a node, plus any
/// intermediate directory implied by a path is synthesized (`entry_idx` `None`).
struct Node {
    /// Central-directory index of the backing entry; `None` for the synthetic root
    /// and for intermediate directories implied by a path but not themselves listed.
    entry_idx: Option<usize>,
    /// Last path component (raw bytes) — the name a parent lists this child under.
    name: Vec<u8>,
    kind: NodeKind,
    size: u64,
    modified: Option<TimeStamp>,
    accessed: Option<TimeStamp>,
    born: Option<TimeStamp>,
    /// Node ids of this node's directory children.
    children: Vec<u64>,
}

/// Reader plus its per-entry decompressed-content cache, guarded by one mutex.
struct Inner<R: Read + Seek> {
    archive: ZipArchive<R>,
    /// Node id → the entry's fully-decompressed bytes (decompression is not free,
    /// and `read_at` may be called repeatedly at different offsets).
    cache: HashMap<u64, Arc<Vec<u8>>>,
}

/// A mounted ZIP archive exposed through the forensic-vfs `FileSystem` contract.
/// Reads are `&self` over an interior `Mutex`, so one handle serves N workers.
pub struct ZipVfs<R: Read + Seek> {
    inner: Mutex<Inner<R>>,
    nodes: Vec<Node>,
}

impl<R: Read + Seek + Send> ZipVfs<R> {
    /// Open a ZIP archive over a `Read + Seek` cursor.
    ///
    /// Parses the central directory, then derives the directory tree from the flat
    /// list of entry names: a synthetic root (node 0), one node per entry, and any
    /// synthesized intermediate directories, wired parent→children by splitting each
    /// name on `/`.
    ///
    /// # Errors
    /// Any [`ZipCoreError`] from opening the container, mapped to the corresponding
    /// [`VfsError`] (a missing End Of Central Directory becomes a loud
    /// [`VfsError::Bootstrap`]).
    pub fn open(reader: R) -> VfsResult<Self> {
        let mut archive = ZipArchive::new(reader).map_err(map_err)?;
        // Central-directory metadata (names, sizes, timestamp extra fields) without
        // opening decoders — so encrypted entries stay navigable.
        let layouts = archive.structural_view().map_err(map_err)?;
        let nodes = build_tree(&layouts);
        Ok(Self {
            inner: Mutex::new(Inner {
                archive,
                cache: HashMap::new(),
            }),
            nodes,
        })
    }

    /// Lock the interior state, recovering from a poisoned mutex rather than
    /// panicking (Paranoid Gatekeeper).
    fn lock(&self) -> MutexGuard<'_, Inner<R>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolve a [`FileId`] to a node, or a loud error for any non-`Opaque` id or
    /// an index outside the node table.
    fn node_of(&self, id: FileId) -> VfsResult<&Node> {
        let idx = index_of(id)?;
        self.nodes
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .ok_or(VfsError::Unsupported {
                layer: "zip file-id",
                scheme: format!("Opaque({idx}) out of range"),
            })
    }

    /// The fully-decompressed bytes of node `node_id` (a file backed by central
    /// entry `entry_idx`), decoding once and caching by node id so repeated
    /// `read_at` offsets do not re-decompress. A decode/IO failure is surfaced
    /// loud, never a silent empty.
    fn content(&self, node_id: u64, entry_idx: usize) -> VfsResult<Arc<Vec<u8>>> {
        let mut inner = self.lock();
        if let Some(data) = inner.cache.get(&node_id) {
            return Ok(Arc::clone(data));
        }
        let bytes = {
            let mut file = inner.archive.by_index(entry_idx).map_err(map_err)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|source| VfsError::Io {
                    op: "zip read",
                    source,
                })?;
            bytes
        };
        let arc = Arc::new(bytes);
        inner.cache.insert(node_id, Arc::clone(&arc));
        Ok(arc)
    }
}

/// The node index carried by a [`FileId`]; any other identity domain is a caller
/// error surfaced loud.
fn index_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::Opaque(n) => Ok(n),
        other => Err(VfsError::Unsupported {
            layer: "zip file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// A ZIP entry exposes a single unnamed data stream; a named-stream id is refused
/// loud.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "zip stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Map a [`ZipCoreError`] to the VFS error type, keeping I/O distinct from a
/// structural decode failure and a not-a-ZIP signature from a bootstrap failure.
fn map_err(e: ZipCoreError) -> VfsError {
    match e {
        ZipCoreError::Io(source) => VfsError::Io {
            op: "zip read",
            source,
        },
        ZipCoreError::Format(FormatError::NoEocd) => VfsError::Bootstrap {
            stage: "zip mount",
            detail: "no End Of Central Directory record (not a ZIP archive)".to_string(),
        },
        ZipCoreError::UnsupportedMethod(_)
        | ZipCoreError::UnsupportedEncryption { .. }
        | ZipCoreError::EncryptedNoPassword(_)
        | ZipCoreError::WrongPassword(_)
        | ZipCoreError::SpannedArchive { .. } => VfsError::Unsupported {
            layer: "zip",
            scheme: e.to_string(),
        },
        other => VfsError::Decode {
            layer: "zip",
            offset: 0,
            detail: other.to_string(),
            bytes: forensic_vfs::SmallHex::new(&[]),
        },
    }
}

/// A Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC) as a VFS [`TimeStamp`].
fn filetime_ts(ft: u64) -> TimeStamp {
    /// 100 ns ticks between 1601-01-01 and the Unix epoch (1970-01-01).
    const EPOCH_DIFF_100NS: i128 = 116_444_736_000_000_000;
    TimeStamp {
        unix_nanos: (i128::from(ft) - EPOCH_DIFF_100NS) * 100,
        source: TimeSource::Unspecified,
        resolution: TimeResolution::WinFileTime,
    }
}

/// A Unix-epoch seconds timestamp (Info-ZIP extended timestamp) as a [`TimeStamp`].
fn unix_secs_ts(secs: i32) -> TimeStamp {
    TimeStamp {
        unix_nanos: i128::from(secs) * 1_000_000_000,
        source: TimeSource::Unspecified,
        resolution: TimeResolution::Seconds,
    }
}

/// Derive `(modified, accessed, born)` from an entry's extra fields, preferring the
/// higher-fidelity NTFS `FILETIME` over the Info-ZIP Unix seconds when both exist.
/// The ZIP "ctime" extra fields record *creation* time, so they map to `born`.
fn extra_times(extra: &ExtraFields) -> (Option<TimeStamp>, Option<TimeStamp>, Option<TimeStamp>) {
    let modified = extra
        .ntfs_mtime
        .map(filetime_ts)
        .or_else(|| extra.unix_mtime.map(unix_secs_ts));
    let accessed = extra
        .ntfs_atime
        .map(filetime_ts)
        .or_else(|| extra.unix_atime.map(unix_secs_ts));
    let born = extra
        .ntfs_ctime
        .map(filetime_ts)
        .or_else(|| extra.unix_ctime.map(unix_secs_ts));
    (modified, accessed, born)
}

/// Derive the directory tree (node 0 = synthetic root) from the flat central
/// directory. Each entry name is split on `/` (and `\`); intermediate directories
/// are synthesized on first use and deduplicated by their normalized path, so an
/// explicit `sub/` entry and an implied `sub` prefix resolve to one node.
fn build_tree(layouts: &[EntryLayout]) -> Vec<Node> {
    let mut nodes: Vec<Node> = Vec::with_capacity(layouts.len() + 1);
    // Node 0: synthetic root.
    nodes.push(Node {
        entry_idx: None,
        name: Vec::new(),
        kind: NodeKind::Dir,
        size: 0,
        modified: None,
        accessed: None,
        born: None,
        children: Vec::new(),
    });

    // Normalized ('/'-joined, separator-trimmed) path -> node id. Root is "".
    let mut by_path: HashMap<String, u64> = HashMap::new();
    by_path.insert(String::new(), 0);

    for layout in layouts {
        let raw = layout.central.name.as_str();
        // ZIP marks a directory by a trailing separator ('\' seen in some Windows
        // producers, per the reader's own `is_dir`).
        let is_dir = raw.ends_with('/') || raw.ends_with('\\');
        let comps: Vec<&str> = raw
            .split(['/', '\\'])
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        let Some(last) = comps.len().checked_sub(1) else {
            continue; // a bare "/" (or empty) entry names no addressable node
        };
        let (modified, accessed, born) = extra_times(&layout.extra);

        let mut parent_id = 0u64;
        let mut acc = String::new();
        for (ci, comp) in comps.iter().enumerate() {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(comp);

            if ci == last {
                // Leaf: the entry itself (file, or an explicit directory record).
                if let Some(&existing) = by_path.get(&acc) {
                    // A directory implied earlier now has its explicit record; keep
                    // its identity, just attach the backing entry + timestamps.
                    if let Some(n) = nodes.get_mut(usize::try_from(existing).unwrap_or(usize::MAX))
                    {
                        if n.entry_idx.is_none() {
                            n.entry_idx = Some(layout.index);
                            n.modified = modified;
                            n.accessed = accessed;
                            n.born = born;
                        }
                    }
                } else {
                    let id = nodes.len() as u64;
                    nodes.push(Node {
                        entry_idx: Some(layout.index),
                        name: comp.as_bytes().to_vec(),
                        kind: if is_dir {
                            NodeKind::Dir
                        } else {
                            NodeKind::File
                        },
                        size: if is_dir {
                            0
                        } else {
                            layout.central.uncompressed_size
                        },
                        modified,
                        accessed,
                        born,
                        children: Vec::new(),
                    });
                    by_path.insert(acc.clone(), id);
                    push_child(&mut nodes, parent_id, id);
                }
            } else if let Some(&existing) = by_path.get(&acc) {
                parent_id = existing;
            } else {
                let id = nodes.len() as u64;
                nodes.push(Node {
                    entry_idx: None,
                    name: comp.as_bytes().to_vec(),
                    kind: NodeKind::Dir,
                    size: 0,
                    modified: None,
                    accessed: None,
                    born: None,
                    children: Vec::new(),
                });
                by_path.insert(acc.clone(), id);
                push_child(&mut nodes, parent_id, id);
                parent_id = id;
            }
        }
    }
    nodes
}

/// Register `child` under `parent_id`'s children list.
fn push_child(nodes: &mut [Node], parent_id: u64, child: u64) {
    if let Some(parent) = nodes.get_mut(usize::try_from(parent_id).unwrap_or(usize::MAX)) {
        parent.children.push(child);
    }
}

impl<R: Read + Seek + Send> FileSystem for ZipVfs<R> {
    fn kind(&self) -> FsKind {
        // forensic-vfs has no ZIP/archive FsKind variant (see the module note).
        FsKind::Other
    }

    fn root(&self) -> FileId {
        FileId::Opaque(0)
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: ARCHIVE_BLOCK,
            physical: ARCHIVE_BLOCK,
            cluster_or_block: ARCHIVE_BLOCK,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // The surfaced Info-ZIP / NTFS extended-timestamp extra fields are UTC.
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let node = self.node_of(ino)?;
        if node.kind != NodeKind::Dir {
            return Err(VfsError::Decode {
                layer: "zip",
                offset: 0,
                detail: format!("node {:?} is not a directory", index_of(ino)?),
                bytes: forensic_vfs::SmallHex::new(&[]),
            });
        }
        // Snapshot children into owned entries so the stream outlives the borrow.
        let mut out: Vec<VfsResult<VfsDirEntry>> = Vec::with_capacity(node.children.len());
        for &child in &node.children {
            let Some(c) = self.nodes.get(usize::try_from(child).unwrap_or(usize::MAX)) else {
                continue; // cov:unreachable: children hold in-range node ids by construction
            };
            out.push(Ok(VfsDirEntry {
                name: c.name.clone(),
                id: FileId::Opaque(child),
                kind: c.kind,
            }));
        }
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let node = self.node_of(ino)?;
        require_default_stream(stream)?;
        // First cut: an archive exposes no on-media runs, so a non-empty file
        // yields one logical run (image_offset 0). See the module note.
        if node.size == 0 {
            return Ok(ExtentStream::empty());
        }
        let run = RunInfo {
            run: ByteRun {
                image_offset: 0,
                len: node.size,
                flags: RunFlags::default(),
            },
            alloc: RunAlloc::Allocated,
        };
        Ok(ExtentStream::new(std::iter::once(Ok(run))))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let node = self.node_of(parent)?;
        if node.kind != NodeKind::Dir {
            return Err(VfsError::Decode {
                layer: "zip",
                offset: 0,
                detail: format!("node {:?} is not a directory", index_of(parent)?),
                bytes: forensic_vfs::SmallHex::new(&[]),
            });
        }
        for &child in &node.children {
            if let Some(c) = self.nodes.get(usize::try_from(child).unwrap_or(usize::MAX)) {
                if c.name == name {
                    return Ok(Some(FileId::Opaque(child)));
                }
            }
        }
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let idx = index_of(ino)?;
        let node = self.node_of(ino)?;
        Ok(FsMeta {
            ino: idx,
            kind: node.kind,
            allocated: Allocation::Allocated,
            size: node.size,
            nlink: 1,
            // The reader does not surface uid/gid/mode.
            uid: None,
            gid: None,
            mode: None,
            times: MacbTimes {
                modified: node.modified,
                accessed: node.accessed,
                // ZIP has no inode-change time; the extra-field "ctime" is creation.
                changed: None,
                born: node.born,
            },
            streams: Vec::new(),
            residency: ResidencyKind::NonResident,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let idx = index_of(ino)?;
        require_default_stream(stream)?;
        // Validate the node exists / is a file; a directory (or the root) has no
        // extractable data and reads as 0.
        let (kind, entry_idx) = {
            let node = self.node_of(ino)?;
            (node.kind, node.entry_idx)
        };
        if kind != NodeKind::File {
            return Ok(0);
        }
        let Some(entry_idx) = entry_idx else {
            return Ok(0); // cov:unreachable: a File node always carries a backing entry
        };
        let data = self.content(idx, entry_idx)?;
        let Ok(start) = usize::try_from(off) else {
            return Ok(0);
        };
        if start >= data.len() {
            return Ok(0);
        }
        let n = (data.len() - start).min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(start..start + n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }

    fn read_link(&self, ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        // Validate the id (loud on a bad FileId), then report no target: the reader
        // does not surface symlink targets (matching the AD1 / DAR adapters).
        self.node_of(ino)?;
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::process::Command;

    use forensic_vfs::{
        Allocation, FileId, FileSystem, FsKind, NodeKind, RunAlloc, StreamId, TimeZonePolicy,
    };

    use super::ZipVfs;

    /// The multi-KB payload written into `sub/big.bin` — a compressible pattern so
    /// the minted entry is DEFLATE-compressed, exercising decode + offset reads.
    fn big_payload() -> Vec<u8> {
        (0..8192u32).map(|i| (i % 251) as u8).collect()
    }

    /// The oracle archive, minted by Info-ZIP and committed to the repository.
    ///
    /// This used to shell out to the system `zip` at test time and return `None`
    /// when it was absent, so nine tests carried a skip arm. Those arms were
    /// unreachable on any machine that HAS `zip` — which is every CI runner — so
    /// the coverage gate could never satisfy them, and they could not honestly be
    /// marked `cov:unreachable` either, because they are genuinely reachable.
    ///
    /// Committing the bytes keeps the property that mattered — the container is
    /// authored by Info-ZIP, not by our own writer, so a decode bug cannot pass
    /// by agreeing with itself — while making the suite satisfiable from
    /// committed bytes alone, with no installed tool. Provenance and the exact
    /// minting command are in tests/data/README.md.
    fn mint_zip() -> Option<Vec<u8>> {
        Some(include_bytes!("../../tests/data/oracle-infozip.zip").to_vec())
    }

    /// Open the minted archive through the adapter, or `None` to skip.
    fn open() -> Option<ZipVfs<Cursor<Vec<u8>>>> {
        let bytes = mint_zip()?;
        Some(ZipVfs::open(Cursor::new(bytes)).expect("open minted zip"))
    }

    /// Resolve a `/`-separated path from the synthetic root via `lookup`.
    fn resolve(fs: &ZipVfs<Cursor<Vec<u8>>>, parts: &[&[u8]]) -> FileId {
        let mut id = fs.root();
        for p in parts {
            id = fs.lookup(id, p).expect("lookup").expect("present");
        }
        id
    }

    /// Drain a file to EOF by looping `read_at` with a small buffer.
    fn read_all(fs: &ZipVfs<Cursor<Vec<u8>>>, id: FileId) -> Vec<u8> {
        let mut out = Vec::new();
        let mut off = 0u64;
        loop {
            let mut buf = [0u8; 8];
            let n = fs
                .read_at(id, StreamId::Default, off, &mut buf)
                .expect("read_at");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            off += n as u64;
        }
        out
    }

    #[test]
    fn kind_root_zone_and_sectors() {
        let fs = open().expect("committed oracle fixture must load");
        assert_eq!(fs.kind(), FsKind::Other);
        assert!(matches!(fs.root(), FileId::Opaque(0)));
        // The surfaced Info-ZIP / NTFS extended-timestamp extra fields are UTC.
        assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
        let ss = fs.sector_sizes();
        assert_eq!(ss.logical, 512);
        assert_eq!(ss.cluster_or_block, 512);
        assert!(ss.physical >= 512);
        assert_eq!(fs.meta(fs.root()).expect("root meta").kind, NodeKind::Dir);
    }

    #[test]
    fn lists_root_entries() {
        let fs = open().expect("committed oracle fixture must load");
        let names: Vec<Vec<u8>> = fs
            .read_dir(fs.root())
            .expect("read_dir root")
            .map(|e| e.expect("entry").name)
            .collect();
        assert!(names.iter().any(|n| n == b"hello.txt"), "got {names:?}");
        assert!(names.iter().any(|n| n == b"sub"), "got {names:?}");
    }

    #[test]
    fn resolves_and_reads_hello() {
        let fs = open().expect("committed oracle fixture must load");
        let id = resolve(&fs, &[b"hello.txt"]);
        let m = fs.meta(id).expect("meta");
        assert_eq!(m.kind, NodeKind::File);
        assert_eq!(m.size, b"hello zip\n".len() as u64);
        assert_eq!(m.allocated, Allocation::Allocated);
        // ZIP records no inode-change time; Info-ZIP stamps a modified time.
        assert!(m.times.changed.is_none());
        assert!(m.times.modified.is_some(), "Info-ZIP stamps mtime");
        assert_eq!(read_all(&fs, id), b"hello zip\n");
    }

    #[test]
    fn reads_big_file_spanning_and_offset() {
        let fs = open().expect("committed oracle fixture must load");
        let id = resolve(&fs, &[b"sub", b"big.bin"]);
        let want = big_payload();
        assert_eq!(fs.meta(id).expect("meta").size, want.len() as u64);
        assert_eq!(read_all(&fs, id), want);
        // A mid-stream offset read returns the right slice.
        let mut buf = [0u8; 16];
        let n = fs
            .read_at(id, StreamId::Default, 4096, &mut buf)
            .expect("read");
        assert_eq!(&buf[..n], &want[4096..4096 + n]);
    }

    #[test]
    fn directory_reports_dir_kind() {
        let fs = open().expect("committed oracle fixture must load");
        let id = resolve(&fs, &[b"sub"]);
        assert_eq!(fs.meta(id).expect("meta").kind, NodeKind::Dir);
        assert!(fs.read_dir(id).is_ok());
    }

    #[test]
    fn extents_hello_single_run_and_root() {
        let fs = open().expect("committed oracle fixture must load");
        let id = resolve(&fs, &[b"hello.txt"]);
        let runs: Vec<_> = fs
            .extents(id, StreamId::Default)
            .expect("extents")
            .map(|r| r.expect("run"))
            .collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run.len, b"hello zip\n".len() as u64);
        assert_eq!(runs[0].alloc, RunAlloc::Allocated);
        let root_runs: Vec<_> = fs
            .extents(fs.root(), StreamId::Default)
            .expect("root extents")
            .map(|r| r.expect("run"))
            .collect();
        assert!(root_runs.len() <= 1);
    }

    #[test]
    fn wrong_file_id_and_stream_are_loud() {
        let fs = open().expect("committed oracle fixture must load");
        let bad = FileId::NtfsRef { entry: 5, seq: 1 };
        assert!(fs.meta(bad).is_err());
        assert!(fs.read_dir(bad).is_err());
        assert!(fs.lookup(bad, b"x").is_err());
        assert!(fs.read_link(bad, 8).is_err());
        // An out-of-range node index is refused.
        assert!(fs.meta(FileId::Opaque(9_999_999)).is_err());
        // A named stream is refused.
        let id = resolve(&fs, &[b"hello.txt"]);
        assert!(fs
            .read_at(id, StreamId::Named(1), 0, &mut [0u8; 4])
            .is_err());
        assert!(fs.extents(id, StreamId::Named(1)).is_err());
        // read_dir on a file is loud.
        assert!(fs.read_dir(id).is_err());
    }

    #[test]
    fn lookup_missing_is_none() {
        let fs = open().expect("committed oracle fixture must load");
        assert!(fs
            .lookup(fs.root(), b"NOPE.NOTPRESENT")
            .expect("lookup")
            .is_none());
    }

    #[test]
    fn empty_forensic_surfaces() {
        let fs = open().expect("committed oracle fixture must load");
        assert_eq!(fs.deleted().expect("deleted").count(), 0);
        assert_eq!(fs.unallocated().expect("unallocated").count(), 0);
        let id = resolve(&fs, &[b"hello.txt"]);
        assert!(fs.read_link(id, 4096).expect("read_link").is_empty());
    }
}
