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

    /// Mint a small ZIP with the system `zip` CLI (an independent oracle): a
    /// top-level file plus a nested subdirectory carrying a multi-KB file. Returns
    /// the archive bytes, or `None` when `zip` is unavailable (skip cleanly).
    fn mint_zip() -> Option<Vec<u8>> {
        let dir = tempfile::tempdir().ok()?;
        let root = dir.path();
        std::fs::write(root.join("hello.txt"), b"hello zip\n").ok()?;
        std::fs::create_dir(root.join("sub")).ok()?;
        std::fs::write(root.join("sub").join("nested.txt"), b"nested\n").ok()?;
        std::fs::write(root.join("sub").join("big.bin"), big_payload()).ok()?;
        let status = Command::new("zip")
            .args(["-r", "-q", "archive.zip", "hello.txt", "sub"])
            .current_dir(root)
            .status();
        match status {
            Ok(s) if s.success() => std::fs::read(root.join("archive.zip")).ok(),
            _ => None,
        }
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
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
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
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
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
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
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
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
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
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
        let id = resolve(&fs, &[b"sub"]);
        assert_eq!(fs.meta(id).expect("meta").kind, NodeKind::Dir);
        assert!(fs.read_dir(id).is_ok());
    }

    #[test]
    fn extents_hello_single_run_and_root() {
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
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
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
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
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
        assert!(fs
            .lookup(fs.root(), b"NOPE.NOTPRESENT")
            .expect("lookup")
            .is_none());
    }

    #[test]
    fn empty_forensic_surfaces() {
        let Some(fs) = open() else {
            eprintln!("skipping: `zip` CLI unavailable");
            return;
        };
        assert_eq!(fs.deleted().expect("deleted").count(), 0);
        assert_eq!(fs.unallocated().expect("unallocated").count(), 0);
        let id = resolve(&fs, &[b"hello.txt"]);
        assert!(fs.read_link(id, 4096).expect("read_link").is_empty());
    }
}
