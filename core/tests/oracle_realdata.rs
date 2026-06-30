//! Tier-2 validation against archives produced by independent third-party
//! engines (Info-ZIP `zip`, `7z`), with ground truth from an independent oracle
//! (the OS filesystem mtime the engine recorded). The engine and oracle are
//! independent, but *we* choose the scenario (trivial inputs, a 64 KiB split),
//! so this is tier-2, not tier-1 — it can miss real-world quirks we did not
//! construct. The committed real-world corpus in `realworld_corpus.rs` is the
//! tier-1 counterpart for the extra-field parsers. These tests mint archives at
//! run time and skip cleanly when the tools are absent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::path::Path;
use std::process::Command;
use std::time::UNIX_EPOCH;

use zip_core::{ZipArchive, ZipCoreError};

/// FILETIME epoch (1601-01-01) to Unix epoch (1970-01-01), in seconds.
const FILETIME_UNIX_DELTA_SECS: i64 = 11_644_473_600;

fn tool_available(cmd: &str, arg: &str) -> bool {
    Command::new(cmd)
        .arg(arg)
        .output()
        .is_ok_and(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
}

fn fs_mtime_secs(path: &Path) -> i64 {
    let m = std::fs::metadata(path).unwrap();
    i64::try_from(
        m.modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// A scratch directory under the OS temp dir; removed on drop.
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("zip_core_oracle_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn infozip_unix_timestamp_matches_filesystem_mtime() {
    if !tool_available("zip", "-v") {
        eprintln!("skip: Info-ZIP `zip` not available");
        return;
    }
    let s = Scratch::new("ut");
    let src = s.path().join("payload.txt");
    std::fs::write(&src, b"hello").unwrap();
    let expected = fs_mtime_secs(&src);

    let status = Command::new("zip")
        .arg("-q")
        .arg("out.zip")
        .arg("payload.txt")
        .current_dir(s.path())
        .status()
        .unwrap();
    assert!(status.success(), "zip should succeed");

    let bytes = std::fs::read(s.path().join("out.zip")).unwrap();
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let extra = ar.structural_view().unwrap()[0].extra.clone();

    // Info-ZIP writes the Unix extended-timestamp extra (0x5455). The mtime it
    // records is the source file's mtime — our independent ground truth.
    let got = extra
        .unix_mtime
        .expect("Info-ZIP zip records a 0x5455 Unix mtime");
    assert!(
        (i64::from(got) - expected).abs() <= 2,
        "parsed unix_mtime {got} should match filesystem mtime {expected}"
    );
}

#[test]
fn sevenzip_ntfs_filetime_matches_filesystem_mtime() {
    if !tool_available("7z", "i") && !tool_available("7za", "i") {
        eprintln!("skip: 7z not available");
        return;
    }
    let bin = if tool_available("7z", "i") {
        "7z"
    } else {
        "7za"
    };
    let s = Scratch::new("ntfs");
    let src = s.path().join("payload.txt");
    std::fs::write(&src, b"hello").unwrap();
    let expected = fs_mtime_secs(&src);

    let out = Command::new(bin)
        .arg("a")
        .arg("-tzip")
        .arg("out.zip")
        .arg("payload.txt")
        .current_dir(s.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "7z should succeed: {out:?}");

    let bytes = std::fs::read(s.path().join("out.zip")).unwrap();
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let extra = ar.structural_view().unwrap()[0].extra.clone();

    // 7z writes the NTFS FileTimes extra (0x000a) as Windows FILETIME ticks.
    let ticks = extra
        .ntfs_mtime
        .expect("7z records a 0x000a NTFS FILETIME mtime");
    let got_unix = i64::try_from(ticks).unwrap() / 10_000_000 - FILETIME_UNIX_DELTA_SECS;
    assert!(
        (got_unix - expected).abs() <= 2,
        "parsed NTFS mtime {got_unix}s should match filesystem mtime {expected}s"
    );
}

#[test]
fn infozip_split_archive_fails_loud_on_every_entry() {
    if !tool_available("zip", "-v") {
        eprintln!("skip: Info-ZIP `zip` not available");
        return;
    }
    let s = Scratch::new("split");
    // A payload large enough to force a split at the 64 KiB minimum. It must be
    // incompressible, or deflate shrinks it back under one segment — use a cheap
    // LCG so the bytes don't compress (no extra dependency, fully deterministic).
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let big: Vec<u8> = (0..200_000)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 33) as u8
        })
        .collect();
    std::fs::write(s.path().join("big.bin"), &big).unwrap();
    std::fs::write(s.path().join("small.txt"), b"second").unwrap();

    let status = Command::new("zip")
        .arg("-q")
        .arg("-s")
        .arg("64k")
        .arg("split.zip")
        .arg("big.bin")
        .arg("small.txt")
        .current_dir(s.path())
        .status()
        .unwrap();
    assert!(status.success(), "zip -s should succeed");

    // Confirm it actually split (segments exist), else the test proves nothing.
    assert!(
        s.path().join("split.z01").exists(),
        "expected a real multi-segment split archive"
    );

    let bytes = std::fs::read(s.path().join("split.zip")).unwrap();
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    // Enumeration works (the CD is wholly present on the last segment)…
    assert!(!ar.is_empty());
    // …but every data read must fail loud: we hold only the last segment.
    for i in 0..ar.len() {
        assert!(
            matches!(ar.by_index(i), Err(ZipCoreError::SpannedArchive { .. })),
            "entry {i} of a real split archive must fail loud, not read wrong bytes"
        );
    }
}
