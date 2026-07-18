//! PKWARE `SecureZIP` strong encryption — password-based AES decryption.
//!
//! The in-scope case is the *password* branch of PKWARE strong encryption
//! (GP-flag bit 6) with an AES algorithm id (0x660E/0x660F/0x6610). Every other
//! strong variant — certificate-based, 3DES-ERD, non-AES — stays refused loud.
//!
//! Tier-1 ground truth: the committed `securezip-strong-aes256-pw.expected` is
//! the byte-exact output of `7zz x -so -p'Sr0ninPass!'` on the fixture (captured
//! at commit time; the env-gated `oracle_7zz_matches` test re-derives it live
//! when `7zz` is present, so the committed bytes cannot silently drift).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read};

use zip_core::{ZipArchive, ZipCoreError};

const FIXTURE: &[u8] = include_bytes!("data/securezip-strong-aes256-pw.zip");
const EXPECTED: &[u8] = include_bytes!("data/securezip-strong-aes256-pw.expected");
const SIGNED: &[u8] = include_bytes!("data/securezip-strong-signed.zip");
const PASSWORD: &[u8] = b"Sr0ninPass!";

fn decrypt(zip: &[u8], name: &str, password: &[u8]) -> Result<Vec<u8>, ZipCoreError> {
    let mut ar = ZipArchive::new(Cursor::new(zip.to_vec()))?;
    let mut f = ar.by_name_decrypt(name, password)?;
    let mut out = Vec::new();
    f.read_to_end(&mut out).map_err(|e| {
        // Surface the inner ZipCoreError (WrongPassword/CRC) that ZipFile wraps in
        // io::Error::other, so callers can match on the typed variant.
        match e
            .into_inner()
            .and_then(|b| b.downcast::<ZipCoreError>().ok())
        {
            Some(inner) => *inner,
            None => ZipCoreError::WrongPassword(name.to_string()),
        }
    })?;
    Ok(out)
}

#[test]
fn decrypts_fixture_byte_for_byte_vs_oracle() {
    let out = decrypt(FIXTURE, "secret.txt", PASSWORD).expect("must decrypt");
    assert_eq!(
        out, EXPECTED,
        "decrypted bytes must equal the 7zz -so ground truth"
    );
}

#[test]
fn wrong_password_refuses_loud() {
    let err = decrypt(FIXTURE, "secret.txt", b"WrongPass!").unwrap_err();
    assert!(
        matches!(err, ZipCoreError::WrongPassword(_)),
        "a wrong password must fail loud (WrongPassword), got {err:?}"
    );
}

#[test]
fn certificate_variant_stays_refused() {
    // securezip-strong-signed.zip uses the *certificate* strong variant — with no
    // private key it must stay refused loud, never mis-decoded.
    let mut ar = ZipArchive::new(Cursor::new(SIGNED.to_vec())).unwrap();
    let name = ar.file_names().next().unwrap().to_string();
    let res = ar.by_name_decrypt(&name, PASSWORD).map(|_| ());
    assert!(
        matches!(res, Err(ZipCoreError::UnsupportedEncryption { .. })),
        "certificate strong encryption must stay refused, got {res:?}"
    );
}

/// Tier-1 differential: when `7zz` is available, prove the committed `.expected`
/// bytes really are 7-Zip's output (closes the loop so the oracle file can't be
/// fudged). Skips cleanly when the tool is absent — the committed-bytes gate
/// above does not depend on it.
#[test]
fn oracle_7zz_matches_expected() {
    use std::process::Command;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest}/tests/data/securezip-strong-aes256-pw.zip");
    let out = match Command::new("7zz")
        .args(["x", "-so", "-p", "Sr0ninPass!", &path])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => {
            eprintln!("skipping: 7zz not available");
            return;
        }
    };
    assert_eq!(
        out, EXPECTED,
        "committed .expected must equal live 7zz output"
    );
}

// ── Self-encoded round-trips (code-path coverage) ─────────────────────────────
//
// The AES-256 Store fixture above is the Tier-1 correctness oracle (checked vs
// 7-Zip). The helpers below mint strong-encryption entries with the SAME audited
// primitives to reach the code paths a single real fixture cannot — AES-128/192,
// the Deflate branch, and the IVSize-0 IV derivation. They are self-consistent
// round-trips (Tier-3): they prove the decoder handles those code paths, while
// the real fixture proves the crypto is actually correct.
mod mint {
    use aes::cipher::generic_array::GenericArray;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use sha1::{Digest, Sha1};

    fn sha1_of(parts: &[&[u8]]) -> [u8; 20] {
        let mut h = Sha1::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    fn dk_half(d: &[u8; 20], c: u8) -> [u8; 20] {
        let mut b = [c; 64];
        for (x, y) in b.iter_mut().zip(d.iter()) {
            *x ^= *y;
        }
        sha1_of(&[&b])
    }

    fn derive_key(d: &[u8; 20], ks: usize) -> Vec<u8> {
        let mut k = Vec::new();
        k.extend_from_slice(&dk_half(d, 0x36));
        k.extend_from_slice(&dk_half(d, 0x5C));
        k.truncate(ks);
        k
    }

    fn cbc_encrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        macro_rules! run {
            ($t:ty) => {{
                let mut e = cbc::Encryptor::<$t>::new_from_slices(key, iv).unwrap();
                for c in out.chunks_exact_mut(16) {
                    e.encrypt_block_mut(GenericArray::from_mut_slice(c));
                }
            }};
        }
        match key.len() {
            16 => run!(aes::Aes128),
            24 => run!(aes::Aes192),
            _ => run!(aes::Aes256),
        }
        out
    }

    fn crc32(d: &[u8]) -> u32 {
        let mut h = crc32fast::Hasher::new();
        h.update(d);
        h.finalize()
    }

    fn deflate(d: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }

    /// The strong-encryption entry data (decryption header ‖ file ciphertext) for a
    /// key size (16/24/32), method (0=Store, 8=Deflate), and `IVSize` mode, plus the
    /// entry's CRC-32 and uncompressed size.
    pub fn entry(
        method: u16,
        key_size: usize,
        iv0: bool,
        plaintext: &[u8],
        password: &[u8],
    ) -> (Vec<u8>, u32, u32) {
        let compressed = if method == 0 {
            plaintext.to_vec()
        } else {
            deflate(plaintext)
        };
        let crc = crc32(plaintext);
        let mut iv = [0u8; 16];
        let iv_used;
        if iv0 {
            iv[0..4].copy_from_slice(&crc.to_le_bytes());
            iv[4..12].copy_from_slice(&(plaintext.len() as u64).to_le_bytes());
            iv_used = 12;
        } else {
            iv = [0x24u8; 16];
            iv_used = 16;
        }
        let master = derive_key(&sha1_of(&[password]), key_size);
        let rd = [0xABu8; 16];
        let mut erd_plain = rd.to_vec();
        erd_plain.extend_from_slice(&[0x10u8; 16]);
        let erd = cbc_encrypt(&master, &iv, &erd_plain);
        let file_key = derive_key(&sha1_of(&[&iv[..iv_used], &rd]), key_size);
        let v = [0xCDu8; 12];
        let mut vdata_plain = v.to_vec();
        vdata_plain.extend_from_slice(&crc32(&v).to_le_bytes());
        let vdata = cbc_encrypt(&file_key, &iv, &vdata_plain);
        let mut file_iv = [0u8; 16];
        file_iv.copy_from_slice(&vdata[vdata.len() - 16..]);
        let pad = (16 - compressed.len() % 16) % 16;
        let mut padded = compressed.clone();
        padded.resize(padded.len() + pad, 0);
        let file_cipher = cbc_encrypt(&file_key, &file_iv, &padded);

        let alg_id = 0x660Eu16 + ((key_size - 16) / 8) as u16;
        let mut rem = Vec::new();
        rem.extend_from_slice(&3u16.to_le_bytes()); // Format
        rem.extend_from_slice(&alg_id.to_le_bytes()); // AlgID
        rem.extend_from_slice(&((key_size * 8) as u16).to_le_bytes()); // Bitlen
        rem.extend_from_slice(&1u16.to_le_bytes()); // Flags = password
        rem.extend_from_slice(&(erd.len() as u16).to_le_bytes()); // ErdSize
        rem.extend_from_slice(&erd);
        rem.extend_from_slice(&0u32.to_le_bytes()); // Reserved1
        rem.extend_from_slice(&(vdata.len() as u16).to_le_bytes()); // VSize
        rem.extend_from_slice(&vdata);

        let mut data = Vec::new();
        data.extend_from_slice(&(if iv0 { 0u16 } else { 16u16 }).to_le_bytes()); // IVSize
        if !iv0 {
            data.extend_from_slice(&iv);
        }
        data.extend_from_slice(&(rem.len() as u32).to_le_bytes()); // Size
        data.extend_from_slice(&rem);
        data.extend_from_slice(&file_cipher);
        (data, crc, plaintext.len() as u32)
    }

    /// Wrap arbitrary entry data in a one-entry ZIP flagged encrypted (bit 0) +
    /// strong (bit 6), with the given method and sizes.
    pub fn zip_around(method: u16, crc: u32, uncompressed: u32, data: &[u8]) -> Vec<u8> {
        let name = b"secret.txt";
        let flags = 0x0041u16;
        let mut o = Vec::new();
        o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        o.extend_from_slice(&51u16.to_le_bytes());
        o.extend_from_slice(&flags.to_le_bytes());
        o.extend_from_slice(&method.to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes()); // mod time/date
        o.extend_from_slice(&crc.to_le_bytes());
        o.extend_from_slice(&(data.len() as u32).to_le_bytes());
        o.extend_from_slice(&uncompressed.to_le_bytes());
        o.extend_from_slice(&(name.len() as u16).to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        o.extend_from_slice(name);
        o.extend_from_slice(data);
        let cd = o.len();
        o.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        o.extend_from_slice(&51u16.to_le_bytes());
        o.extend_from_slice(&51u16.to_le_bytes());
        o.extend_from_slice(&flags.to_le_bytes());
        o.extend_from_slice(&method.to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes());
        o.extend_from_slice(&crc.to_le_bytes());
        o.extend_from_slice(&(data.len() as u32).to_le_bytes());
        o.extend_from_slice(&uncompressed.to_le_bytes());
        o.extend_from_slice(&(name.len() as u16).to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes()); // extra
        o.extend_from_slice(&0u16.to_le_bytes()); // comment
        o.extend_from_slice(&0u16.to_le_bytes()); // disk start
        o.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        o.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        o.extend_from_slice(&0u32.to_le_bytes()); // lfh offset
        o.extend_from_slice(name);
        let cd_size = o.len() - cd;
        o.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        o.extend_from_slice(&0u32.to_le_bytes()); // disks
        o.extend_from_slice(&1u16.to_le_bytes());
        o.extend_from_slice(&1u16.to_le_bytes());
        o.extend_from_slice(&(cd_size as u32).to_le_bytes());
        o.extend_from_slice(&(cd as u32).to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        o
    }

    /// Mint a full one-entry strong-encryption ZIP for the given parameters.
    pub fn zip(
        method: u16,
        key_size: usize,
        iv0: bool,
        plaintext: &[u8],
        password: &[u8],
    ) -> Vec<u8> {
        let (data, crc, uncompressed) = entry(method, key_size, iv0, plaintext, password);
        zip_around(method, crc, uncompressed, &data)
    }
}

const MINT_PW: &[u8] = b"m1nt-Pass!";

#[test]
fn roundtrip_all_key_sizes_and_methods() {
    let pt = b"the quick brown fox jumps over the lazy dog, 0123456789 padding..".to_vec();
    for key_size in [16usize, 24, 32] {
        for method in [0u16, 8] {
            let zip = mint::zip(method, key_size, false, &pt, MINT_PW);
            let out = decrypt(&zip, "secret.txt", MINT_PW)
                .unwrap_or_else(|e| panic!("ks={key_size} method={method}: {e:?}"));
            assert_eq!(out, pt, "ks={key_size} method={method}");
        }
    }
}

#[test]
fn roundtrip_ivsize_zero_derives_iv() {
    let pt = b"IVSize=0 derives the IV from crc and uncompressed size".to_vec();
    let zip = mint::zip(0, 32, true, &pt, MINT_PW);
    assert_eq!(decrypt(&zip, "secret.txt", MINT_PW).unwrap(), pt);
}

#[test]
fn minted_wrong_password_refuses() {
    let zip = mint::zip(0, 32, false, b"secret payload!!", MINT_PW);
    assert!(matches!(
        decrypt(&zip, "secret.txt", b"not-the-pw"),
        Err(ZipCoreError::WrongPassword(_))
    ));
}

/// Corrupting a validation-blob byte makes the `VData` CRC-32 gate fail (the second
/// wrong-password gate, distinct from the ERD pad-block gate).
#[test]
fn corrupt_validation_blob_fails_crc_gate() {
    let pt = b"payload for the vdata gate".to_vec();
    let (mut data, crc, uncompressed) = mint::entry(0, 32, false, &pt, MINT_PW);
    // VData sits at the end of the decryption header, before the file ciphertext.
    // Layout (iv16): IVSize2 IV16 Size4 [Format2 AlgID2 Bitlen2 Flags2 ErdSize2
    // ERD32 Reserved4 VSize2 VData16] → VData starts at 22 + 48 = 70.
    data[70] ^= 0xFF;
    let zip = mint::zip_around(0, crc, uncompressed, &data);
    assert!(matches!(
        decrypt(&zip, "secret.txt", MINT_PW),
        Err(ZipCoreError::WrongPassword(_))
    ));
}

/// Every out-of-scope decryption-header shape must be refused loud. Each case
/// patches one field of an otherwise-valid AES-256 header (iv16 layout).
#[test]
fn malformed_headers_refuse_loud() {
    let pt = b"sixteen bytes...".to_vec();
    let base = || mint::entry(0, 32, false, &pt, MINT_PW);
    // (byte offset, value, label) — offsets in the entry-data / decryption header.
    let cases: &[(usize, u8, &str)] = &[
        (0, 8, "IVSize neither 0 nor 16"),
        (18, 8, "Size (rem) below 16"),
        (22, 2, "Format != 3"),
        (24, 0x00, "AlgID below AES range"), // 0x0000
        (26, 0xFF, "BitLen mismatch"),
        (28, 0x00, "no password/cert flag"),   // clears bit 0
        (28, 0x02, "certificate flag"),        // sets bit 1, clears password bit
        (29, 0x40, "3DES-ERD flag"),           // sets 0x4000
        (30, 0x00, "ErdSize below one block"), // 0x00xx low byte -> 0
        (64, 1, "Reserved1 nonzero"),
        (68, 0x20, "VSize inconsistent"), // 32 != remaining 16
    ];
    for &(off, val, label) in cases {
        let (mut data, crc, uncompressed) = base();
        data[off] = val;
        let zip = mint::zip_around(0, crc, uncompressed, &data);
        assert!(
            matches!(
                decrypt(&zip, "secret.txt", MINT_PW),
                Err(ZipCoreError::UnsupportedEncryption { .. })
            ),
            "case '{label}' must refuse loud"
        );
    }
}

/// `AlgID` above the AES range, and an `ErdSize` that overflows the header, are also
/// refused (distinct branches from the cases above).
#[test]
fn algid_high_and_erd_overflow_refuse() {
    let pt = b"sixteen bytes...".to_vec();
    // AlgID 0x6620 (> 0x6610+2).
    let (mut d1, c1, u1) = mint::entry(0, 32, false, &pt, MINT_PW);
    d1[24] = 0x20;
    d1[25] = 0x66;
    let z1 = mint::zip_around(0, c1, u1, &d1);
    assert!(matches!(
        decrypt(&z1, "secret.txt", MINT_PW),
        Err(ZipCoreError::UnsupportedEncryption { .. })
    ));
    // ErdSize 0x0111 (273): 273 % 16 != 0 and would overrun.
    let (mut d2, c2, u2) = mint::entry(0, 32, false, &pt, MINT_PW);
    d2[30] = 0x11;
    d2[31] = 0x01;
    let z2 = mint::zip_around(0, c2, u2, &d2);
    assert!(matches!(
        decrypt(&z2, "secret.txt", MINT_PW),
        Err(ZipCoreError::UnsupportedEncryption { .. })
    ));
}
