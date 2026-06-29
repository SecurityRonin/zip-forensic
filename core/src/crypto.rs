//! Entry decryption: traditional ZipCrypto and WinZip AES (method 99).
//!
//! ZipCrypto is the ZIP format's own legacy stream cipher — there is no audited
//! crate for it, so it is implemented here per the PKWARE APPNOTE (decrypt-only).
//! WinZip AES is built ENTIRELY on audited RustCrypto primitives (`aes`, `ctr`,
//! `hmac`, `sha1`, `pbkdf2`) — no cryptographic primitive is hand-rolled
//! (CLAUDE.md crypto rule). Both are decrypt-only.

use std::io::{self, Read};

use crate::ZipCoreError;

// ───────────────────────── ZipCrypto (traditional PKWARE) ─────────────────────

/// A `Read` adapter that decrypts a traditional-ZipCrypto stream on the fly.
pub(crate) struct ZipCryptoReader<R> {
    inner: R,
    key0: u32,
    key1: u32,
    key2: u32,
}

impl<R: Read> ZipCryptoReader<R> {
    /// Initialise from the password, consume + verify the 12-byte encryption
    /// header, and leave `inner` positioned at the ciphertext. `check_byte` is the
    /// password-verification byte (CRC high byte, or mod-time high byte when the
    /// entry uses a data descriptor).
    pub(crate) fn new(
        inner: R,
        password: &[u8],
        check_byte: u8,
        entry: &str,
    ) -> Result<Self, ZipCoreError> {
        let mut r = ZipCryptoReader {
            inner,
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        };
        for &b in password {
            r.update(b);
        }
        let mut header = [0u8; 12];
        r.inner.read_exact(&mut header)?;
        for byte in &mut header {
            *byte = r.decrypt_byte(*byte);
        }
        if header[11] != check_byte {
            return Err(ZipCoreError::WrongPassword(entry.to_string()));
        }
        Ok(r)
    }

    fn update(&mut self, b: u8) {
        self.key0 = crc32_byte(self.key0, b);
        self.key1 = self
            .key1
            .wrapping_add(self.key0 & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.key2 = crc32_byte(self.key2, (self.key1 >> 24) as u8);
    }

    fn decrypt_byte(&mut self, cipher: u8) -> u8 {
        let temp = ((self.key2 | 2) & 0xffff) as u16;
        let keystream = ((u32::from(temp).wrapping_mul(u32::from(temp ^ 1))) >> 8) as u8;
        let plain = cipher ^ keystream;
        self.update(plain);
        plain
    }
}

impl<R: Read> Read for ZipCryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for byte in &mut buf[..n] {
            *byte = self.decrypt_byte(*byte);
        }
        Ok(n)
    }
}

/// One byte of CRC-32 (IEEE) update — the keystream feedback for ZipCrypto.
fn crc32_byte(crc: u32, b: u8) -> u32 {
    let mut c = (crc ^ u32::from(b)) & 0xff;
    for _ in 0..8 {
        c = if c & 1 != 0 {
            (c >> 1) ^ 0xEDB8_8320
        } else {
            c >> 1
        };
    }
    (crc >> 8) ^ c
}

// ───────────────────────────── WinZip AES (method 99) ─────────────────────────

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// Parsed AE-x extra field (header id 0x9901).
#[derive(Debug, Clone, Copy)]
pub(crate) struct AesInfo {
    /// AES key strength: 1 = 128-bit, 2 = 192-bit, 3 = 256-bit.
    pub(crate) strength: u8,
    /// The real compression method applied before encryption.
    pub(crate) actual_method: u16,
    /// Vendor version 2 (AE-2) omits the CRC; version 1 (AE-1) keeps it.
    pub(crate) is_ae2: bool,
}

/// Salt length in bytes for an AES strength code.
fn salt_len(strength: u8) -> usize {
    match strength {
        1 => 8,
        2 => 12,
        _ => 16,
    }
}

/// AES key length in bytes for a strength code.
fn key_len(strength: u8) -> usize {
    match strength {
        1 => 16,
        2 => 24,
        _ => 32,
    }
}

/// A `Read` adapter that decrypts a WinZip-AES stream (AES-CTR) and verifies the
/// trailing HMAC-SHA1 authentication code at EOF.
pub(crate) struct AesReader<R> {
    inner: R,
    cipher: AesCtr,
    hmac: HmacSha1,
    /// Ciphertext bytes still to read (excludes the 10-byte auth code).
    remaining: u64,
    entry: String,
    done: bool,
}

/// AES-CTR keystream with a little-endian counter starting at 1 (the WinZip
/// convention), keyed by 128/192/256-bit keys. Built on the audited `aes`/`ctr`
/// crates — never hand-rolled.
enum AesCtr {
    A128(ctr::Ctr128LE<aes::Aes128>),
    A192(ctr::Ctr128LE<aes::Aes192>),
    A256(ctr::Ctr128LE<aes::Aes256>),
}

impl AesCtr {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            AesCtr::A128(c) => c.apply_keystream(buf),
            AesCtr::A192(c) => c.apply_keystream(buf),
            AesCtr::A256(c) => c.apply_keystream(buf),
        }
    }
}

impl<R: Read> AesReader<R> {
    pub(crate) fn new(
        mut inner: R,
        password: &[u8],
        info: AesInfo,
        compressed_size: u64,
        entry: &str,
    ) -> Result<Self, ZipCoreError> {
        let klen = key_len(info.strength);
        let slen = salt_len(info.strength);
        // salt + 2-byte password verifier + ciphertext + 10-byte auth code.
        let overhead = slen as u64 + 2 + 10;
        if compressed_size < overhead {
            return Err(ZipCoreError::UnsupportedEncryption {
                entry: entry.to_string(),
                reason: "AES entry too small for salt/verifier/auth".to_string(),
            });
        }
        let mut salt = vec![0u8; slen];
        inner.read_exact(&mut salt)?;
        let mut pwd_verify = [0u8; 2];
        inner.read_exact(&mut pwd_verify)?;

        // PBKDF2-HMAC-SHA1, 1000 iterations -> enc key | mac key | 2-byte verifier.
        let mut derived = vec![0u8; 2 * klen + 2];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &salt, 1000, &mut derived);
        let enc_key = &derived[..klen];
        let mac_key = &derived[klen..2 * klen];
        let derived_verify = &derived[2 * klen..2 * klen + 2];
        if !constant_time_eq::constant_time_eq(derived_verify, &pwd_verify) {
            return Err(ZipCoreError::WrongPassword(entry.to_string()));
        }

        // WinZip AES counter: 16 bytes, little-endian, starting at 1.
        let iv = 1u128.to_le_bytes();
        let cipher = match info.strength {
            1 => AesCtr::A128(ctr::Ctr128LE::<aes::Aes128>::new(
                enc_key.into(),
                (&iv).into(),
            )),
            2 => AesCtr::A192(ctr::Ctr128LE::<aes::Aes192>::new(
                enc_key.into(),
                (&iv).into(),
            )),
            _ => AesCtr::A256(ctr::Ctr128LE::<aes::Aes256>::new(
                enc_key.into(),
                (&iv).into(),
            )),
        };
        // HMAC-SHA1 accepts a key of any length, so `new_from_slice` is infallible
        // here; there is no error arm to handle (or leave uncovered).
        #[allow(clippy::unwrap_used)]
        let hmac = <HmacSha1 as Mac>::new_from_slice(mac_key).unwrap();

        Ok(Self {
            inner,
            cipher,
            hmac,
            remaining: compressed_size - overhead,
            entry: entry.to_string(),
            done: false,
        })
    }

    /// Read the trailing 10-byte auth code and verify it against the HMAC.
    fn finish(&mut self) -> io::Result<()> {
        let mut code = [0u8; 10];
        self.inner.read_exact(&mut code)?;
        let computed = self.hmac.clone().finalize().into_bytes();
        if !constant_time_eq::constant_time_eq(&computed[..10], &code) {
            return Err(io::Error::other(ZipCoreError::WrongPassword(
                self.entry.clone(),
            )));
        }
        Ok(())
    }
}

impl<R: Read> Read for AesReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            if !self.done {
                self.done = true;
                self.finish()?;
            }
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            // Truncated ciphertext: cannot authenticate.
            return Err(io::Error::other(ZipCoreError::WrongPassword(
                self.entry.clone(),
            )));
        }
        // HMAC is computed over the CIPHERTEXT, then we decrypt in place.
        self.hmac.update(&buf[..n]);
        self.cipher.apply(&mut buf[..n]);
        self.remaining -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::Cursor;

    /// Build a valid WinZip-AES stream (salt + verifier + ciphertext + auth) for a
    /// given strength, using the same RustCrypto primitives — exercises every
    /// strength arm and gives a base to corrupt for the fail-loud paths.
    fn build_aes_stream(strength: u8, password: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let klen = key_len(strength);
        let slen = salt_len(strength);
        let salt = vec![0x11u8; slen];
        let mut derived = vec![0u8; 2 * klen + 2];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &salt, 1000, &mut derived);
        let enc_key = &derived[..klen];
        let mac_key = &derived[klen..2 * klen];
        let verify = &derived[2 * klen..2 * klen + 2];
        let iv = 1u128.to_le_bytes();
        let mut ct = plaintext.to_vec();
        let mut cipher = match strength {
            1 => AesCtr::A128(ctr::Ctr128LE::<aes::Aes128>::new(
                enc_key.into(),
                (&iv).into(),
            )),
            2 => AesCtr::A192(ctr::Ctr128LE::<aes::Aes192>::new(
                enc_key.into(),
                (&iv).into(),
            )),
            _ => AesCtr::A256(ctr::Ctr128LE::<aes::Aes256>::new(
                enc_key.into(),
                (&iv).into(),
            )),
        };
        cipher.apply(&mut ct);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(mac_key).unwrap();
        mac.update(&ct);
        let auth = mac.finalize().into_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(verify);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&auth[..10]);
        out
    }

    fn info(strength: u8) -> AesInfo {
        AesInfo {
            strength,
            actual_method: 0,
            is_ae2: true,
        }
    }

    #[test]
    fn aes_decrypts_all_strengths() {
        let pw = b"correct horse";
        let pt: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        for strength in [1u8, 2, 3] {
            let s = build_aes_stream(strength, pw, &pt);
            let mut r = AesReader::new(
                Cursor::new(s.clone()),
                pw,
                info(strength),
                s.len() as u64,
                "e",
            )
            .unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            assert_eq!(out, pt, "strength {strength}");
        }
    }

    #[test]
    fn aes_entry_too_small_errors() {
        // Below salt+verifier+auth overhead.
        assert!(AesReader::new(Cursor::new(vec![0u8; 5]), b"pw", info(3), 5, "e").is_err());
    }

    #[test]
    fn aes_corrupt_ciphertext_fails_hmac() {
        let pw = b"pw";
        let pt = b"the quick brown fox".repeat(8);
        let mut s = build_aes_stream(3, pw, &pt);
        s[20] ^= 0xFF; // flip a ciphertext byte (after salt16 + verify2)
        let mut r =
            AesReader::new(Cursor::new(s.clone()), pw, info(3), s.len() as u64, "e").unwrap();
        let mut out = Vec::new();
        assert!(
            r.read_to_end(&mut out).is_err(),
            "HMAC must reject corrupted ciphertext"
        );
    }

    #[test]
    fn aes_truncated_ciphertext_errors() {
        let pw = b"pw";
        let pt = b"data".repeat(40);
        let s = build_aes_stream(3, pw, &pt);
        // Claim more ciphertext than the stream actually contains.
        let mut r = AesReader::new(
            Cursor::new(s.clone()),
            pw,
            info(3),
            s.len() as u64 + 64,
            "e",
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(
            r.read_to_end(&mut out).is_err(),
            "truncated ciphertext must error"
        );
    }

    #[test]
    fn aes_wrong_password_fails_verifier() {
        let pw = b"right";
        let pt = b"secret".to_vec();
        let s = build_aes_stream(3, pw, &pt);
        assert!(AesReader::new(
            Cursor::new(s.clone()),
            b"wrong",
            info(3),
            s.len() as u64,
            "e"
        )
        .is_err());
    }
}
