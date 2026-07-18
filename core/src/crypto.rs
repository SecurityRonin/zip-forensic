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

// ─────────────────── PKWARE Strong Encryption (password-based AES) ─────────────
//
// The password branch of PKWARE strong encryption (GP flag bit 6), transcribed
// from 7-Zip `CPP/7zip/Crypto/ZipStrong.cpp`. Every primitive is audited
// RustCrypto (`sha1`, `aes`, `cbc`) — nothing is hand-rolled. Certificate-based,
// 3DES-ERD, and non-AES headers are refused loud, exactly as 7-Zip returns
// E_NOTIMPL. The decryption header (prepended to the entry's compressed data) is:
//   IVSize(2) IVData(IVSize) Size(4) Format(2) AlgID(2) Bitlen(2) Flags(2)
//   ErdSize(2) ErdData(ErdSize) Reserved1(4) VSize(2) VData(VSize) — ErdData and
// VData are CBC ciphertext; VData's plaintext ends in a CRC-32 of the rest.

use aes::cipher::generic_array::GenericArray;
use cbc::cipher::BlockDecryptMut;
use sha1::{Digest, Sha1};

/// Lowest AES algorithm id for strong encryption: 0x660E/0F/10 = AES-128/192/256.
const ALG_AES128: u16 = 0x660E;
/// AES CBC block / PKCS#7 pad-block size.
const AES_BLOCK: usize = 16;
/// Upper bound on the decryption-header remainder, mirroring 7-Zip (`1 << 18`).
const MAX_STRONG_REM: usize = 1 << 18;

fn sha1_of(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// One half of the `CryptDeriveKey`(SHA1) construction: SHA1 of a 64-byte buffer
/// filled with `c`, its first 20 bytes XOR-combined with `digest`.
fn derive_key_half(digest: &[u8; 20], c: u8) -> [u8; 20] {
    let mut buf = [c; 64];
    for (b, d) in buf.iter_mut().zip(digest.iter()) {
        *b ^= *d;
    }
    sha1_of(&[&buf])
}

/// Windows `CryptDeriveKey`(SHA1) for AES: `SHA1(0x36-pad) ‖ SHA1(0x5C-pad)`
/// truncated to `key_size` (16/24/32).
fn crypt_derive_key(digest: &[u8; 20], key_size: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&derive_key_half(digest, 0x36));
    key.extend_from_slice(&derive_key_half(digest, 0x5C));
    key.truncate(key_size);
    key
}

/// AES-CBC decryptor over one message, dispatched by key length. Built on the
/// audited `cbc`/`aes` crates — never hand-rolled.
enum CbcDec {
    A128(cbc::Decryptor<aes::Aes128>),
    A192(cbc::Decryptor<aes::Aes192>),
    A256(cbc::Decryptor<aes::Aes256>),
}

impl CbcDec {
    fn new(key: &[u8], iv: &[u8; 16], entry: &str) -> Result<Self, ZipCoreError> {
        let err = || ZipCoreError::UnsupportedEncryption {
            entry: entry.to_string(),
            reason: format!("invalid AES key length {}", key.len()),
        };
        Ok(match key.len() {
            16 => Self::A128(cbc::Decryptor::new_from_slices(key, iv).map_err(|_| err())?),
            24 => Self::A192(cbc::Decryptor::new_from_slices(key, iv).map_err(|_| err())?),
            32 => Self::A256(cbc::Decryptor::new_from_slices(key, iv).map_err(|_| err())?),
            _ => return Err(err()),
        })
    }

    fn decrypt_block(&mut self, block: &mut [u8; AES_BLOCK]) {
        let b = GenericArray::from_mut_slice(block);
        match self {
            Self::A128(c) => c.decrypt_block_mut(b),
            Self::A192(c) => c.decrypt_block_mut(b),
            Self::A256(c) => c.decrypt_block_mut(b),
        }
    }
}

/// CBC-decrypt `data` in place; `data.len()` must be a multiple of `AES_BLOCK`.
fn cbc_decrypt_buffer(
    key: &[u8],
    iv: &[u8; 16],
    data: &mut [u8],
    entry: &str,
) -> Result<(), ZipCoreError> {
    let mut dec = CbcDec::new(key, iv, entry)?;
    for chunk in data.chunks_exact_mut(AES_BLOCK) {
        let mut block = [0u8; AES_BLOCK];
        block.copy_from_slice(chunk);
        dec.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    Ok(())
}

/// Parsed strong-encryption decryption header: the initialization vector, the
/// derived AES file key, and the total header length (so the caller can locate
/// the encrypted file data that follows it).
pub(crate) struct StrongHeader {
    pub(crate) iv: [u8; 16],
    pub(crate) file_key: Vec<u8>,
    pub(crate) header_len: u64,
}

/// Validated layout of the decryption-header remainder buffer.
struct StrongLayout {
    /// AES key length in bytes (16/24/32).
    key_size: usize,
    /// `ErdData` length: CBC ciphertext at `p[10..10 + rd_size]`.
    rd_size: usize,
    /// Offset of the validation blob (`VData`) within the remainder buffer.
    valid_off: usize,
    /// Validation-blob length: CBC ciphertext at `p[valid_off..valid_off + valid_size]`.
    valid_size: usize,
}

/// Validate the fixed fields + layout of the decryption-header remainder buffer
/// `p`, refusing loud for every out-of-scope strong variant (non-AES, bad
/// `BitLen`, certificate, 3DES-ERD, non-password, inconsistent sizes). `p.len()`
/// is the `rem_size` the header declared and is `>= 16`, so the 10 fixed bytes
/// exist.
fn parse_strong_layout(p: &[u8], entry: &str) -> Result<StrongLayout, ZipCoreError> {
    let refuse = |reason: String| ZipCoreError::UnsupportedEncryption {
        entry: entry.to_string(),
        reason,
    };
    let rem_size = p.len();

    let format = u16::from_le_bytes([p[0], p[1]]);
    if format != 3 {
        return Err(refuse(format!(
            "strong-encryption format {format} (expected 3)"
        )));
    }
    let alg = u16::from_le_bytes([p[2], p[3]]);
    let alg_idx = match alg.checked_sub(ALG_AES128) {
        Some(i) if i <= 2 => usize::from(i),
        _ => {
            return Err(refuse(format!(
                "strong-encryption AlgID {alg:#06x} is not AES (0x660E/0F/10)"
            )))
        }
    };
    let bit_len = usize::from(u16::from_le_bytes([p[4], p[5]]));
    let flags = u16::from_le_bytes([p[6], p[7]]);
    let key_size = 16 + alg_idx * 8;
    if key_size * 8 != bit_len {
        return Err(refuse(format!(
            "strong-encryption BitLen {bit_len} does not match AlgID key size {key_size}"
        )));
    }
    if flags & 0x4000 != 0 {
        return Err(refuse(
            "strong-encryption uses 3DES for the ERD (unsupported)".into(),
        ));
    }
    if flags & 0x0002 != 0 {
        return Err(refuse(
            "strong-encryption is certificate-based (no private key)".into(),
        ));
    }
    if flags & 0x0001 == 0 {
        return Err(refuse(
            "strong-encryption header sets neither the password nor certificate flag".into(),
        ));
    }

    // ErdData must fit after the 10-byte fixed header and be a positive multiple
    // of the block size (CBC ciphertext with a full 0x10 pad block).
    let rd_size = usize::from(u16::from_le_bytes([p[8], p[9]]));
    if rd_size.checked_add(16).is_none_or(|v| v > rem_size) {
        return Err(refuse(format!(
            "strong-encryption ERD size {rd_size} overflows the {rem_size}-byte header"
        )));
    }
    if rd_size < AES_BLOCK || rd_size % AES_BLOCK != 0 {
        return Err(refuse(format!(
            "strong-encryption ERD size {rd_size} is not a positive multiple of {AES_BLOCK}"
        )));
    }

    // Layout: [10 fixed][rd_size ERD][4 Reserved1][2 VSize][valid_size VData].
    // Reserved1 must be 0 on the non-certificate branch (else it is a recipient
    // list). VData is 16-aligned and must consume the rest of the header exactly.
    let reserved_off = 10 + rd_size;
    let reserved = u32::from_le_bytes([
        p[reserved_off],
        p[reserved_off + 1],
        p[reserved_off + 2],
        p[reserved_off + 3],
    ]);
    if reserved != 0 {
        return Err(refuse(format!(
            "strong-encryption Reserved1 {reserved:#x} (certificate recipient list, unsupported)"
        )));
    }
    let vsize_off = reserved_off + 4;
    let valid_size = usize::from(u16::from_le_bytes([p[vsize_off], p[vsize_off + 1]]));
    let valid_off = vsize_off + 2;
    if valid_size < 4
        || valid_size % AES_BLOCK != 0
        || valid_off.checked_add(valid_size) != Some(rem_size)
    {
        return Err(refuse(format!(
            "strong-encryption validation blob size {valid_size} is inconsistent with the header"
        )));
    }

    Ok(StrongLayout {
        key_size,
        rd_size,
        valid_off,
        valid_size,
    })
}

/// Parse the strong-encryption decryption header from `r` (positioned at the
/// entry's first data byte), derive the AES file key, and verify the password.
/// Refuses loud (`UnsupportedEncryption`) for every out-of-scope strong variant
/// and returns `WrongPassword` when the password fails either integrity gate.
pub(crate) fn read_strong_header<R: Read>(
    r: &mut R,
    password: &[u8],
    crc: u32,
    unpack_size: u64,
    entry: &str,
) -> Result<StrongHeader, ZipCoreError> {
    let refuse = |reason: String| ZipCoreError::UnsupportedEncryption {
        entry: entry.to_string(),
        reason,
    };

    // IVSize + IVData. IVSize 0 derives the IV from crc ‖ uncompressed size.
    let mut buf2 = [0u8; 2];
    r.read_exact(&mut buf2)?;
    let iv_size_field = u16::from_le_bytes(buf2);
    let mut iv = [0u8; 16];
    let iv_used: usize;
    let mut header_len = 2u64;
    if iv_size_field == 0 {
        iv[0..4].copy_from_slice(&crc.to_le_bytes());
        iv[4..12].copy_from_slice(&unpack_size.to_le_bytes());
        iv_used = 12;
    } else if iv_size_field == 16 {
        r.read_exact(&mut iv)?;
        header_len += 16;
        iv_used = 16;
    } else {
        return Err(refuse(format!(
            "strong-encryption IV size {iv_size_field} (only 0 or 16 supported)"
        )));
    }

    // Size (remainder length) + the remainder buffer holding every field after it.
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4)?;
    header_len += 4;
    let rem_size = u32::from_le_bytes(buf4) as usize;
    if !(16..=MAX_STRONG_REM).contains(&rem_size) {
        return Err(refuse(format!(
            "strong-encryption header remainder {rem_size} bytes out of range"
        )));
    }
    let mut p = vec![0u8; rem_size];
    r.read_exact(&mut p)?;
    header_len += rem_size as u64;

    let StrongLayout {
        key_size,
        rd_size,
        valid_off,
        valid_size,
    } = parse_strong_layout(&p, entry)?;

    // MasterKey = CryptDeriveKey(SHA1(password)).
    let master_key = crypt_derive_key(&sha1_of(&[password]), key_size);

    // Recover RD: CBC-decrypt the ERD, then verify + strip its trailing 0x10 pad
    // block. A wrong password almost always fails here (garbage pad).
    let mut erd = p[10..10 + rd_size].to_vec();
    cbc_decrypt_buffer(&master_key, &iv, &mut erd, entry)?;
    let rd_len = rd_size - AES_BLOCK;
    if erd[rd_len..].iter().any(|&b| usize::from(b) != AES_BLOCK) {
        return Err(ZipCoreError::WrongPassword(entry.to_string()));
    }
    let rd = &erd[..rd_len];

    // FileKey = CryptDeriveKey(SHA1(iv[0..iv_used] ‖ RD)).
    let file_key = crypt_derive_key(&sha1_of(&[&iv[..iv_used], rd]), key_size);

    // Password check: CBC-decrypt the validation blob; its trailing CRC-32 must
    // match the CRC of the preceding plaintext, else the password is wrong.
    let mut vdata = p[valid_off..valid_off + valid_size].to_vec();
    cbc_decrypt_buffer(&file_key, &iv, &mut vdata, entry)?;
    let split = valid_size - 4;
    let want = u32::from_le_bytes([
        vdata[split],
        vdata[split + 1],
        vdata[split + 2],
        vdata[split + 3],
    ]);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&vdata[..split]);
    if hasher.finalize() != want {
        return Err(ZipCoreError::WrongPassword(entry.to_string()));
    }

    // 7-Zip decrypts the file data with the SAME CBC decoder that just decrypted
    // the validation blob, without re-seeding the IV (`CDecoder::Init` is a
    // no-op). CBC therefore chains: the file data's IV is the last ciphertext
    // block of the validation blob, not the header IV.
    let mut file_iv = [0u8; 16];
    file_iv.copy_from_slice(&p[rem_size - AES_BLOCK..rem_size]);

    Ok(StrongHeader {
        iv: file_iv,
        file_key,
        header_len,
    })
}

/// A `Read` adapter that CBC-decrypts a strong-encryption file-data stream on the
/// fly. CBC is block-based, so bytes are staged one 16-byte block at a time. The
/// ciphertext length is a multiple of the block size (CBC output); trailing pad
/// bytes past the real payload are handled by the caller (a `Stored` entry is
/// capped at its uncompressed size, a compressed entry's decoder self-terminates).
pub(crate) struct StrongAesReader<R> {
    inner: R,
    cipher: CbcDec,
    block: [u8; AES_BLOCK],
    block_pos: usize,
    block_len: usize,
    remaining: u64,
}

impl<R: Read> StrongAesReader<R> {
    pub(crate) fn new(
        inner: R,
        file_key: &[u8],
        iv: &[u8; 16],
        enc_len: u64,
        entry: &str,
    ) -> Result<Self, ZipCoreError> {
        Ok(Self {
            inner,
            cipher: CbcDec::new(file_key, iv, entry)?,
            block: [0u8; AES_BLOCK],
            block_pos: 0,
            block_len: 0,
            remaining: enc_len,
        })
    }
}

impl<R: Read> Read for StrongAesReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.block_pos >= self.block_len {
            if self.remaining == 0 {
                return Ok(0);
            }
            // The stream length is a multiple of the block size, so a full block
            // is always available; a short read here is truncated ciphertext.
            self.inner.read_exact(&mut self.block)?;
            self.cipher.decrypt_block(&mut self.block);
            self.block_pos = 0;
            self.block_len = AES_BLOCK;
            self.remaining = self.remaining.saturating_sub(AES_BLOCK as u64);
        }
        let n = (self.block_len - self.block_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.block[self.block_pos..self.block_pos + n]);
        self.block_pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::Cursor;

    #[test]
    fn cbc_dec_new_rejects_unsupported_key_length() {
        // 16/24/32 are the only AES key lengths; anything else is refused loud
        // (this arm is unreachable from the header parser, which derives key sizes
        // of 16/24/32, so it is exercised directly here).
        for len in [0usize, 15, 33] {
            assert!(matches!(
                CbcDec::new(&vec![0u8; len], &[0u8; 16], "e"),
                Err(ZipCoreError::UnsupportedEncryption { .. })
            ));
        }
        assert!(CbcDec::new(&[0u8; 32], &[0u8; 16], "e").is_ok());
    }

    #[test]
    fn strong_reader_reads_to_eof() {
        // Read the whole ciphertext stream and confirm the exhausted reader yields
        // Ok(0) (the `remaining == 0` arm the archive path caps before reaching).
        let ct = vec![0xAAu8; 32]; // two blocks
        let mut r = StrongAesReader::new(Cursor::new(ct), &[0u8; 32], &[0u8; 16], 32, "e").unwrap();
        let mut out = Vec::new();
        assert_eq!(r.read_to_end(&mut out).unwrap(), 32);
        assert_eq!(r.read(&mut [0u8; 4]).unwrap(), 0);
    }

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
