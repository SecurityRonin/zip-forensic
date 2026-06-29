//! Bounds-checked little-endian reader over an in-memory byte slice.
//!
//! Every read returns `Result`: a truncated header yields a `FormatError`, never
//! an out-of-bounds panic. This is the static half of the Paranoid Gatekeeper —
//! the parser cannot index past the buffer (pairs with the fuzz "must not panic"
//! invariant and `unwrap_used = "deny"`).

use crate::FormatError;

/// A forward cursor over a byte slice with checked little-endian reads.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Borrow `n` bytes and advance, or error if fewer remain.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        let end = self.pos.checked_add(n).ok_or(FormatError::Truncated)?;
        let slice = self.data.get(self.pos..end).ok_or(FormatError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Skip `n` bytes, or error if fewer remain.
    pub(crate) fn skip(&mut self, n: usize) -> Result<(), FormatError> {
        self.take(n).map(|_| ())
    }

    pub(crate) fn u16(&mut self) -> Result<u16, FormatError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, FormatError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn reads_le_integers_and_advances() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xAA, 0xBB];
        let mut r = Reader::new(&data);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert_eq!(r.u32().unwrap(), 0x0605_0403);
        assert_eq!(r.remaining(), 4);
        assert_eq!(r.take(2).unwrap(), &[0x07, 0x08]);
        assert_eq!(r.u16().unwrap(), 0xBBAA);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn truncated_read_errors_not_panics() {
        let data = [0x01];
        let mut r = Reader::new(&data);
        assert!(r.u32().is_err());
        assert!(r.u16().is_err());
        assert!(r.take(2).is_err());
    }
}
