//! An explicit, deterministic length-prefixed binary codec.
//!
//! DaNTe wire structures (ledger records, tree heads, message envelopes) are
//! encoded with this rather than CBOR so the byte layout is **canonical by
//! construction**: there is exactly one encoding of a given value, with no
//! reliance on a serializer's map-ordering or shortest-form behaviour. That
//! property is what makes signatures and content-addressed ids well defined.
//!
//! Rules: integers are big-endian and fixed-width. [`Writer::fixed`] writes raw
//! bytes with no prefix (for `[u8; N]`). [`Writer::bytes`] and
//! [`Writer::string`] prepend a `u32` byte length. Lists prepend a `u32` count,
//! written by the caller via [`Writer::u32`].

use thiserror::Error;

/// A decode error.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// Ran out of input before a field was complete.
    #[error("unexpected end of input")]
    Eof,
    /// Bytes remained after the top-level value was decoded.
    #[error("{0} trailing byte(s) after decode")]
    Trailing(usize),
    /// A length or count prefix exceeded the bytes actually available.
    #[error("length prefix {0} exceeds remaining input")]
    LengthTooLarge(u64),
    /// A boolean field held a byte other than 0 or 1.
    #[error("invalid boolean byte {0}")]
    BadBool(u8),
    /// A string field was not valid UTF-8.
    #[error("invalid UTF-8 in string")]
    BadUtf8,
    /// A tag/enum discriminant was not recognised.
    #[error("unknown discriminant {value} for {ty}")]
    BadDiscriminant {
        /// The type being decoded.
        ty: &'static str,
        /// The unrecognised value.
        value: u64,
    },
    /// A structural invariant failed (e.g. wrong version).
    #[error("invalid {0}")]
    Invalid(&'static str),
}

/// Appends values to an in-memory buffer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A new, empty writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// A writer with room for `capacity` bytes reserved.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Append a `u8`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a big-endian `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a big-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a big-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a boolean as a single `0`/`1` byte.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(u8::from(v));
        self
    }

    /// Append raw bytes with no length prefix (use for `[u8; N]`).
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a `u32` length followed by `bytes`.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a `u32` byte length followed by the UTF-8 of `s`.
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// Consume the writer, returning the buffer.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// The bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Reads values from a byte slice, tracking position.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Eof);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read a `u8`.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    /// Read a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    /// Read a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    /// Read a big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Read a `0`/`1` boolean byte.
    pub fn bool(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(WireError::BadBool(other)),
        }
    }

    /// Read exactly `N` raw bytes into an array.
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    /// Read a `u32`-length-prefixed byte slice (borrowed from the input).
    pub fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        if len > self.remaining() {
            return Err(WireError::LengthTooLarge(len as u64));
        }
        self.take(len)
    }

    /// Read a `u32`-length-prefixed UTF-8 string.
    pub fn string(&mut self) -> Result<String, WireError> {
        let raw = self.bytes()?;
        core::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| WireError::BadUtf8)
    }

    /// Assert the input is fully consumed.
    pub fn finish(self) -> Result<(), WireError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(WireError::Trailing(self.remaining()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_roundtrip() {
        let mut w = Writer::new();
        w.u8(0xAB)
            .u16(0xBEEF)
            .u32(0xDEAD_BEEF)
            .u64(0x0102_0304_0506_0708)
            .bool(true)
            .bool(false)
            .fixed(&[1, 2, 3, 4])
            .bytes(b"hello")
            .string("wörld");
        let bytes = w.into_vec();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0xAB);
        assert_eq!(r.u16().unwrap(), 0xBEEF);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(r.bool().unwrap());
        assert!(!r.bool().unwrap());
        assert_eq!(r.fixed::<4>().unwrap(), [1, 2, 3, 4]);
        assert_eq!(r.bytes().unwrap(), b"hello");
        assert_eq!(r.string().unwrap(), "wörld");
        r.finish().unwrap();
    }

    #[test]
    fn integers_are_big_endian() {
        let mut w = Writer::new();
        w.u32(0x0A0B_0C0D);
        assert_eq!(w.into_vec(), [0x0A, 0x0B, 0x0C, 0x0D]);
    }

    #[test]
    fn eof_is_reported() {
        let mut r = Reader::new(&[0x00, 0x01]);
        assert_eq!(r.u32(), Err(WireError::Eof));
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        // says 100 bytes follow, but only 2 do
        let bytes = [0x00, 0x00, 0x00, 0x64, 0xAA, 0xBB];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.bytes(), Err(WireError::LengthTooLarge(100)));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let bytes = [0xAA, 0xBB];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0xAA);
        assert_eq!(r.finish(), Err(WireError::Trailing(1)));
    }

    #[test]
    fn bad_bool_and_utf8_are_rejected() {
        assert_eq!(Reader::new(&[2]).bool(), Err(WireError::BadBool(2)));
        let bad = [0x00, 0x00, 0x00, 0x01, 0xFF];
        assert_eq!(Reader::new(&bad).string(), Err(WireError::BadUtf8));
    }
}
