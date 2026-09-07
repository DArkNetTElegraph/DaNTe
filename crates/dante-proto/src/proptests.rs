//! Property tests for the wire layer: the codec round-trips, and every public
//! decoder is total (returns `Ok`/`Err`, never panics) on arbitrary bytes.

use proptest::prelude::*;

use crate::{
    enc::{Reader, Writer},
    envelope::Envelope,
    head::SignedTreeHead,
    record::Record,
};

/// One primitive field, as both a value and the ops to write/read it.
#[derive(Clone, Debug, PartialEq)]
enum Field {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bool(bool),
    Fixed([u8; 8]),
    Bytes(Vec<u8>),
    Str(String),
}

fn field_strategy() -> impl Strategy<Value = Field> {
    prop_oneof![
        any::<u8>().prop_map(Field::U8),
        any::<u16>().prop_map(Field::U16),
        any::<u32>().prop_map(Field::U32),
        any::<u64>().prop_map(Field::U64),
        any::<bool>().prop_map(Field::Bool),
        any::<[u8; 8]>().prop_map(Field::Fixed),
        proptest::collection::vec(any::<u8>(), 0..256).prop_map(Field::Bytes),
        "[\\x00-\\x{10FFFF}]{0,64}".prop_map(Field::Str),
    ]
}

proptest! {
    /// A sequence of primitives written then read back in the same order is
    /// recovered exactly, with no trailing bytes.
    #[test]
    fn codec_roundtrips_arbitrary_field_sequences(fields in proptest::collection::vec(field_strategy(), 0..40)) {
        let mut w = Writer::new();
        for f in &fields {
            match f {
                Field::U8(v)    => { w.u8(*v); }
                Field::U16(v)   => { w.u16(*v); }
                Field::U32(v)   => { w.u32(*v); }
                Field::U64(v)   => { w.u64(*v); }
                Field::Bool(v)  => { w.bool(*v); }
                Field::Fixed(v) => { w.fixed(v); }
                Field::Bytes(v) => { w.bytes(v); }
                Field::Str(v)   => { w.string(v); }
            }
        }
        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        for f in &fields {
            match f {
                Field::U8(v)    => prop_assert_eq!(r.u8().unwrap(), *v),
                Field::U16(v)   => prop_assert_eq!(r.u16().unwrap(), *v),
                Field::U32(v)   => prop_assert_eq!(r.u32().unwrap(), *v),
                Field::U64(v)   => prop_assert_eq!(r.u64().unwrap(), *v),
                Field::Bool(v)  => prop_assert_eq!(r.bool().unwrap(), *v),
                Field::Fixed(v) => prop_assert_eq!(&r.fixed::<8>().unwrap(), v),
                Field::Bytes(v) => prop_assert_eq!(r.bytes().unwrap(), v.as_slice()),
                Field::Str(v)   => prop_assert_eq!(&r.string().unwrap(), v),
            }
        }
        prop_assert!(r.finish().is_ok());
    }

    /// `Reader` never reads past the end: a truncated buffer errors, it does not
    /// panic or over-read.
    #[test]
    fn reader_is_total_on_truncation(buf in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut r = Reader::new(&buf);
        // Hammer a mix of accessors; each must return without panicking.
        let _ = r.u64();
        let _ = r.bytes();
        let _ = r.string();
        let _ = r.fixed::<32>();
        let _ = r.bool();
    }

    /// Public decoders are total on arbitrary input.
    #[test]
    fn record_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Record::decode(&buf);
    }

    #[test]
    fn envelope_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Envelope::decode(&buf);
    }

    #[test]
    fn signed_tree_head_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = SignedTreeHead::decode(&buf);
    }

    /// A decoded value re-encodes to the exact bytes it came from (canonical
    /// form), whenever it decodes at all.
    #[test]
    fn record_decode_is_canonical(buf in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(rec) = Record::decode(&buf) {
            prop_assert_eq!(rec.encode(), buf);
        }
    }

    #[test]
    fn envelope_decode_is_canonical(buf in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(env) = Envelope::decode(&buf) {
            prop_assert_eq!(env.encode(), buf);
        }
    }
}
