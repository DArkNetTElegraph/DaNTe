//! Property tests for the relay protocol codec: decoding is total on arbitrary
//! bytes, and any value that decodes re-encodes to exactly the same bytes.

use proptest::prelude::*;

use crate::wire::{Request, Response};

proptest! {
    #[test]
    fn request_decode_is_total_and_canonical(buf in proptest::collection::vec(any::<u8>(), 0..8192)) {
        if let Ok(req) = Request::decode(&buf) {
            prop_assert_eq!(req.encode(), buf);
        }
    }

    #[test]
    fn response_decode_is_total_and_canonical(buf in proptest::collection::vec(any::<u8>(), 0..8192)) {
        if let Ok(res) = Response::decode(&buf) {
            prop_assert_eq!(res.encode(), buf);
        }
    }
}
