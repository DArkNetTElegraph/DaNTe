#![no_main]
use libfuzzer_sys::fuzz_target;
use dante_net::wire::{Request, Response};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Request::decode(data) {
        assert_eq!(r.encode(), data, "Request decode is not canonical");
    }
    if let Ok(r) = Response::decode(data) {
        assert_eq!(r.encode(), data, "Response decode is not canonical");
    }
});
