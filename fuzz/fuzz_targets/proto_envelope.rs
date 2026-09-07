#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = dante_proto::Envelope::decode(data) {
        assert_eq!(env.encode(), data, "Envelope decode is not canonical");
    }
    let _ = dante_proto::head::SignedTreeHead::decode(data);
});
