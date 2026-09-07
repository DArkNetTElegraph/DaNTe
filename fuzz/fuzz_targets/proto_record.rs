#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(rec) = dante_proto::Record::decode(data) {
        // Whatever decodes must re-encode to the exact same bytes.
        assert_eq!(rec.encode(), data, "Record decode is not canonical");
    }
});
