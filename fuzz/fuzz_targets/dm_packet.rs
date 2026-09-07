#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = dante_dm::Packet::decode(data) {
        assert_eq!(p.encode(), data, "Packet decode is not canonical");
    }
    if let Ok(c) = dante_dm::Content::decode(data) {
        assert_eq!(c.encode(), data, "Content decode is not canonical");
    }
    let _ = dante_dm::RatchetState::decode(data);
    let _ = dante_dm::SessionState::decode(data);
    let _ = dante_dm::PreKeyBundle::decode(data);
});
