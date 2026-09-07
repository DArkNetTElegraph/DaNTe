#![no_main]
use libfuzzer_sys::fuzz_target;
use dante_group::{GroupMessage, GroupState, SenderKeyBundle};

fuzz_target!(|data: &[u8]| {
    let _ = GroupState::decode(data);
    if let Ok(m) = GroupMessage::decode(data) {
        assert_eq!(m.encode(), data, "GroupMessage decode is not canonical");
    }
    if let Ok(b) = SenderKeyBundle::decode(data) {
        assert_eq!(b.encode(), data, "SenderKeyBundle decode is not canonical");
    }
});
