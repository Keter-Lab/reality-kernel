#![no_main]

use libfuzzer_sys::fuzz_target;
use rk_sensor::decoder::{decode, DecodeStats, Payload};

fuzz_target!(|data: &[u8]| {
    let stats = DecodeStats::default();
    let result = decode(data);
    stats.record(&result);
    assert_eq!(stats.decoded() + stats.rejected(), 1);

    // A decoded record must be internally consistent: iterating its strings
    // must yield exactly the declared count without panicking.
    if let Ok(event) = result {
        match event.payload {
            Payload::Exec { body, strings } => {
                assert_eq!(strings.count(), usize::from(body.str_count))
            }
            Payload::File { body, strings } => {
                assert_eq!(strings.count(), usize::from(body.str_count))
            }
            Payload::Net { .. } | Payload::Raw { .. } => {}
        }
    }
});
