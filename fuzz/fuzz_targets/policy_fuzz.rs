#![no_main]

//! Phase 8 (docs/design/phase-8.md §3.3): arbitrary text through the policy
//! parser and compiler must return a result, never panic. A policy file is
//! operator input, but a crash here would take the sensor down on SIGHUP.

use libfuzzer_sys::fuzz_target;
use rk_policy::net::{compile, diff, parse, ProfileIds};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut ids = ProfileIds::default();
    if let Ok(policy) = parse(text, &mut ids) {
        let _ = compile(&policy, 1);
        // diff against itself must be empty: same text, same allocator state.
        assert!(diff(Some(&policy), &policy).is_empty());
    }
});
