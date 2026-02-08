#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // We accept any bytes; the decoder must not panic or hang.
    let _ = nrf_core::decode(data);
});