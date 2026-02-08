#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise varint32 parser behavior directly
    let _ = nrf_core::_fuzz_decode_varint32(data);
});