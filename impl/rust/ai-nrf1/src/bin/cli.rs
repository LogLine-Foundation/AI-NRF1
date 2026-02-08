//! Simple CLI: canonicalize input to NRF or convert between NRF and CBOR (when feature enabled).
//! Usage:
//!   nrf1 canon --in nrf --out nrf < input.bin > output.bin
//!   nrf1 canon --in cbor --out nrf < input.cbor > output.nrf
//!   nrf1 canon --in nrf --out cbor < input.nrf > output.cbor  (requires feature compat_cbor)

use std::env;
use std::io::{self, Read, Write};

fn read_all_stdin() -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_all_stdout(bytes: &[u8]) -> io::Result<()> {
    io::stdout().write_all(bytes)?;
    Ok(())
}

fn usage() {
    eprintln!("nrf1 canon --in {{nrf|cbor}} --out {{nrf|cbor}} <in >out");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 || args[1] != "canon" {
        usage();
        std::process::exit(1);
    }
    let mut in_fmt = None;
    let mut out_fmt = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => { i+=1; in_fmt = Some(args.get(i).map(|s| s.as_str()).unwrap_or("")); }
            "--out" => { i+=1; out_fmt = Some(args.get(i).map(|s| s.as_str()).unwrap_or("")); }
            _ => {}
        }
        i+=1;
    }
    let in_fmt = in_fmt.ok_or("missing --in")?;
    let out_fmt = out_fmt.ok_or("missing --out")?;

    let data = read_all_stdin()?;

    // Parse to Value
    let value = match in_fmt {
        "nrf" => {
            nrf1::decode(&data)?
        }
        "cbor" => {
            #[cfg(feature = "compat_cbor")]
            {
                nrf1::compat_cbor::cbor::from_slice(&data)?
            }
            #[cfg(not(feature = "compat_cbor"))]
            {
                return Err("CBOR support not enabled (build with --features compat_cbor)".into());
            }
        }
        _ => {
            return Err("unsupported --in format".into());
        }
    };

    // Emit in desired format
    let out = match out_fmt {
        "nrf" => nrf1::encode(&value),
        "cbor" => {
            #[cfg(feature = "compat_cbor")]
            {
                nrf1::compat_cbor::cbor::to_vec(&value)?
            }
            #[cfg(not(feature = "compat_cbor"))]
            {
                return Err("CBOR support not enabled (build with --features compat_cbor)".into());
            }
        }
        _ => {
            return Err("unsupported --out format".into());
        }
    };

    write_all_stdout(&out)?;
    Ok(())
}
