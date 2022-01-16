//! Module for some utility functions, including debug
//!
use std::char;
use std::io::Cursor;

// A domain name is null terminated or terminated by a pointer as explained in the RFC1035
pub fn is_sentinel(x: u8) -> bool {
    x == 0 || x >= 192
}

// Debug utility
pub fn pretty_cursor<'a>(buffer: &Cursor<&'a [u8]>) {
    let reference = buffer.get_ref();

    eprintln!("position={}", buffer.position());

    let mut i = 0usize;
    eprint!("index:");
    for _ in *reference {
        eprint!("{:02} ", i);
        i += 1;
    }
    eprintln!();

    eprint!("byte :");
    for x in *reference {
        eprint!("{:02X} ", x);
    }
    eprintln!();

    eprint!("ascii:");
    for x in *reference {
        let c = char::from_u32(*x as u32).unwrap();
        if c.is_ascii_alphanumeric() {
            eprint!("{:>2} ", char::from_u32(*x as u32).unwrap());
        } else {
            eprint!("   ");
        }
    }
    eprintln!();
}
