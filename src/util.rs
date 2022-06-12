//! Module for some utility functions, including debug
//!
use std::char;
use std::io::Cursor;

// Format a buffer as a string of hex char or chars
#[macro_export]
macro_rules! format_buffer {
    ("X", &$buffer:ident) => {{
        // just a string of hex chars
        format!("{:02X?}", $buffer)
    }};
    ("C", &$buffer:ident) => {{
        // just a string of chars
        let mut s = String::new();
        for x in $buffer.iter() {
            // only print out printable chars
            if x > &21 && x < &128 {
                // char is always 4 bytes, so need to deal with it
                let c = char::from_u32(*x as u32).unwrap();
                s.push_str(&format!("{:<4}", c));
            } else {
                s.push_str(&format!("{:<4}", " "));
            }
        }
        s
    }};
}

/// A domain name is null terminated or terminated by a pointer as explained in the RFC1035.
///
/// # Example
/// ```
/// use dnslib::util::is_pointer;
///
/// assert!(is_pointer(0b11000000));
/// assert!(!is_pointer(0));
/// assert!(!is_pointer(0b10000000));
/// ```
// A domain name is null terminated or terminated by a pointer as explained in the RFC1035
pub fn is_pointer(x: u8) -> bool {
    x >= 192
}

/// Convert a domain into bytes
///
/// # Example
/// ```
/// use dnslib::util::to_domain;
///
/// assert_eq!(to_domain("www.google.ie"), &[0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00]);
/// ```
// A domain name is null terminated or terminated by a pointer as explained in the RFC1035
pub fn to_domain(domain: &str) -> Vec<u8> {
    let mut v = Vec::new();

    for label in domain.split('.') {
        let size = label.len() as u8;
        v.push(size);
        v.extend(label.bytes());
    }
    v.push(0);

    v
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

// Utility to transfrom data coming from a copy from Wireshark into a slice of u8
// Ex:
// 0000   08 d4 81 a0 00 01 00 08 00 00 00 01 02 68 6b 00
// 0010   00 02 00 01 c0 0c 00 02 00 01 00 00 54 60 00 0e
// 0020   01 63 05 68 6b 69 72 63 03 6e 65 74 c0 0c c0 0c
// 0030   00 02 00 01 00 00 54 60 00 04 01 74 c0 22 c0 0c
// 0040   00 02 00 01 00 00 54 60 00 04 01 76 c0 22 c0 0c
// 0050   00 02 00 01 00 00 54 60 00 04 01 7a c0 22 c0 0c
// 0060   00 02 00 01 00 00 54 60 00 04 01 64 c0 22 c0 0c
// 0070   00 02 00 01 00 00 54 60 00 04 01 75 c0 22 c0 0c
// 0080   00 02 00 01 00 00 54 60 00 04 01 79 c0 22 c0 0c
// 0090   00 02 00 01 00 00 54 60 00 04 01 78 c0 22 00 00
// 00a0   29 02 00 00 00 00 00 00 00
pub fn get_sample_slice(s: &str) -> Vec<u8> {
    s.split_ascii_whitespace()
        .filter(|x| x.len() == 2)
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect()
}
