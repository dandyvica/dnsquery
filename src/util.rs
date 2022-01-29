//! Module for some utility functions, including debug
//!
use std::char;
use std::io::Cursor;

/// Give the leftmost 2 bits of a 8-bit integer.
///
/// # Example
/// ```
/// use dnslib::util::leftmost_bits;
///
/// assert_eq!(leftmost_bits(0b11000000), 0b11_u8);
/// ```
pub fn leftmost_bits(x: u8) -> u8 {
    x >> 6
}

/// A domain name is null terminated or terminated by a pointer as explained in the RFC1035.
///
/// # Example
/// ```
/// use dnslib::util::is_sentinel;
///
/// assert!(is_sentinel(0b11000000));
/// assert!(is_sentinel(0));
/// assert!(!is_sentinel(0b10000000));
/// ```
// A domain name is null terminated or terminated by a pointer as explained in the RFC1035
pub fn is_pointer(x: u8) -> bool {
    leftmost_bits(x) == 0b11_u8
}

/// A domain name is null terminated or terminated by a pointer as explained in the RFC1035.
///
/// # Example
/// ```
/// use dnslib::util::is_sentinel;
///
/// assert!(is_sentinel(0b11000000));
/// assert!(is_sentinel(0));
/// assert!(!is_sentinel(0b10000000));
/// ```
// A domain name is null terminated or terminated by a pointer as explained in the RFC1035
pub fn is_sentinel(x: u8) -> bool {
    x == 0 || leftmost_bits(x) == 0b11_u8
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
