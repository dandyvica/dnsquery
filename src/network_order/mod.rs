use std::io::{Cursor, Result};

use crate::error::DNSResult;

// functions to convert or build TLS structures
pub trait ToFromNetworkOrder<'a>: std::fmt::Debug {
    // copy structure data to a network-order buffer
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize>;

    // copy from a network-order buffer to a structure
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()>;
}

pub mod dns;
pub mod primitive;
//pub mod resource_record;
