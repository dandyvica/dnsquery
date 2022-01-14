use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Result, Seek, SeekFrom};
use std::str;

use crate::derive_enum;
use crate::error::{DNSError, DNSResult};
use crate::network_order::ToFromNetworkOrder;
use crate::rfc1035::HINFO;


