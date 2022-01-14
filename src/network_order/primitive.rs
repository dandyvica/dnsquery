//! All functions/trait to convert DNS structures to network order back & forth
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Result, Seek, SeekFrom};
use std::str;

use crate::derive_enum;
use crate::error::{DNSError, DNSResult};
use crate::rfc1035::{
    CharacterString, DNSPacket, DNSPacketFlags, DNSPacketHeader, DNSQuestion, DnsResponse,
    DomainName, OpCode, PacketType, QClass, QType, ResponseCode, HINFO,
};

use crate::network_order::ToFromNetworkOrder;

// constants data used for tests
// cfg(doctest) doesn't work as expected
pub const SAMPLE_DOMAIN: &'static str = "www.google.ie";
pub const SAMPLE_SLICE: &[u8; 15] = &[
    0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00,
];
pub const SAMPLE_SLICE_EXTENDED: &[u8; 19] = &[
    0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00, 0x00,
    0x01, 0x00, 0x01,
];

impl<'a> ToFromNetworkOrder<'a> for u8 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(255_u8.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0xFF]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_u8(*self)?;
        Ok(1)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let b = vec![0xFF];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = 0u8;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, 255);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
        *self = buffer.read_u8()?;
        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for u16 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x1234_u16.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34]);
    /// ```   
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_u16::<BigEndian>(*self)?;
        Ok(2)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let b = vec![0x12, 0x34];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = 0u16;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, 0x1234);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
        *self = buffer.read_u16::<BigEndian>()?;
        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for u32 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x12345678_u32.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_u32::<BigEndian>(*self)?;
        Ok(4)
    }
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = 0u32;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, 0x12345678);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
        *self = buffer.read_u32::<BigEndian>()?;
        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for i32 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x12345678_i32.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```   
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_i32::<BigEndian>(*self)?;
        Ok(2)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = 0i32;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, 0x12345678);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
        *self = buffer.read_i32::<BigEndian>()?;
        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for &[u8] {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(&[0x12_u8, 0x34, 0x56, 0x78].to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.append(&mut self.to_vec());
        Ok(self.len())
    }

    fn from_network_bytes(&mut self, _v: &mut Cursor<&[u8]>) -> DNSResult<()> {
        Ok(())
    }
}

impl<'a, T: ToFromNetworkOrder<'a>> ToFromNetworkOrder<'a> for Option<T> {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert_eq!(Some(0xFF_u8).to_network_bytes(&mut buffer).unwrap(), 1);
    /// assert_eq!(buffer, &[0xFF]);
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let r: Option<u8> = None;
    /// assert_eq!(r.to_network_bytes(&mut buffer).unwrap(), 0);
    /// assert!(buffer.is_empty());
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        if self.is_none() {
            Ok(0)
        } else {
            self.as_ref().unwrap().to_network_bytes(buffer)
        }
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v: Option<u32> = None;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert!(v.is_none());
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v: Option<u32> = Some(0u32);
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v.unwrap(), 0x12345678);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        if self.is_none() {
            Ok(())
        } else {
            self.as_mut().unwrap().from_network_bytes(buffer)
        }
    }
}

impl<'a, T: ToFromNetworkOrder<'a>, const N: usize> ToFromNetworkOrder<'a> for [T; N] {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert_eq!([0xFFFF_u16; 10].to_network_bytes(&mut buffer).unwrap(), 20);
    /// assert_eq!(buffer, &[0xFF; 20]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        for x in self {
            // first convert x to network bytes
            let mut buf: Vec<u8> = Vec::new();
            length += x.to_network_bytes(&mut buf)?;

            buffer.append(&mut buf);
        }
        //v.append(&mut self.to_vec());
        Ok(length)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = [0u8;4];
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, [0x12_u8, 0x34, 0x56, 0x78]);
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = [0u16;2];
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, [0x1234_u16, 0x5678]);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        for x in self {
            x.from_network_bytes(buffer)?;
        }
        Ok(())
    }
}

impl<'a, T> ToFromNetworkOrder<'a> for Vec<T>
where
    T: Default + ToFromNetworkOrder<'a>,
{
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let v = vec![[0xFFFF_u16;3],[0xFFFF;3],[0xFFFF;3]];
    /// assert_eq!(v.to_network_bytes(&mut buffer).unwrap(), 18);
    /// assert_eq!(&buffer, &[0xFF; 18]);
    /// ```
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        // copy data for each element
        for item in self {
            length += item.to_network_bytes(buffer)?;
        }

        Ok(length)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v: Vec<u16> = Vec::new();
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, &[0x1234_u16, 0x5678]);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        // the length field holds the length of data field in bytes
        let length = buffer.get_ref().len() / std::mem::size_of::<T>();
        for _ in 0..length {
            let mut u: T = T::default();
            u.from_network_bytes(buffer)?;
            self.push(u);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use super::*;

    // sample is taken from real data using wireshark to be able to test
    // domain name compression
    const SAMPLE: &[u8] = &[
        0x41, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06, 0x67, 0x6f,
        0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x05, 0x00, 0x01, 0xc0, 0x0c,
        0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x26, 0x03, 0x6e, 0x73, 0x31, 0xc0,
        0x0c, 0x09, 0x64, 0x6e, 0x73, 0x2d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0xc0, 0x0c, 0x19, 0x1b,
        0xc0, 0x0c, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x07, 0x08, 0x00,
        0x00, 0x00, 0x3c, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn domain_name() {
        let mut buffer = Cursor::new(SAMPLE);

        // move forward to find first test: 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x05, 0x00, 0x01, 0xc0, 0x0c, 0x00
        buffer.seek(SeekFrom::Start(12)).unwrap();

        // read domain name
        let mut dn = DomainName::default();
        assert!(dn.from_network_bytes(&mut buffer).is_ok());
        assert_eq!(dn.0, &["google", "com"]);
        assert_eq!(&dn.to_string(), "google.com");

        // move forward to find second test: 0xc0, 0x0c
        buffer.seek(SeekFrom::Start(28)).unwrap();

        // read domain name
        let mut dn = DomainName::default();
        assert!(dn.from_network_bytes(&mut buffer).is_ok());
        assert_eq!(dn.0, &["google", "com"]);
        assert_eq!(&dn.to_string(), "google.com");

        // move forward to find second test: 0x6e, 0x73, 0x31, 0xc0, 0x0c
        buffer.seek(SeekFrom::Start(40)).unwrap();

        // read domain name
        let mut dn = DomainName::default();
        assert!(dn.from_network_bytes(&mut buffer).is_ok());
        assert_eq!(dn.0, &["ns1", "google", "com"]);
        assert_eq!(&dn.to_string(), "ns1.google.com");

        // move forward to find second test: 0x09, 0x64, 0x6e, 0x73, 0x2d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0xc0, 0x0c
        buffer.seek(SeekFrom::Start(46)).unwrap();

        // read domain name
        let mut dn = DomainName::default();
        assert!(dn.from_network_bytes(&mut buffer).is_ok());
        assert_eq!(dn.0, &["dns-admin", "google", "com"]);
        assert_eq!(&dn.to_string(), "dns-admin.google.com");
    }

    #[test]
    fn dnspacket_to_network() {
        // flags
        let flags = DNSPacketFlags {
            packet_type: PacketType::Response,
            op_code: OpCode::IQuery,
            is_authorative_answer: true,
            is_truncated: true,
            is_recursion_desired: true,
            is_recursion_available: true,
            z: 0b111,
            response_code: ResponseCode::NoError,
        };

        // packet header
        let header = DNSPacketHeader {
            id: 0x1234,
            flags: flags,
            qd_count: 0x1234,
            an_count: 0x1234,
            ns_count: 0x1234,
            ar_count: 0x1234,
        };

        // question
        let mut qn = DomainName::default();
        qn.from_slice(SAMPLE_SLICE.as_slice()).unwrap();
        let question = DNSQuestion {
            name: qn,
            r#type: QType::A,
            class: QClass::IN,
        };

        // packet
        let packet = DNSPacket::<DNSQuestion> {
            header: header,
            data: question,
        };

        // convert to NB
        let mut buffer: Vec<u8> = Vec::new();

        let converted = packet.to_network_bytes(&mut buffer);
        assert!(converted.is_ok());
        let length = converted.unwrap();
        assert_eq!(length, 31);

        assert_eq!(
            buffer,
            &[
                0x12,
                0x34,
                0b1000_1111,
                0b1111_0000,
                0x12,
                0x34,
                0x12,
                0x34,
                0x12,
                0x34,
                0x12,
                0x34,
                0x03,
                0x77,
                0x77,
                0x77,
                0x06,
                0x67,
                0x6f,
                0x6f,
                0x67,
                0x6c,
                0x65,
                0x02,
                0x69,
                0x65,
                0x00,
                0x00,
                0x01,
                0x00,
                0x01
            ]
        );
    }
}
