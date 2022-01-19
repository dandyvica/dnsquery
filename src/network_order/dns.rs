//! All functions/trait to convert DNS structures to network order back & forth
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Result, Seek, SeekFrom};
use std::str;

use crate::derive_enum;
use crate::error::{DNSError, DNSResult};
use crate::network_order::ToFromNetworkOrder;
use crate::rfc1035::{
    CharacterString, DNSPacket, DNSPacketFlags, DNSPacketHeader, DNSQuestion, DnsResponse,
    DomainName, OpCode, PacketType, QClass, QType, ResponseCode,
};

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

impl<'a> ToFromNetworkOrder<'a> for CharacterString<'a> {
    fn to_network_bytes(&self, _buffer: &mut Vec<u8>) -> Result<usize> {
        Ok(0)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::CharacterString;
    ///
    /// let mut buffer = Cursor::new([0x06_u8, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65].as_slice());
    /// let mut cs = CharacterString::default();
    /// assert!(cs.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(cs, "google");
    /// ```    
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        // get a reference on [u8]
        let reference = buffer.get_ref();

        // first char is the string length
        let size = reference[0] as usize;

        // move the cursor forward
        buffer.seek(SeekFrom::Start(12))?;

        // save data
        *self = str::from_utf8(&buffer.get_ref()[1..size + 1])?;
        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for DomainName<'a> {
    /// ```
    /// use dnslib::rfc1035::DomainName;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::network_order::dns::{SAMPLE_DOMAIN, SAMPLE_SLICE};
    ///
    /// let dn = DomainName::try_from(SAMPLE_DOMAIN).unwrap();
    /// let mut buffer: Vec<u8> = Vec::new();
    ///
    /// assert_eq!(dn.to_network_bytes(&mut buffer).unwrap(), 15);
    /// assert_eq!(&buffer, SAMPLE_SLICE);
    /// ```
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        for label in &self.0 {
            // write length first
            buffer.write_u8(label.len() as u8)?;

            // write label
            label.as_bytes().to_network_bytes(buffer)?;

            length += label.len() + 1;
        }

        // add sentinel 0x00
        buffer.write_u8(0)?;

        Ok(length + 1)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::DomainName;
    /// use dnslib::network_order::dns::{SAMPLE_DOMAIN, SAMPLE_SLICE};
    ///
    /// // with sentinel = 0
    /// let mut buffer = Cursor::new(SAMPLE_SLICE.as_slice());
    /// let mut dn = DomainName::default();
    /// assert!(dn.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(dn.0, &["www", "google", "ie"]);
    ///
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        //dbg!("============================");

        // loop through the vector
        let start_position = buffer.position() as usize;

        //dbg!(start_position);
        //dbg!(buffer.get_ref()[start_position]);
        //println!("\nstart_position={}, char={:X}", start_position, buffer.get_ref()[start_position]);
        //println!("buffer========> {:0X?}", buffer);

        // read until 0 or 192 (which is the value 0b11000000)
        // description is possible cases are described in RFC1035:
        //
        // The compression scheme allows a domain name in a message to be
        // represented as either:
        // - a sequence of labels ending in a zero octet
        // - a pointer
        // - a sequence of labels ending with a pointer
        let sentinel = buffer
            .by_ref()
            .bytes()
            .skip_while(|x| x.as_ref().unwrap() != &0 && x.as_ref().unwrap() < &192)
            .next();

        //dbg!(&sentinel);
        //println!("sentinel={:?}", sentinel);
        //println!("end_position={}", buffer.position());

        // as last() returns an Option, we need to check it
        if sentinel.is_none() {
            return Err(DNSError::new("malformed compression"));
        }
        // and it's safe to unwrap
        let sentinel = sentinel.unwrap()?;
        debug_assert!(sentinel == 0 || sentinel >= 192);

        // where are we now ?
        let end_position = buffer.position() as usize;
        //dbg!(end_position);

        // at the end of the previous iteration, the sentinel is either 0 which means no compression
        // or > 192 which means compression. But the compression pointer is a 16-bit pointer, so
        // we need to read another byte
        // if we did find the sentinel, get data from cursor
        if sentinel == 0 {
            self.from_slice(&buffer.get_ref()[start_position..end_position])?;
        } else if sentinel >= 192 {
            // it's a pointer, but the pointer is 16-bits, so we need to get it
            let buf = [sentinel, buffer.read_u8()?];

            // and convert it from network bytes
            let pointer = u16::from_be_bytes(buf);

            // From RFC1035:
            //
            // The pointer takes the form of a two octet sequence:
            // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // | 1  1|                OFFSET                   |
            // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //    The first two bits are ones.  This allows a pointer to be distinguished
            //    from a label, since the label must begin with two zero bits because
            //    labels are restricted to 63 octets or less.  (The 10 and 01 combinations
            //    are reserved for future use.)  The OFFSET field specifies an offset from
            //    the start of the message (i.e., the first octet of the ID field in the
            //    domain header).  A zero offset specifies the first byte of the ID field,
            //    etc.

            // get rid of the first leftmost bits
            let pointer = ((pointer << 2) >> 2) as usize;
            //dbg!(pointer);

            // if we only have the pointer
            if end_position - start_position == 1 {
                self.from_slice(&buffer.get_ref()[pointer..])?;
            } else {
                self.from_slice(&buffer.get_ref()[start_position..end_position])?;
                self.from_slice(&buffer.get_ref()[pointer..])?;
            }

            //end_position += 1;
        } else {
            panic!("unexpected sentinel value <{}>", sentinel);
        }

        Ok(())
    }
}

// Impl QType & QClass enums
derive_enum!(QType, u16);
derive_enum!(QClass, u16);
derive_enum!(PacketType, u16);

impl<'a> ToFromNetworkOrder<'a> for DNSPacketFlags {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSPacketFlags, ResponseCode, OpCode, PacketType};
    ///
    /// let flags = DNSPacketFlags {
    ///     packet_type: PacketType::Response,
    ///     op_code: OpCode::IQuery,
    ///     authorative_answer: true,
    ///     truncated: true,
    ///     recursion_desired: true,
    ///     recursion_available: true,
    ///     z: 0b111,
    ///     response_code: ResponseCode::NoError
    /// };
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(flags.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0b1000_1111, 0b1111_0000]);
    /// ```   
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        // combine all flags according to structure
        //                               1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let mut flags = (self.packet_type as u16) << 15;
        flags |= (self.op_code as u16) << 11;
        flags |= (self.authorative_answer as u16) << 10;
        flags |= (self.truncated as u16) << 9;
        flags |= (self.recursion_desired as u16) << 8;
        flags |= (self.recursion_available as u16) << 7;
        flags |= (self.z as u16) << 4;
        flags |= self.response_code as u16;

        buffer.write_u16::<BigEndian>(flags)?;
        Ok(2)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSPacketFlags, ResponseCode, OpCode, PacketType};
    ///
    /// let b = vec![0b1000_1111, 0b1111_0000];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = DNSPacketFlags::default();
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// println!("{:?}", v);
    /// assert_eq!(v.packet_type, PacketType::Response);
    /// assert_eq!(v.op_code, OpCode::IQuery);
    /// assert!(v.authorative_answer);
    /// assert!(v.truncated);
    /// assert!(v.recursion_desired);
    /// assert!(v.recursion_available);
    /// assert_eq!(v.z, 0b111);
    /// assert_eq!(v.response_code, ResponseCode::NoError);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
        // read as u16
        let flags = buffer.read_u16::<BigEndian>()?;

        // decode all flags according to structure
        //                               1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        // check for packet_type inconsistencies
        let packet_type = flags >> 15;
        debug_assert!(
            packet_type == 0_u16 || packet_type == 1,
            "QR is neither a question nor a response, value = {}",
            packet_type
        );

        self.packet_type = packet_type.try_into()?;

        self.op_code = OpCode::try_from(flags >> 11 & 0b1111)?;
        self.authorative_answer = (flags >> 10) & 1 == 1;
        self.truncated = (flags >> 9) & 1 == 1;
        self.recursion_desired = (flags >> 8) & 1 == 1;
        self.recursion_available = (flags >> 7) & 1 == 1;
        self.z = (flags >> 7 & 0b111) as u8;
        self.response_code = ResponseCode::try_from(flags & 0b1111)?;

        Ok(())
    }
}

// impl<'a> ToFromNetworkOrder<'a> for DNSPacketHeader {
//     /// ```
//     /// use dnslib::network_order::ToFromNetworkOrder;
//     /// use dnslib::rfc1035::{DNSPacketFlags, DNSPacketHeader, ResponseCode, OpCode, PacketType};
//     ///
//     /// let flags = DNSPacketFlags {
//     ///     packet_type: PacketType::Response,
//     ///     op_code: OpCode::IQuery,
//     ///     authorative_answer: true,
//     ///     truncated: true,
//     ///     recursion_desired: true,
//     ///     recursion_available: true,
//     ///     z: 0b111,
//     ///     response_code: ResponseCode::NoError
//     /// };
//     ///
//     /// let packet = DNSPacketHeader {
//     ///     id: 0x1234,
//     ///     flags: flags,
//     ///     qd_count: 0x1234,
//     ///     an_count: 0x1234,
//     ///     ns_count: 0x1234,
//     ///     ar_count: 0x1234,
//     /// };
//     ///
//     /// let mut buffer: Vec<u8> = Vec::new();
//     /// assert!(packet.to_network_bytes(&mut buffer).is_ok());
//     /// assert_eq!(buffer, &[0x12, 0x34, 0b1000_1111, 0b1111_0000, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34]);
//     /// ```
//     fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
//         self.id.to_network_bytes(buffer)?;
//         self.flags.to_network_bytes(buffer)?;
//         self.qd_count.to_network_bytes(buffer)?;
//         self.an_count.to_network_bytes(buffer)?;
//         self.ns_count.to_network_bytes(buffer)?;
//         self.ar_count.to_network_bytes(buffer)?;
//         Ok(12)
//     }

//     /// ```
//     /// use std::io::Cursor;
//     /// use dnslib::network_order::ToFromNetworkOrder;
//     /// use dnslib::rfc1035::{DNSPacketHeader, DNSPacketFlags, ResponseCode, OpCode};
//     ///
//     /// let b = vec![0x12, 0x34, 0b1000_1111, 0b1111_0000, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34];
//     /// let mut buffer = Cursor::new(b.as_slice());
//     /// let mut packet = DNSPacketHeader::default();
//     /// assert!(packet.from_network_bytes(&mut buffer).is_ok());
//     /// assert_eq!(packet.id, 0x1234);
//     /// assert_eq!(packet.qd_count, 0x1234);
//     /// assert_eq!(packet.an_count, 0x1234);
//     /// assert_eq!(packet.ns_count, 0x1234);
//     /// assert_eq!(packet.ar_count, 0x1234);
//     /// ```
//     fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
//         self.id.from_network_bytes(buffer)?;
//         self.flags.from_network_bytes(buffer)?;
//         self.qd_count.from_network_bytes(buffer)?;
//         self.an_count.from_network_bytes(buffer)?;
//         self.ns_count.from_network_bytes(buffer)?;
//         self.ar_count.from_network_bytes(buffer)?;
//         Ok(())
//     }
// }

impl<'a> ToFromNetworkOrder<'a> for DnsResponse<'a> {
    fn to_network_bytes(&self, _buffer: &mut Vec<u8>) -> Result<usize> {
        Ok(0)
    }

    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        self.name.from_network_bytes(buffer)?;
        self.r#type.from_network_bytes(buffer)?;
        self.class.from_network_bytes(buffer)?;
        self.ttl.from_network_bytes(buffer)?;
        self.rd_length.from_network_bytes(buffer)?;
        Ok(())
    }
}

// impl<'a> ToFromNetworkOrder<'a> for DNSQuestion<'a> {
//     /// ```
//     /// use dnslib::network_order::ToFromNetworkOrder;
//     /// use dnslib::rfc1035::{DNSQuestion, QClass, DomainName, QType};
//     /// use dnslib::network_order::{SAMPLE_DOMAIN, SAMPLE_SLICE_EXTENDED};
//     ///
//     /// let mut buffer: Vec<u8> = Vec::new();
//     /// let qn = DomainName::try_from(SAMPLE_DOMAIN).unwrap();
//     ///
//     /// let question = DNSQuestion {
//     ///     name: qn,
//     ///     r#type: QType::A,
//     ///     class: QClass::IN,
//     /// };
//     ///
//     /// let converted = question.to_network_bytes(&mut buffer);
//     /// assert!(converted.is_ok());
//     /// let length = converted.unwrap();
//     /// assert_eq!(length, 19);
//     ///
//     /// assert_eq!(&buffer, SAMPLE_SLICE_EXTENDED);
//     /// ```
//     fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
//         let mut length = self.name.to_network_bytes(buffer)?;
//         length += self.r#type.to_network_bytes(buffer)?;
//         length += self.class.to_network_bytes(buffer)?;
//         Ok(length)
//     }

//     /// ```
//     /// use std::io::Cursor;
//     /// use dnslib::network_order::ToFromNetworkOrder;
//     /// use dnslib::rfc1035::{DNSQuestion, QType, QClass};
//     /// use dnslib::network_order::{SAMPLE_DOMAIN, SAMPLE_SLICE, SAMPLE_SLICE_EXTENDED};
//     ///
//     /// let mut buffer = Cursor::new(SAMPLE_SLICE_EXTENDED.as_slice());
//     /// let mut question = DNSQuestion::default();
//     ///
//     /// assert!(question.from_network_bytes(&mut buffer).is_ok());
//     /// assert_eq!(&question.name.to_string(), SAMPLE_DOMAIN);
//     /// assert_eq!(question.r#type, QType::A);
//     /// assert_eq!(question.class, QClass::IN);
//     /// ```
//     fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
//         self.name.from_network_bytes(buffer)?;
//         self.r#type.from_network_bytes(buffer)?;
//         self.class.from_network_bytes(buffer)?;
//         Ok(())
//     }
// }

impl<'a, T> ToFromNetworkOrder<'a> for DNSPacket<T>
where
    T: ToFromNetworkOrder<'a>,
{
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = self.header.to_network_bytes(buffer)?;
        length += self.data.to_network_bytes(buffer)?;
        Ok(length)
    }

    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        self.header.from_network_bytes(buffer)?;
        self.data.from_network_bytes(buffer)?;
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
        assert_eq!(&dn.to_string(), "google.com.");

        // move forward to find second test: 0xc0, 0x0c
        buffer.seek(SeekFrom::Start(28)).unwrap();

        // read domain name
        let mut dn = DomainName::default();
        assert!(dn.from_network_bytes(&mut buffer).is_ok());
        assert_eq!(dn.0, &["google", "com"]);
        assert_eq!(&dn.to_string(), "google.com.");

        // move forward to find second test: 0x6e, 0x73, 0x31, 0xc0, 0x0c
        buffer.seek(SeekFrom::Start(40)).unwrap();

        // read domain name
        let mut dn = DomainName::default();
        assert!(dn.from_network_bytes(&mut buffer).is_ok());
        assert_eq!(dn.0, &["ns1", "google", "com"]);
        assert_eq!(&dn.to_string(), "ns1.google.com.");

        // move forward to find second test: 0x09, 0x64, 0x6e, 0x73, 0x2d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0xc0, 0x0c
        buffer.seek(SeekFrom::Start(46)).unwrap();

        // read domain name
        let mut dn = DomainName::default();
        assert!(dn.from_network_bytes(&mut buffer).is_ok());
        assert_eq!(dn.0, &["dns-admin", "google", "com"]);
        assert_eq!(&dn.to_string(), "dns-admin.google.com.");
    }

    #[test]
    fn dnspacket_to_network() {
        // flags
        let flags = DNSPacketFlags {
            packet_type: PacketType::Response,
            op_code: OpCode::IQuery,
            authorative_answer: true,
            truncated: true,
            recursion_desired: true,
            recursion_available: true,
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
