//! All functions/trait to convert DNS structures to network order back & forth
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Result, Seek, SeekFrom};
use std::str;

use crate::derive_enum;
use crate::error::{DNSError, DNSResult};
use crate::network_order::ToFromNetworkOrder;
use crate::rfc1035::{
    CharacterString, DNSPacket, DNSPacketFlags, DNSPacketHeader, DNSQuestion, DnsResponse,
    DomainName, OpCode, PacketType, QClass, QType, ResponseCode, HINFO,
};

impl<'a> ToFromNetworkOrder<'a> for CharacterString<'a> {
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
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
    /// use dnslib::network_order::{SAMPLE_DOMAIN, SAMPLE_SLICE};
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
    /// use dnslib::network_order::{SAMPLE_DOMAIN, SAMPLE_SLICE};
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
        let mut end_position = buffer.position() as usize;
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

            end_position += 1;
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
    ///     is_authorative_answer: true,
    ///     is_truncated: true,
    ///     is_recursion_desired: true,
    ///     is_recursion_available: true,
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
        flags |= (self.is_authorative_answer as u16) << 10;
        flags |= (self.is_truncated as u16) << 9;
        flags |= (self.is_recursion_desired as u16) << 8;
        flags |= (self.is_recursion_available as u16) << 7;
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
    /// assert!(v.is_authorative_answer);
    /// assert!(v.is_truncated);
    /// assert!(v.is_recursion_desired);
    /// assert!(v.is_recursion_available);
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
        self.is_authorative_answer = (flags >> 10) & 1 == 1;
        self.is_truncated = (flags >> 9) & 1 == 1;
        self.is_recursion_desired = (flags >> 8) & 1 == 1;
        self.is_recursion_available = (flags >> 7) & 1 == 1;
        self.z = (flags >> 7 & 0b111) as u8;
        self.response_code = ResponseCode::try_from(flags & 0b1111)?;

        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for DNSPacketHeader {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSPacketFlags, DNSPacketHeader, ResponseCode, OpCode, PacketType};
    ///
    /// let flags = DNSPacketFlags {
    ///     packet_type: PacketType::Response,
    ///     op_code: OpCode::IQuery,
    ///     is_authorative_answer: true,
    ///     is_truncated: true,
    ///     is_recursion_desired: true,
    ///     is_recursion_available: true,
    ///     z: 0b111,
    ///     response_code: ResponseCode::NoError
    /// };
    ///
    /// let packet = DNSPacketHeader {
    ///     id: 0x1234,
    ///     flags: flags,
    ///     qd_count: 0x1234,
    ///     an_count: 0x1234,
    ///     ns_count: 0x1234,
    ///     ar_count: 0x1234,
    /// };
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(packet.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0b1000_1111, 0b1111_0000, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        self.id.to_network_bytes(buffer)?;
        self.flags.to_network_bytes(buffer)?;
        self.qd_count.to_network_bytes(buffer)?;
        self.an_count.to_network_bytes(buffer)?;
        self.ns_count.to_network_bytes(buffer)?;
        self.ar_count.to_network_bytes(buffer)?;
        Ok(12)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSPacketHeader, DNSPacketFlags, ResponseCode, OpCode};
    ///
    /// let b = vec![0x12, 0x34, 0b1000_1111, 0b1111_0000, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut packet = DNSPacketHeader::default();
    /// assert!(packet.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(packet.id, 0x1234);
    /// assert_eq!(packet.qd_count, 0x1234);
    /// assert_eq!(packet.an_count, 0x1234);
    /// assert_eq!(packet.ns_count, 0x1234);
    /// assert_eq!(packet.ar_count, 0x1234);
    /// ```
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
        self.id.from_network_bytes(buffer)?;
        self.flags.from_network_bytes(buffer)?;
        self.qd_count.from_network_bytes(buffer)?;
        self.an_count.from_network_bytes(buffer)?;
        self.ns_count.from_network_bytes(buffer)?;
        self.ar_count.from_network_bytes(buffer)?;
        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for DnsResponse<'a> {
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
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

impl<'a> ToFromNetworkOrder<'a> for DNSQuestion<'a> {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSQuestion, QClass, DomainName, QType};
    /// use dnslib::network_order::{SAMPLE_DOMAIN, SAMPLE_SLICE_EXTENDED};
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let qn = DomainName::try_from(SAMPLE_DOMAIN).unwrap();
    ///
    /// let question = DNSQuestion {
    ///     name: qn,
    ///     r#type: QType::A,
    ///     class: QClass::IN,
    /// };
    ///
    /// let converted = question.to_network_bytes(&mut buffer);
    /// assert!(converted.is_ok());
    /// let length = converted.unwrap();
    /// assert_eq!(length, 19);
    ///
    /// assert_eq!(&buffer, SAMPLE_SLICE_EXTENDED);
    /// ```
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = self.name.to_network_bytes(buffer)?;
        length += self.r#type.to_network_bytes(buffer)?;
        length += self.class.to_network_bytes(buffer)?;
        Ok(length)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSQuestion, QType, QClass};
    /// use dnslib::network_order::{SAMPLE_DOMAIN, SAMPLE_SLICE, SAMPLE_SLICE_EXTENDED};
    ///
    /// let mut buffer = Cursor::new(SAMPLE_SLICE_EXTENDED.as_slice());
    /// let mut question = DNSQuestion::default();
    ///
    /// assert!(question.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(&question.name.to_string(), SAMPLE_DOMAIN);
    /// assert_eq!(question.r#type, QType::A);
    /// assert_eq!(question.class, QClass::IN);
    /// ```    
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        self.name.from_network_bytes(buffer)?;
        self.r#type.from_network_bytes(buffer)?;
        self.class.from_network_bytes(buffer)?;
        Ok(())
    }
}

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