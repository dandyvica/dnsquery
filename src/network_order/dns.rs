//! All functions/trait to convert DNS structures to network order back & forth
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Result, Seek, SeekFrom};
use std::str;

use crate::derive_enum;
use crate::error::{DNSError, DNSResult};
use crate::network_order::ToFromNetworkOrder;
use crate::rfc1035::{
    CharacterString, DNSPacket, DNSPacketFlags, DomainName, LabelType, OpCode, PacketType, QClass,
    QType, ResponseCode,
};

impl<'a> ToFromNetworkOrder<'a> for CharacterString<'a> {
    /// ```
    /// use dnslib::rfc1035::{CharacterString, LabelType};
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let cs = CharacterString::from("www");
    /// let mut buffer: Vec<u8> = Vec::new();
    ///
    /// assert_eq!(cs.to_network_bytes(&mut buffer).unwrap(), 4);
    /// assert_eq!(&buffer, &[0x03, 0x77, 0x77, 0x77]);
    /// ```  
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_u8(self.length)?;
        self.data.to_network_bytes(buffer)?;

        Ok(self.length as usize + 1)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::CharacterString;
    ///
    /// let mut buffer = Cursor::new([0x06_u8, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65].as_slice());
    /// let mut cs = CharacterString::default();
    /// assert!(cs.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(cs.length, 6u8);
    /// assert_eq!(cs.data, "google");
    /// ```    
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        // get a reference on [u8]
        let position = buffer.position() as usize;
        let inner_data = buffer.get_ref();

        // first char is the string length
        self.length = inner_data[position] as u8;

        // move the cursor forward
        buffer.seek(SeekFrom::Current(self.length as i64))?;

        // save data
        self.data =
            str::from_utf8(&buffer.get_ref()[position + 1..position + self.length as usize + 1])?;
        Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for LabelType<'a> {
    /// ```
    /// use dnslib::rfc1035::{CharacterString, LabelType};
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let dt = LabelType::Label(CharacterString::from("www"));
    /// let mut buffer: Vec<u8> = Vec::new();
    ///
    /// assert_eq!(dt.to_network_bytes(&mut buffer).unwrap(), 4);
    /// assert_eq!(&buffer, &[0x03, 0x77, 0x77, 0x77]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        match self {
            LabelType::Label(label) => {
                let length = label.to_network_bytes(buffer)?;
                Ok(length)
            }
            LabelType::Root => {
                buffer.write_u8(0u8)?;
                Ok(1)
            }
        }
    }

    fn from_network_bytes(&mut self, _buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        unimplemented!("LabelType<'a>.from_network_bytes()");
        //Ok(())
    }
}

impl<'a> ToFromNetworkOrder<'a> for DomainName<'a> {
    /// ```
    /// use dnslib::rfc1035::DomainName;
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let dn = DomainName::try_from("www.google.ie").unwrap();
    /// let mut buffer: Vec<u8> = Vec::new();
    ///
    /// assert_eq!(dn.to_network_bytes(&mut buffer).unwrap(), 15);
    /// assert_eq!(&buffer, &[0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        for label in &self.labels {
            // write label
            length += label.to_network_bytes(buffer)?;
        }
        Ok(length)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DomainName, LabelType, CharacterString};
    ///
    /// // with sentinel = 0
    /// let mut buffer = Cursor::new([0x03_u8, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00].as_slice());
    /// let mut dn = DomainName::default();
    /// assert!(dn.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(dn.labels.len(), 4);
    /// assert_eq!(dn.labels,
    /// &[
    ///     LabelType::Label(CharacterString::from("www")),
    ///     LabelType::Label(CharacterString::from("google")),
    ///     LabelType::Label(CharacterString::from("ie")),
    ///     LabelType::Root
    /// ]);
    /// ```    
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        //dbg!("============================");

        // loop through the vector
        let start_position = buffer.position() as usize;

        // get a reference on inner data
        let inner_ref = buffer.get_ref();

        // fill-in labels from inner data
        let new_position = self.from_position(start_position, inner_ref)?;

        // set new position
        buffer.set_position(new_position as u64);

        // if a pointer, get pointer value and call
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
    ///     z: true,
    ///     authentic_data: true,
    ///     checking_disabled: true,
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
        flags |= (self.z as u16) << 6;
        flags |= (self.authentic_data as u16) << 5;
        flags |= (self.checking_disabled as u16) << 4;
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
    /// assert!(v.z);
    /// assert!(v.authentic_data);
    /// assert!(v.checking_disabled);
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
        // |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
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
        self.z = (flags >> 6 & 1) == 1;
        self.authentic_data = (flags >> 5 & 1) == 1;
        self.checking_disabled = (flags >> 4 & 1) == 1;
        self.response_code = ResponseCode::try_from(flags & 0b1111)?;

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
