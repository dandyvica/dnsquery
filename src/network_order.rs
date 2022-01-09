//! All functions/trait to convert DNS structures to network order back & forth
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::io::Result;

use crate::derive_enum;
use crate::rfc1035::{
    DNSPacket, DNSPacketFlags, DNSPacketHeader, DNSQuestion, OpCode, QClass, QName, QType,
    ResponseCode,
};

// functions to convert or build TLS structures
pub trait ToFromNetworkOrder {
    // copy structure data to a network-order buffer
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize>;

    // copy from a network-order buffer to a structure
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()>;
}

impl ToFromNetworkOrder for u8 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(255_u8.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0xFF]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_u8(*self)?;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        *self = v.read_u8()?;
        Ok(())
    }
}

impl ToFromNetworkOrder for u16 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x1234_u16.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34]);
    /// ```   
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_u16::<BigEndian>(*self)?;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        *self = v.read_u16::<BigEndian>()?;
        Ok(())
    }
}

impl ToFromNetworkOrder for u32 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x12345678_u32.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_u32::<BigEndian>(*self)?;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        *self = v.read_u32::<BigEndian>()?;
        Ok(())
    }
}

impl ToFromNetworkOrder for i32 {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x12345678_i32.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```   
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_i32::<BigEndian>(*self)?;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        *self = v.read_i32::<BigEndian>()?;
        Ok(())
    }
}

impl<T: ToFromNetworkOrder> ToFromNetworkOrder for Option<T> {
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
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        if self.is_none() {
            Ok(0)
        } else {
            self.as_ref().unwrap().to_network_bytes(v)
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        if self.is_none() {
            Ok(())
        } else {
            self.as_mut().unwrap().from_network_bytes(v)
        }
    }
}

impl<T: ToFromNetworkOrder, const N: usize> ToFromNetworkOrder for [T; N] {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert_eq!([0xFFFF_u16; 10].to_network_bytes(&mut buffer).unwrap(), 20);
    /// assert_eq!(buffer, &[0xFF; 20]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        for x in self {
            // first convert x to network bytes
            let mut buffer: Vec<u8> = Vec::new();
            length += x.to_network_bytes(&mut buffer)?;

            v.append(&mut buffer);
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        for x in self {
            x.from_network_bytes(v)?;
        }
        //v.read_exact(self)?;
        Ok(())
    }
}

impl<T> ToFromNetworkOrder for Vec<T>
where
    T: Default + ToFromNetworkOrder,
{
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let v = vec![[0xFFFF_u16;3],[0xFFFF;3],[0xFFFF;3]];
    /// assert_eq!(v.to_network_bytes(&mut buffer).unwrap(), 18);
    /// assert_eq!(&buffer, &[0xFF; 18]);
    /// ```
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        // copy data for each element
        for item in self {
            length += item.to_network_bytes(v)?;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        // the length field holds the length of data field in bytes
        let length = v.get_ref().len() / std::mem::size_of::<T>();
        for _ in 0..length {
            let mut u: T = T::default();
            u.from_network_bytes(v)?;
            self.push(u);
        }
        Ok(())
    }
}

impl ToFromNetworkOrder for QName {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::QName;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let qn = QName::from_vec(&[3, 97, 97, 97, 2, 98, 98, 1, 99, 0]);
    ///
    /// let converted = qn.to_network_bytes(&mut buffer);
    /// assert!(converted.is_ok());
    /// let length = converted.unwrap();
    /// assert_eq!(length, 10);
    ///
    /// assert_eq!(buffer, &[3, 97, 97, 97, 2, 98, 98, 1, 99, 0]);
    /// ```
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        // calculate length of what is converted
        let mut length = 0usize;

        for x in self.0.iter() {
            x.0.to_network_bytes(v)?;
            x.1.to_network_bytes(v)?;
            length += 1 + if x.1.is_some() {
                x.1.as_ref().unwrap().len()
            } else {
                0
            };
        }
        Ok(length)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::QName;
    ///
    /// let b = vec![0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut qn = QName::default();
    /// assert!(qn.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(qn.0.get(0).unwrap(), &(3_u8, Some("www".as_bytes().to_vec())));
    /// assert_eq!(qn.0.get(1).unwrap(), &(6_u8, Some("google".as_bytes().to_vec())));
    /// assert_eq!(qn.0.get(2).unwrap(), &(2_u8, Some("ie".as_bytes().to_vec())));
    /// ```
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        // sanity check: last byte should by the sentinel
        debug_assert!(v.get_mut().last() == Some(&0u8));

        // loop through the vector
        let mut index = 0usize;

        loop {
            let size = v.get_mut()[index];

            // if we've reached the sentinel, exit
            if size == 0 {
                break;
            }

            self.0.push((
                size,
                Some(v.get_mut()[index + 1..index + 1 + size as usize].to_vec()),
            ));

            // adjust length
            index += size as usize + 1;
        }

        // add the sentinel length
        self.0.push((0_u8, None));

        Ok(())
    }
}

// Impl QType & QClass enums
derive_enum!(QType, u16);
derive_enum!(QClass, u16);

impl ToFromNetworkOrder for DNSPacketFlags {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSPacketFlags, ResponseCode, OpCode};
    ///
    /// let flags = DNSPacketFlags {
    ///     is_response: true,
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
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        // combine all flags according to structure
        //                               1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let mut flags = (self.is_response as u16) << 15;
        flags |= (self.op_code as u16) << 11;
        flags |= (self.is_authorative_answer as u16) << 10;
        flags |= (self.is_truncated as u16) << 9;
        flags |= (self.is_recursion_desired as u16) << 8;
        flags |= (self.is_recursion_available as u16) << 7;
        flags |= (self.z as u16) << 4;
        flags |= self.response_code as u16;

        v.write_u16::<BigEndian>(flags)?;
        Ok(2)
    }

    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSPacketFlags, ResponseCode, OpCode};
    ///
    /// let b = vec![0b1000_1111, 0b1111_0000];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut v = DNSPacketFlags::default();
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// println!("{:?}", v);
    /// assert!(v.is_response);
    /// assert_eq!(v.op_code, OpCode::IQuery);
    /// assert!(v.is_authorative_answer);
    /// assert!(v.is_truncated);
    /// assert!(v.is_recursion_desired);
    /// assert!(v.is_recursion_available);
    /// assert_eq!(v.z, 0b111);
    /// assert_eq!(v.response_code, ResponseCode::NoError);
    /// ```
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        // read as u16
        let flags = v.read_u16::<BigEndian>()?;

        // decode all flags according to structure
        //                               1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        self.is_response = (flags >> 15) == 1;

        match OpCode::try_from(flags >> 11 & 0b1111) {
            Ok(oc) => {
                self.op_code = oc;
            }
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        };

        self.is_authorative_answer = (flags >> 10) & 1 == 1;
        self.is_truncated = (flags >> 9) & 1 == 1;
        self.is_recursion_desired = (flags >> 8) & 1 == 1;
        self.is_recursion_available = (flags >> 7) & 1 == 1;
        self.z = (flags >> 7 & 0b111) as u8;

        match ResponseCode::try_from(flags & 0b1111) {
            Ok(rc) => {
                self.response_code = rc;
                Ok(())
            }
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }
}

impl ToFromNetworkOrder for DNSPacketHeader {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSPacketHeader, DNSPacketFlags, ResponseCode, OpCode};
    ///
    /// let flags = DNSPacketFlags {
    ///     is_response: true,
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
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        self.id.to_network_bytes(v)?;
        self.flags.to_network_bytes(v)?;
        self.qd_count.to_network_bytes(v)?;
        self.an_count.to_network_bytes(v)?;
        self.ns_count.to_network_bytes(v)?;
        self.ar_count.to_network_bytes(v)?;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        self.id.from_network_bytes(v)?;
        self.flags.from_network_bytes(v)?;
        self.qd_count.from_network_bytes(v)?;
        self.an_count.from_network_bytes(v)?;
        self.ns_count.from_network_bytes(v)?;
        self.ar_count.from_network_bytes(v)?;
        Ok(())
    }
}

impl ToFromNetworkOrder for DNSQuestion {
    /// ```
    /// use dnslib::network_order::ToFromNetworkOrder;
    /// use dnslib::rfc1035::{DNSQuestion, QClass, QName, QType};
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let qn = QName::from_vec(&[3, 97, 97, 97, 2, 98, 98, 1, 99, 0]);
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
    /// assert_eq!(length, 14);
    ///
    /// assert_eq!(buffer, &[3, 97, 97, 97, 2, 98, 98, 1, 99, 0, 0, 1, 0, 1]);
    /// ```
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        let mut length = self.name.to_network_bytes(v)?;
        length += self.r#type.to_network_bytes(v)?;
        length += self.class.to_network_bytes(v)?;
        Ok(length)
    }

    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        self.name.from_network_bytes(v)?;
        self.r#type.from_network_bytes(v)?;
        self.class.from_network_bytes(v)?;
        Ok(())
    }
}

impl<T> ToFromNetworkOrder for DNSPacket<T>
where
    T: ToFromNetworkOrder,
{
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        let mut length = self.header.to_network_bytes(v)?;
        length += self.data.to_network_bytes(v)?;
        Ok(length)
    }

    fn from_network_bytes(&mut self, v: &mut Cursor<&[u8]>) -> Result<()> {
        self.header.from_network_bytes(v)?;
        self.data.from_network_bytes(v)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnspacket_to_network() {
        // flags
        let flags = DNSPacketFlags {
            is_response: true,
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
        let qn = QName::from_vec(&[3, 97, 97, 97, 2, 98, 98, 1, 99, 0]);
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
        assert_eq!(length, 26);

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
                3,
                97,
                97,
                97,
                2,
                98,
                98,
                1,
                99,
                0,
                0,
                1,
                0,
                1
            ]
        );
    }
}
