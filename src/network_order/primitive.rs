//! All functions/trait to convert DNS structures to network order back & forth
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Result, Seek, SeekFrom};

use crate::error::DNSResult;
use crate::network_order::{FromNetworkOrder, ToNetworkOrder};

impl ToNetworkOrder for u8 {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(255_u8.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0xFF]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_u8(*self)?;
        Ok(1)
    }
}

impl<'a> FromNetworkOrder<'a> for u8 {
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::FromNetworkOrder;
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

impl ToNetworkOrder for u16 {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x1234_u16.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34]);
    /// ```   
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_u16::<BigEndian>(*self)?;
        Ok(2)
    }
}

impl<'a> FromNetworkOrder<'a> for u16 {
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::FromNetworkOrder;
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

impl ToNetworkOrder for u32 {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x12345678_u32.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_u32::<BigEndian>(*self)?;
        Ok(4)
    }
}

impl<'a> FromNetworkOrder<'a> for u32 {
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::FromNetworkOrder;
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

impl ToNetworkOrder for i32 {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x12345678_i32.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```   
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.write_i32::<BigEndian>(*self)?;
        Ok(2)
    }
}

impl<'a> FromNetworkOrder<'a> for i32 {
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::FromNetworkOrder;
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

impl ToNetworkOrder for &[u8] {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(&[0x12_u8, 0x34, 0x56, 0x78].to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.append(&mut self.to_vec());
        Ok(self.len())
    }
}

impl<'a> FromNetworkOrder<'a> for &[u8] {
    fn from_network_bytes(&mut self, _v: &mut Cursor<&[u8]>) -> DNSResult<()> {
        unimplemented!("&[u8].from_network_bytes()");
        //Ok(())
    }
}

impl<'a> ToNetworkOrder for &'a str {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(&[0x12_u8, 0x34, 0x56, 0x78].to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.append(&mut self.as_bytes().to_vec());
        Ok(self.len())
    }
}

impl<'a> FromNetworkOrder<'a> for &'a str {
    fn from_network_bytes(&mut self, _v: &mut Cursor<&[u8]>) -> DNSResult<()> {
        unimplemented!("&str.from_network_bytes()");
        //Ok(())
    }
}

impl ToNetworkOrder for String {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(String::from("wxy").to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x77, 0x78, 0x79]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.append(&mut self.as_bytes().to_vec());
        Ok(self.len())
    }
}

impl<'a> FromNetworkOrder<'a> for String {
    fn from_network_bytes(&mut self, buffer: &mut Cursor<&[u8]>) -> DNSResult<()> {
        // get a reference on [u8]
        let position = buffer.position() as usize;
        let inner_data = buffer.get_ref();

        // first char is the string length
        let length = inner_data[position] as u8;

        // move the cursor forward
        buffer.seek(SeekFrom::Current(length as i64))?;

        // save data
        self.push_str(std::str::from_utf8(
            &buffer.get_ref()[position + 1..position + length as usize + 1],
        )?);
        Ok(())
    }
}

impl<T: ToNetworkOrder> ToNetworkOrder for Option<T> {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
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
}

impl<'a, T: FromNetworkOrder<'a>> FromNetworkOrder<'a> for Option<T> {
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::FromNetworkOrder;
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

impl<T: ToNetworkOrder, const N: usize> ToNetworkOrder for [T; N] {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
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
}

impl<'a, T: FromNetworkOrder<'a>, const N: usize> FromNetworkOrder<'a> for [T; N] {
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::FromNetworkOrder;
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

impl<T> ToNetworkOrder for Vec<T>
where
    T: Default + ToNetworkOrder,
{
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
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
}

impl<'a, T> FromNetworkOrder<'a> for Vec<T>
where
    T: Default + FromNetworkOrder<'a>,
{
    /// ```
    /// use std::io::Cursor;
    /// use dnslib::network_order::FromNetworkOrder;
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

impl ToNetworkOrder for Vec<Box<dyn ToNetworkOrder>> {
    /// ```
    /// use dnslib::network_order::ToNetworkOrder;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let v: Vec<Box<dyn ToNetworkOrder>> = vec![Box::new(0xFFu8), Box::new(0x1234u16), Box::new(0x12345678u32)];
    /// assert_eq!(v.to_network_bytes(&mut buffer).unwrap(), 7);
    /// //assert_eq!(&buffer, &[0xFF; 18]);
    /// ```    
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        // copy data for each element
        for item in self {
            length += item.to_network_bytes(buffer)?;
        }

        Ok(length)
    }
}

impl<'a> FromNetworkOrder<'a> for Vec<Box<dyn FromNetworkOrder<'a>>> {
    fn from_network_bytes(&mut self, _buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        unimplemented!("Vec<Box<dyn ToFromNetworkOrder<'a>>>.from_network_bytes()");
        //Ok(())
    }
}

impl<'a, T> ToNetworkOrder for std::marker::PhantomData<&'a T> {
    fn to_network_bytes(&self, _buffer: &mut Vec<u8>) -> Result<usize> {
        Ok(0)
    }
}

impl<'a, T> FromNetworkOrder<'a> for std::marker::PhantomData<&'a T> {
    fn from_network_bytes(&mut self, _buffer: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
        Ok(())
    }
}
