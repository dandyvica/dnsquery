// auto-implement the ToFromNetworkOrder trait for enums
#[macro_export]
macro_rules! derive_enum {
    ($t:ty, u8) => {
        impl ToNetworkOrder for $t {
            fn to_network_bytes(&self, v: &mut Vec<u8>) -> std::io::Result<usize> {
                v.write_u8(*self as u8)?;
                Ok(1)
            }
        }

        impl<'a> FromNetworkOrder<'a> for $t {
            fn from_network_bytes(&mut self, v: &mut std::io::Cursor<&[u8]>) -> DNSResult<()> {
                let value = v.read_u8()?;
                match <$t>::try_from(value) {
                    Ok(ct) => {
                        *self = ct;
                        Ok(())
                    }
                    Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                }
            }
        }
    };

    ($t:ty, u16) => {
        impl ToNetworkOrder for $t {
            fn to_network_bytes(&self, v: &mut Vec<u8>) -> std::io::Result<usize> {
                v.write_u16::<BigEndian>(*self as u16)?;
                Ok(2)
            }
        }

        impl<'a> FromNetworkOrder<'a> for $t {
            fn from_network_bytes(&mut self, v: &mut std::io::Cursor<&[u8]>) -> DNSResult<()> {
                let value = v.read_u16::<BigEndian>()?;
                match <$t>::try_from(value) {
                    Ok(ct) => {
                        *self = ct;
                        Ok(())
                    }
                    Err(e) => Err(DNSError::new(&e)),
                }
            }
        }
    };
}

// useful helpers for tests
#[macro_export]
macro_rules! test_from_network {
    ($slice:ident, $t:ty) => {{
        let s = crate::util::get_sample_slice($slice);
        let mut buffer = std::io::Cursor::new(s.as_slice());
        let mut v = <$t>::default();
        assert!(v.from_network_bytes(&mut buffer).is_ok());
        v
    }};
}

#[macro_export]
macro_rules! test_to_network {
    ($data:ident) => {{
        let mut buffer: Vec<u8> = Vec::new();
        let bytes_written = $data.to_network_bytes(&mut buffer).unwrap();

        (buffer, bytes_written)
    }};
}
