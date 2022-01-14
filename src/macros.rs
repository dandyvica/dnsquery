// auto-implement the ToFromNetworkOrder trait for enums
#[macro_export]
macro_rules! derive_enum {
    ($t:ty, u8) => {
        impl<'a> ToFromNetworkOrder<'a> for $t {
            fn to_network_bytes(&self, v: &mut Vec<u8>) -> std::io::Result<usize> {
                v.write_u8(*self as u8)?;
                Ok(1)
            }

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
        impl<'a> ToFromNetworkOrder<'a> for $t {
            fn to_network_bytes(&self, v: &mut Vec<u8>) -> std::io::Result<usize> {
                v.write_u16::<BigEndian>(*self as u16)?;
                Ok(2)
            }

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
