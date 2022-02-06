//! All functions/trait to convert DNS structures to network order back & forth
use std::net::UdpSocket;

use crate::error::DNSResult;
use crate::network_order::ToFromNetworkOrder;
use crate::rfc1035::{DNSPacketHeader, DNSQuestion, DomainName, QType, QClass, HINFO};
use dns_derive::DnsStruct;

#[derive(Debug, DnsStruct)]
pub struct DNSResponse<'a> {
    pub header: DNSPacketHeader,
    pub questions: Vec<DNSQuestion<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
}

#[derive(Debug)]
pub struct ResourceRecord<'a> {
    pub name: DomainName<'a>, // an owner name, i.e., the name of the node to which this resource record pertains.
    pub r#type: QType,        // two octets containing one of the RR TYPE codes.
    pub class: QClass,        // two octets containing one of the RR CLASS codes.
    pub ttl: u32, //   a bit = 32 signed (actually unsigned) integer that specifies the time interval
    //   that the resource record may be cached before the source
    //   of the information should again be consulted.  Zero
    //   values are interpreted to mean that the RR can only be
    //   used for the transaction in progress, and should not be
    //   cached.  For example, SOA records are always distributed
    //   with a zero TTL to prohibit caching.  Zero values can
    //   also be used for extremely volatile data.
    pub rd_length: u16, // an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub rd_data: &'a [u8],
                        //  a variable length string of octets that describes the
                        //  resource.  The format of this information varies
                        //  according to the TYPE and CLASS of the resource record.
}

impl<'a> ToFromNetworkOrder<'a> for ResourceRecord<'a>
{
    fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        Ok(0)
    }

    fn from_network_bytes(&mut self, buffer: &mut std::io::Cursor<&'a [u8]>) -> DNSResult<()> {
        self.name.from_network_bytes(buffer)?;
        self.r#type.from_network_bytes(buffer)?;
        self.class.from_network_bytes(buffer)?;
        self.ttl.from_network_bytes(buffer)?;
        self.rd_length.from_network_bytes(buffer)?;
        self.rd_data = buffer.get_ref()[];
        Ok(())
    }
}

