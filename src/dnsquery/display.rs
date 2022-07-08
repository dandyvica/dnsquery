//! Display method: as we can't impl the Display trait outside the module where it's defined, and
//! to not put these methods in the lib, use a wrapper
use std::fmt;
use std::io::Cursor;

use log::debug;

use dnslib::{
    error::DNSResult,
    network_order::FromNetworkOrder,
    rfc1035::{
        DNSPacketFlags, DNSPacketHeader, DNSQuery, DNSQuestion, DNSResourceRecord, DNSResponse,
        DomainName, PacketType, QType, RdData, A, AAAA, HINFO, MX, NS, SOA, TXT,
    },
};

// a helper macro for displaying RR data when it's easy
#[macro_export]
macro_rules! rr_display {
    ($rr:ty, $cursor:ident) => {{
        let mut x = <$rr>::default();
        x.from_network_bytes($cursor)?;
        println!("\"{}\"", self::DisplayWrapper(&x));
    }};
}

pub struct DisplayWrapper<'a, T>(pub &'a T);

// Now we can implement the Display trait for DisplayWrapper for all structure we want to display
impl fmt::Display for DisplayWrapper<'_, DomainName> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for DisplayWrapper<'_, SOA> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mname:{} rname:{} serial:{} refresh:{} retry:{} expire:{} minimum:{}",
            self.0.mname,
            self.0.rname,
            self.0.serial,
            self.0.refresh,
            self.0.retry,
            self.0.expire,
            self.0.minimum
        )
    }
}

impl fmt::Display for DisplayWrapper<'_, MX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "preference:{} exchange:{}",
            self.0.preference, self.0.exchange,
        )
    }
}

impl fmt::Display for DisplayWrapper<'_, DNSPacketHeader> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        write!(f, "id:{:X}({}) ", self.0.id, self.0.id)?;
        write!(f, "flags:[{}] ", DisplayWrapper(&self.0.flags))?;

        if self.0.flags.packet_type == PacketType::Query {
            write!(f, "qd:{}", self.0.qd_count)
        } else {
            write!(
                f,
                "qd:{}, an:{} ns:{} ar:{}",
                self.0.qd_count, self.0.an_count, self.0.ns_count, self.0.ar_count
            )
        }
    }
}

impl fmt::Display for DisplayWrapper<'_, DNSPacketFlags> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        write!(f, "{:?} ", self.0.packet_type)?;

        if self.0.packet_type == PacketType::Query {
            write!(
                f,
                "opcode:{:?} rd:{}",
                self.0.op_code, self.0.recursion_desired
            )
        } else {
            write!(
                f,
                "opcode:{:?} tc:{} ra:{} rcode:{:?}",
                self.0.op_code, self.0.truncated, self.0.recursion_available, self.0.response_code
            )
        }
    }
}

impl fmt::Display for DisplayWrapper<'_, DNSQuestion> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "domain:{} qtype:{:?} class:{:?}",
            self.0.name, self.0.r#type, self.0.class
        )
    }
}

impl fmt::Display for DisplayWrapper<'_, DNSQuery> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // header first
        write!(f, "{} ", DisplayWrapper(&self.0.header))?;

        // all questions (usually only 1)
        for (i, question) in self.0.question.iter().enumerate() {
            write!(f, "question#{}: [{}]", i + 1, DisplayWrapper(question))?;
        }

        // now OPT data for EDNS0
        write!(f, "")
    }
}

// The global display method
pub fn display_data(dns_response: &DNSResponse) -> DNSResult<()> {
    debug!("response: {:?}", &dns_response);
    debug!("response header: {:?}", dns_response.header);

    // print out the header first
    println!("ANSWER: {}", DisplayWrapper(&dns_response.header));

    // print out answers
    for answer in &dns_response.answer {
        display_resource(answer);
    }

    if dns_response.authority.is_some() {
        for authorative in dns_response.authority.as_ref().unwrap() {
            display_resource(authorative);
        }
    }

    Ok(())
}

pub fn display_resource(rr: &DNSResourceRecord) {
    match rr.r#type {
        QType::A => match &rr.rd_data {
            Some(RdData::A(ipv4)) => {
                println!("{}", std::net::Ipv4Addr::from(*ipv4));
            }
            _ => panic!("oups"),
        },
        QType::HINFO => match &rr.rd_data {
            Some(RdData::HINFO(hinfo)) => {
                println!("HINFO: {:?}", hinfo);
            }
            _ => panic!("oups"),
        },
        QType::AAAA => match &rr.rd_data {
            Some(RdData::AAAA(ipv6)) => {
                println!("{}", std::net::Ipv6Addr::from(*ipv6));
            }
            _ => panic!("oups"),
        },
        // QType::SOA => {
        //     let mut soa = SOA::default();
        //     soa.from_network_bytes(cursor)?;
        //     println!("{}", DisplayWrapper(&soa));
        // }
        // QType::TXT => {
        //     let mut txt = TXT::default();
        //     txt.from_network_bytes(cursor)?;
        //     println!("\"{}\"", txt);
        // }
        // QType::NS => rr_display!(NS, cursor),
        // QType::MX => rr_display!(MX, cursor),
        _ => unimplemented!(),
    }
}

// pub fn display_data<'a>(cursor: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
//     // receive data
//     let mut response = DNSQuestion::default();
//     response.from_network_bytes(cursor)?;
//     //println!("{:#?}", response);

//     // check out RR
//     print!("qtype:{:?} qclass:{:?}\t", response.r#type, response.class);
//     match response.r#type {
//         QType::A => {
//             let mut ip = A::default();
//             ip.from_network_bytes(cursor)?;
//             println!("{}", std::net::Ipv4Addr::from(ip));
//         }
//         QType::HINFO => {
//             let mut hinfo = HINFO::default();
//             hinfo.from_network_bytes(cursor)?;
//             println!("HINFO: {:?}", hinfo);
//         }
//         QType::AAAA => {
//             let mut aaaa = AAAA::default();
//             aaaa.from_network_bytes(cursor)?;
//             println!("{}", std::net::Ipv6Addr::from(aaaa));
//         }
//         QType::SOA => {
//             let mut soa = SOA::default();
//             soa.from_network_bytes(cursor)?;
//             println!("{}", DisplayWrapper(&soa));
//         }
//         QType::TXT => {
//             let mut txt = TXT::default();
//             txt.from_network_bytes(cursor)?;
//             println!("\"{}\"", txt);
//         }
//         QType::NS => rr_display!(NS, cursor),
//         QType::MX => rr_display!(MX, cursor),
//         _ => unimplemented!(),
//     }

//     Ok(())
// }
