//! Build DNS queries
//!
use rand::Rng;

use dnslib::{
    rfc1035::{DNSPacket, DNSQuestion, DomainName, OpCode, PacketType, QClass, QType},
    error::DNSResult,
};

// placeholder for gathering DNS functions to prepare a request
pub struct DNSRequest;

impl DNSRequest {
    pub fn init_request(packet: &mut DNSPacket<DNSQuestion>, qtype: QType) -> DNSResult<()> {
        // create a random ID
        let mut rng = rand::thread_rng();
        packet.header.id = rng.gen::<u16>();

        packet.header.flags.packet_type = PacketType::Query;
        packet.header.flags.op_code = OpCode::Query;
        packet.header.flags.authorative_answer = false;
        packet.header.flags.truncated = false;
        packet.header.flags.recursion_desired = false;
        packet.header.flags.recursion_available = false;

        packet.header.qd_count = 1;
        packet.header.an_count = 0;
        packet.header.ns_count = 0;
        packet.header.ar_count = 0;

        // create question
        let dn = DomainName::try_from("www.google.com")?;
        let question = DNSQuestion {
            name: dn,
            r#type: qtype,
            class: QClass::IN,
        };

        packet.data = question;

        Ok(())
    }
}
