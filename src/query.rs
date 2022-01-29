//! All functions/trait to convert DNS structures to network order back & forth
use rand::Rng;

use crate::derive_enum;
use crate::error::{DNSError, DNSResult};
use crate::network_order::ToFromNetworkOrder;
use crate::rfc1035::{
    CharacterString, DNSPacket, DNSPacketFlags, DNSPacketHeader, DNSQuestion, DnsResponse,
    DomainName, DomainType, OpCode, PacketType, QClass, QType, ResponseCode, OPT,
};
use dns_derive::{DnsEnum, DnsStruct};

#[derive(Debug, DnsStruct)]
pub struct DnsQuery<'a> {
    header: DNSPacketHeader,
    questions: Vec<DNSQuestion<'a>>,
    opt: Option<OPT>,
}

impl<'a> Default for DnsQuery<'a> {
    fn default() -> Self {
        let mut header = DNSPacketHeader::default();

        // create a random ID
        let mut rng = rand::thread_rng();
        header.id = rng.gen::<u16>();

        header.flags.packet_type = PacketType::Query;
        header.flags.op_code = OpCode::Query;
        header.flags.recursion_desired = true;

        // all others fields are either 0 or false

        Self {
            header: header,
            questions: Vec::new(),
            opt: None,
        }
    }
}

impl<'a> DnsQuery<'a> {
    // Add another question into the list of questions to send
    pub fn push_question(&mut self, question: DNSQuestion<'a>) {
        self.questions.push(question);

        // add we add a question, we need to increment the counter
        self.header.qd_count += 1;
    }

    // Send the query through the wire
    // pub fn send(
    //     &self,
    //     domain: &str,
    //     socket: &UdpSocket,
    //     endpoint: &str,
    //     debug: bool,
    // ) -> DNSResult<()> {
    //     if debug {
    //         eprintln!("{:#?}", dns_packet);
    //     }

    //     println!("question: {}", DisplayWrapper(&self.header));

    //     // convert to network bytes
    //     let mut buffer: Vec<u8> = Vec::new();
    //     dns_packet.to_network_bytes(&mut buffer)?;

    //     // send packet through the wire
    //     let dest = format!("{}:53", endpoint);
    //     socket.send_to(&buffer, dest)?;

    //     Ok(())
    // }
}
