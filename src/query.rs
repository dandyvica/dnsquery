//! All functions/trait to convert DNS structures to network order back & forth
use std::net::UdpSocket;

use log::debug;
use rand::Rng;

use crate::error::DNSResult;
use crate::format_buffer;
use crate::network_order::ToFromNetworkOrder;
use crate::rfc1035::{DNSPacketHeader, DNSQuestion, OpCode, PacketType, OPT};
use dns_derive::DnsStruct;

#[derive(Debug, DnsStruct)]
pub struct DNSQuery<'a> {
    pub header: DNSPacketHeader,
    pub questions: Vec<DNSQuestion<'a>>,
    pub opt: Option<OPT<'a>>,
}

impl<'a> Default for DNSQuery<'a> {
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

impl<'a> DNSQuery<'a> {
    // Add another question into the list of questions to send
    pub fn push_question(&mut self, question: DNSQuestion<'a>) {
        self.questions.push(question);

        // add we add a question, we need to increment the counter
        self.header.qd_count += 1;
    }

    // Send the query through the wire
    pub fn send(&self, socket: &UdpSocket, endpoint: &str) -> DNSResult<()> {
        // convert to network bytes
        let mut buffer: Vec<u8> = Vec::new();
        self.to_network_bytes(&mut buffer)?;
        debug!("query buffer: {}", format_buffer!("X", buffer));
        debug!("query buffer: [{}", format_buffer!("C", buffer));

        // send packet through the wire
        let dest = format!("{}:53", endpoint);
        socket.send_to(&buffer, dest)?;

        Ok(())
    }
}
