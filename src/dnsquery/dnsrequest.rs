//! Build DNS queries
//!
use dnslib::rfc1035::{DNSPacket, DNSQuestion, OpCode, QClass, QName, QType};
use rand::Rng;

// placeholder for gathering DNS functions to prepare a request
pub struct DNSRequest;

impl DNSRequest {
    pub fn init_request(packet: &mut DNSPacket<DNSQuestion>) {
        // create a random ID
        let mut rng = rand::thread_rng();
        packet.header.id = rng.gen::<u16>();

        packet.header.flags.is_response = false;
        packet.header.flags.op_code = OpCode::Query;
        packet.header.flags.is_authorative_answer = false;
        packet.header.flags.is_truncated = false;
        packet.header.flags.is_recursion_desired = false;
        packet.header.flags.is_recursion_available = false;

        packet.header.qd_count = 1;
        packet.header.an_count = 0;
        packet.header.ns_count = 0;
        packet.header.ar_count = 0;

        // create question
        let qn = QName::from_label_list(&["www", "google", "com"]);
        let question = DNSQuestion {
            name: qn,
            r#type: QType::A,
            class: QClass::IN,
        };

        packet.data = question;
    }
}
