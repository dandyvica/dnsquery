//! A DNS resource query
use std::io::Cursor;
use std::net::UdpSocket;

// our DNS library
use dnslib::{
    error::DNSResult,
    network_order::ToFromNetworkOrder,
    query::DNSQuery,
    rfc1035::{
        DNSPacket, DNSPacketHeader, DNSQuestion, QType, ResponseCode, MAX_DNS_PACKET_SIZE, OPT,
    },
    util::pretty_cursor,
};

mod dnsrequest;
use dnsrequest::DNSRequest;

mod args;
use args::CliOptions;

mod display;
use display::{display_data, DisplayWrapper};

fn main() -> DNSResult<()> {
    // manage arguments from command line
    let options = CliOptions::options()?;

    if options.debug {
        eprintln!("{:#?}", options);
    }

    // bind to an ephemeral local port
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    // create the query from command line arguments
    let mut query = DNSQuery::default();
    let question = DNSQuestion::new(&options.domain, options.qtype, None)?;
    query.push_question(question);

    // by default we want OPT
    if !options.no_opt {
        query.opt = Some(OPT::default());
    }

    println!("QUERY: {}", DisplayWrapper(&query));
    if options.debug {
        eprintln!("{:#?}", query);
    }

    // send query
    query.send(&socket, &options.ns)?;

    // receive request
    let _received = receive_answer(&socket, options.debug)?;

    Ok(())
}

fn send_query(
    domain: &str,
    socket: &UdpSocket,
    endpoint: &str,
    qtype: QType,
    debug: bool,
) -> DNSResult<()> {
    // build a new DNS packet
    let mut dns_packet = DNSPacket::<DNSQuestion>::default();
    DNSRequest::init_request(domain, &mut dns_packet, qtype)?;
    if debug {
        eprintln!("{:#?}", dns_packet);
    }

    println!("question: {}", DisplayWrapper(&dns_packet.header));

    // convert to network bytes
    let mut buffer: Vec<u8> = Vec::new();
    dns_packet.to_network_bytes(&mut buffer)?;

    // send packet through the wire
    let dest = format!("{}:53", endpoint);
    socket.send_to(&buffer, dest)?;

    Ok(())
}

fn receive_answer(socket: &UdpSocket, debug: bool) -> DNSResult<usize> {
    // receive packet from endpoint
    let mut buf = [0; MAX_DNS_PACKET_SIZE];
    let received = socket.recv(&mut buf)?;

    // cursor is necessary to use the ToFromNetworkOrder trait
    let mut cursor = Cursor::new(&buf[..received]);

    // get the DNS header
    let mut dns_header_response = DNSPacketHeader::default();
    dns_header_response.from_network_bytes(&mut cursor)?;

    if debug {
        eprintln!("{:#?}", dns_header_response);
        pretty_cursor(&cursor);
    }
    println!("ANSWER: {}", DisplayWrapper(&dns_header_response));

    // check return code
    if dns_header_response.flags.response_code != ResponseCode::NoError {
        eprintln!("Response error!");
        std::process::exit(1);
    }

    // if question is still in the response, skip it
    if dns_header_response.qd_count >= 1 {
        let mut question = DNSQuestion::default();
        for _ in 0..dns_header_response.qd_count {
            question.from_network_bytes(&mut cursor)?;
            //println!("{:#?}", question);
        }
    }

    // display data according to QType
    for _ in 1..=dns_header_response.an_count {
        display_data(&mut cursor)?;
    }

    Ok(received)
}
