//! A DNS resource query
use std::io::Cursor;
use std::net::UdpSocket;

// our DNS library
use dnslib::{
    error::DNSResult,
    network_order::ToFromNetworkOrder,
    rfc1035::{
        DNSPacket, DNSPacketHeader, DNSQuestion, DnsResponse, QType, HINFO, MAX_DNS_PACKET_SIZE,
    },
    util::pretty_cursor,
};

mod dnsrequest;
use dnsrequest::DNSRequest;

mod args;
use args::CliOptions;

fn main() -> DNSResult<()> {
    // manage arguments from command line
    let options = CliOptions::options();

    if options.debug {
        eprintln!("{:#?}", options);
    }
    
    // bind to an ephermeral local port
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    // build and send query
    send_query(&socket, &options.host, options.qtype, options.debug)?;

    // receive request
    receive_answer(&socket, options.debug)?;

    Ok(())
}

fn send_query(socket: &UdpSocket, endpoint: &str, qtype: QType, debug:bool) -> DNSResult<()> {
    // build a new DNS packet
    let mut dns_packet = DNSPacket::<DNSQuestion>::default();
    DNSRequest::init_request(&mut dns_packet, qtype)?;
    if debug {
        eprintln!("{:#?}", dns_packet);
    } 

    println!("{}", dns_packet.header);

    // convert to network bytes
    let mut buffer: Vec<u8> = Vec::new();
    dns_packet.to_network_bytes(&mut buffer)?;

    // send packet through the wire
    let dest = format!("{}:53", endpoint);
    socket.send_to(&buffer, dest)?;

    Ok(())
}

fn receive_answer(socket: &UdpSocket, debug:bool) -> DNSResult<()> {
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
    println!("{}", dns_header_response);

    // if question is still in the response, skip it
    if dns_header_response.qd_count >= 1 {
        let mut question = DNSQuestion::default();
        for _ in 0..dns_header_response.qd_count {
            question.from_network_bytes(&mut cursor)?;
        }
    }

    // display data according to QType
    display_data(&mut cursor)?;

    Ok(())
}

fn display_data<'a>(cursor: &mut Cursor<&'a [u8]>) -> DNSResult<()> {
    // receive data
    let mut response = DnsResponse::default();
    response.from_network_bytes(cursor)?;

    // check out RR
    println!("qtype={:?}", response.r#type);
    match response.r#type {
        QType::A => {
            let mut ip = 0u32;
            ip.from_network_bytes(cursor)?;
            println!("ip={}", std::net::Ipv4Addr::from(ip));
        }
        QType::HINFO => {
            let mut hinfo = HINFO::default();
            hinfo.from_network_bytes(cursor)?;
            println!("HINFO: {:?}", hinfo);
        }
        _ => unimplemented!(),
    }

    Ok(())
}
