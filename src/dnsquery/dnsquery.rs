//! A DNS resource query
use std::io::Cursor;
use std::net::UdpSocket;

// our DNS library
use dnslib::{
    network_order::ToFromNetworkOrder,
    rfc1035::{DNSPacket, DNSPacketHeader, DNSQuestion},
};

mod dnsrequest;
use dnsrequest::DNSRequest;

fn main() -> std::io::Result<()> {
    // bind to an ephermeral local port
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    // build a new DNS packet
    let mut dns_packet = DNSPacket::<DNSQuestion>::default();
    DNSRequest::init_request(&mut dns_packet);
    println!("{:#?}", dns_packet);

    // convert to network bytes
    let mut buffer: Vec<u8> = Vec::new();
    dns_packet.to_network_bytes(&mut buffer)?;

    // send packet through the wire
    //let message = String::from("hello").into_bytes();
    socket.send_to(&buffer, "8.8.8.8:53")?;

    // receive packet from endpoint
    let mut buf = [0; 512];
    match socket.recv(&mut buf) {
        Ok(received) => println!("received {} bytes {:X?}", received, &buf[..received]),
        Err(e) => println!("recv function failed: {:?}", e),
    }

    // checkout DNS header
    let mut dns_header = DNSPacketHeader::default();
    let mut cursor = Cursor::new(&buf[0..12]);
    dns_header.from_network_bytes(&mut cursor);

    Ok(())
}
