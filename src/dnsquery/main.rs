//! A DNS resource query
use std::io::Cursor;
use std::net::UdpSocket;

use log::debug;

// our DNS library
use dnslib::{
    error::DNSResult,
    format_buffer,
    network_order::{FromNetworkOrder},
    rfc1035::{DNSPacketHeader, DNSQuery, DNSResponse, DNSQuestion, ResponseCode, MAX_DNS_PACKET_SIZE, OPT},
    util::pretty_cursor,
};

// mod dnsrequest;
// use dnsrequest::DNSRequest;

mod args;
use args::CliOptions;

mod display;
use display::{display_data, DisplayWrapper};

fn main() -> DNSResult<()> {
    // manage arguments from command line
    let options = CliOptions::options()?;
    debug!("options: {:?}", &options);

    // bind to an ephemeral local port
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    debug!("socket: {:?}", &socket);

    // create the query from command line arguments
    let mut query = DNSQuery::default();
    let question = DNSQuestion::new(&options.domain, options.qtype, None)?;
    debug!("question to send: {:?}", &question);
    query.push_question(question);

    // by default we want OPT
    if !options.no_opt {
        // add the OPT pseudo-RR to the additional data
        let opt = OPT::default();
        query.additional = Some(vec![Box::new(opt)]);
    }
    debug!("query: {:?}", &query);
    println!("QUERY: {}", DisplayWrapper(&query));

    // send query
    query.send(&socket, &options.ns)?;

    // receive request
    let _received = receive_answer(&socket, options.debug)?;

    Ok(())
}

fn receive_answer(socket: &UdpSocket, debug: bool) -> DNSResult<usize> {
    // receive packet from endpoint
    let mut buf = [0; MAX_DNS_PACKET_SIZE];
    let received = socket.recv(&mut buf)?;
    let slice = &buf[..received];
    debug!("received buffer: {}", format_buffer!("X", &slice));
    debug!("received buffer: [{}", format_buffer!("C", &slice));

    // cursor is necessary to use the ToFromNetworkOrder trait
    let mut cursor = Cursor::new(&buf[..received]);

    // get response
    let mut dns_response = DNSResponse::default();
    dns_response.from_network_bytes(&mut cursor)?;    

    debug!("response header: {:?}", dns_response.header);
    debug!("response: {:?}", &dns_response);

    println!("ANSWER: {}", DisplayWrapper(&dns_response.header));

    // check return code
    if dns_response.header.flags.response_code != ResponseCode::NoError {
        eprintln!("Response error!");
        std::process::exit(1);
    }


    Ok(received)
}
