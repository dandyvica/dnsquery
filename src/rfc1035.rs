//! Base structures for DNS messages. Taken from https://datatracker.ietf.org/doc/html/rfc1035
//!
//! The DnsStruct procedural macro automatically defines the implementation of the ToFromNetworkOrder trait.
//! The DnsEnum procedural macro automatically implements Default, FromStr, TryFrom<u8> and TryFrom<u16>
//!
//! FIXME:  clean-up errors
//!         check DnsEnum macro
//! TODO:   start integration tests
//!         move DnsResponse to response.rs
use std::fmt;
use std::fmt::Debug;
use std::str;
use std::net::UdpSocket;

use log::debug;
use rand::Rng;

use crate::error::{DNSError, DNSResult, InternalError};
use crate::network_order::ToFromNetworkOrder;
use crate::util::is_pointer;
use crate::format_buffer;

use dns_derive::{DnsEnum, DnsStruct};

// DNS packets are called "messages" in RFC1035: 
// "All communications inside of the domain protocol are carried in a single format called a message"
#[derive(Debug, DnsStruct)]
pub struct DNSMessage<'a> {
    pub header: DNSPacketHeader,
    pub question: Vec<DNSQuestion<'a>>,
    pub answer: Option<DNSResourceRecord<'a>>,
    pub authority: Option<DNSResourceRecord<'a>>,
    pub additional: Option<DNSResourceRecord<'a>>,
}

impl<'a> DNSMessage<'a> {
    // Add another question into the list of questions to send
    pub fn push_question(&mut self, question: DNSQuestion<'a>) {
        self.question.push(question);

        // add we add a question, we need to increment the counter
        self.header.qd_count += 1;
    }

    // Send the query through the wire
    pub fn send(&self, socket: &UdpSocket, endpoint: &str) -> DNSResult<()> {
        // convert to network bytes
        let mut buffer: Vec<u8> = Vec::new();
        self.to_network_bytes(&mut buffer)?;
        debug!("query buffer: {}", format_buffer!("X", &buffer));
        debug!("query buffer: [{}", format_buffer!("C", &buffer));

        // send packet through the wire
        let dest = format!("{}:53", endpoint);
        debug!("destination: {}", dest);
        socket.send_to(&buffer, dest)?;

        Ok(())
    }
}

impl<'a> Default for DNSMessage<'a> {
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
            question: Vec::new(),
            answer: None,
            authority: None,
            additional: None,
        }
    }
}

// DNS packet with data
#[derive(Debug, Default)]
pub struct DNSPacket<T> {
    pub header: DNSPacketHeader,
    pub data: T,
}

pub const MAX_DNS_PACKET_SIZE: usize = 512;

// DNS packet header: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(Debug, Default, DnsStruct)]
pub struct DNSPacketHeader {
    pub id: u16, // A 16 bit identifier assigned by the program that
    //   generates any kind of query.  This identifier is copied
    //   the corresponding reply and can be used by the requester
    //   to match up replies to outstanding queries.
    pub flags: DNSPacketFlags,
    pub qd_count: u16, // an unsigned 16 bit integer specifying the number of
    //    entries in the question section.
    pub an_count: u16, // an unsigned 16 bit integer specifying the number of
    // resource records in the answer section.
    pub ns_count: u16, // an unsigned 16 bit integer specifying the number of name
    // server resource records in the authority records section.
    pub ar_count: u16, // an unsigned 16 bit integer specifying the number of
                       // resource records in the additional records section.
}

// Flags: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(Debug, Default)]
pub struct DNSPacketFlags {
    pub packet_type: PacketType, // A one bit field that specifies whether this message is a query (0), or a response (1).
    pub op_code: OpCode,         // A four bit field that specifies kind of query in this
    //  message.  This value is set by the originator of a query
    //  and copied into the response.  The values are:
    // 0               a standard query (QUERY)
    // 1               an inverse query (IQUERY)
    // 2               a server status request (STATUS)
    // 3-15            reserved for future use
    pub authorative_answer: bool, // Authoritative Answer - this bit is valid in responses,
    //and specifies that the responding name server is an
    //authority for the domain name in question section.
    //Note that the contents of the answer section may have
    //multiple owner names because of aliases.  The AA bit
    //corresponds to the name which matches the query name, or
    //the first owner name in the answer section.
    pub truncated: bool, //    TrunCation - specifies that this message was truncated
    //    due to length greater than that permitted on the
    //    transmission channel.
    pub recursion_desired: bool, // Recursion Desired - this bit may be set in a query and
    // is copied into the response.  If RD is set, it directs
    // the name server to pursue the query recursively.
    // Recursive query support is optional.
    pub recursion_available: bool, // Recursion Available - this be is set or cleared in a
    //  response, and denotes whether recursive query support is
    //  available in the name server.
    pub z: bool, // Reserved for future use.  Must be zero in all queries and responses.
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub response_code: ResponseCode, // Response code - this 4 bit field is set as part of
                                     //responses.  The values have the following
                                     //interpretation:
                                     //0               No error condition
                                     //1               Format error - The name server was
                                     //                unable to interpret the query.
                                     //2               Server failure - The name server was
                                     //                unable to process this query due to a
                                     //                problem with the name server.
                                     //3               Name Error - Meaningful only for
                                     //                responses from an authoritative name
                                     //                server, this code signifies that the
                                     //                domain name referenced in the query does
                                     //                not exist.
                                     //4               Not Implemented - The name server does
                                     //                not support the requested kind of query.
                                     //5               Refused - The name server refuses to
                                     //                perform the specified operation for
                                     //                policy reasons.  For example, a name
                                     //                server may not wish to provide the
                                     //                information to the particular requester,
                                     //                or a name server may not wish to perform
                                     //                a particular operation (e.g., zone
                                     //                transfer) for particular data.
                                     //6-15            Reserved for future use.
}

/// The flags' first bit is 0 or 1 meaning a question or a response. Better is to use an enum which is
/// both clearer and type oriented.
#[derive(Debug, Clone, Copy, PartialEq, DnsEnum)]
#[repr(u8)]
pub enum PacketType {
    Query = 0,
    Response = 1,
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        match *self {
            PacketType::Query => write!(f, "QUERY"),
            PacketType::Response => write!(f, "RESPONSE"),
        }
    }
}

// op codes: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(Debug, Clone, Copy, PartialEq, DnsEnum)]
#[repr(u8)]
pub enum OpCode {
    Query = 0,  //[RFC1035]
    IQuery = 1, // (Inverse Query, OBSOLETE)	[RFC3425]
    Status = 2, // [RFC1035]
    Unassigned = 3,
    Notify = 4, // [RFC1996]
    Update = 5, // [RFC2136]
    DOS = 6,    // DNS Stateful Operations (DSO)	[RFC8490]
                // 7-15 Unassigned
}

// response codes: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
#[derive(Debug, Clone, Copy, PartialEq, DnsEnum)]
#[repr(u16)]
pub enum ResponseCode {
    NoError = 0,  // No Error	[RFC1035]
    FormErr = 1,  // Format Error	[RFC1035]
    ServFail = 2, // Server Failure	[RFC1035]
    NXDomain = 3, // Non-Existent Domain	[RFC1035]
    NotImp = 4,   // Not Implemented	[RFC1035]
    Refused = 5,  // Query Refused	[RFC1035]
    YXDomain = 6, // Name Exists when it should not	[RFC2136][RFC6672]
    YXRRSet = 7,  // RR Set Exists when it should not	[RFC2136]
    NXRRSet = 8,  // RR Set that should exist does not	[RFC2136]
    //NotAuth = 9, // Server Not Authoritative for zone	[RFC2136]
    NotAuth = 9,    // Not Authorized	[RFC8945]
    NotZone = 10,   // Name not contained in zone	[RFC2136]
    DSOTYPENI = 11, // DSO-TYPE Not Implemented	[RFC8490]
    // 12-Unassigned = 15,
    BADVERS = 16, // Bad OPT Version	[RFC6891]
    //BADSIG = 16, // TSIG Signature Failure	[RFC8945]
    BADKEY = 17,    // Key not recognized	[RFC8945]
    BADTIME = 18,   // Signature out of time window	[RFC8945]
    BADMODE = 19,   // Bad TKEY Mode	[RFC2930]
    BADNAME = 20,   // Duplicate key name	[RFC2930]
    BADALG = 21,    // Algorithm not supported	[RFC2930]
    BADTRUNC = 22,  // 	Bad Truncation	[RFC8945]
    BADCOOKIE = 23, //	Bad/missing Server Cookie	[RFC7873]
}

// RR format
#[derive(Debug, Default, DnsStruct)]
pub struct DnsResponse<'a> {
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
                        //pub r_data: Vec<u8>, //  a variable length string of octets that describes the
                        //  resource.  The format of this information varies
                        //  according to the TYPE and CLASS of the resource record.
}

impl<'a> fmt::Display for DnsResponse<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        write!(
            f,
            "NAME:{} TYPE:{:?} CLASS:{:?} TTL:{} RDLENGTH={}",
            self.name, self.r#type, self.class, self.ttl, self.rd_length
        )
    }
}

// RR type codes: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
#[derive(Debug, Copy, Clone, PartialEq, DnsEnum)]
#[repr(u16)]
pub enum QType {
    A = 1,           // a host address	[RFC1035]
    NS = 2,          // an authoritative name server	[RFC1035]
    MD = 3,          // a mail destination (OBSOLETE - use MX)	[RFC1035]
    MF = 4,          // a mail forwarder (OBSOLETE - use MX)	[RFC1035]
    CNAME = 5,       // the canonical name for an alias	[RFC1035]
    SOA = 6,         // marks the start of a zone of authority	[RFC1035]
    MB = 7,          // a mailbox domain name (EXPERIMENTAL)	[RFC1035]
    MG = 8,          // a mail group member (EXPERIMENTAL)	[RFC1035]
    MR = 9,          // a mail rename domain name (EXPERIMENTAL)	[RFC1035]
    NULL = 10,       // a null RR (EXPERIMENTAL)	[RFC1035]
    WKS = 11,        // a well known service description	[RFC1035]
    PTR = 12,        // a domain name pointer	[RFC1035]
    HINFO = 13,      // host information	[RFC1035]
    MINFO = 14,      // mailbox or mail list information	[RFC1035]
    MX = 15,         // mail exchange	[RFC1035]
    TXT = 16,        // text strings	[RFC1035]
    RP = 17,         // for Responsible Person	[RFC1183]
    AFSDB = 18,      // for AFS Data Base location	[RFC1183][RFC5864]
    X25 = 19,        // for X.25 PSDN address	[RFC1183]
    ISDN = 20,       // for ISDN address	[RFC1183]
    RT = 21,         // for Route Through	[RFC1183]
    NSAP = 22,       // for NSAP address, NSAP style A record	[RFC1706]
    NSAPPTR = 23,    // for domain name pointer, NSAP style	[RFC1706]
    SIG = 24,        // for security signature	[RFC2536][RFC2931][RFC3110][RFC4034]
    KEY = 25,        // for security key	[RFC2536][RFC2539][RFC3110][RFC4034]
    PX = 26,         // X.400 mail mapping information	[RFC2163]
    GPOS = 27,       // Geographical Position	[RFC1712]
    AAAA = 28,       // IP6 Address	[RFC3596]
    LOC = 29,        // Location Information	[RFC1876]
    NXT = 30,        // Next Domain (OBSOLETE)	[RFC2535][RFC3755]
    EID = 31, // Endpoint Identifier	[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]		1995-06
    NIMLOC = 32, // Nimrod Locator	[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]		1995-06
    SRV = 33,    // Server Selection	[1][RFC2782]
    ATMA = 34, // ATM Address	[ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
    NAPTR = 35, // Naming Authority Pointer	[RFC3403]
    KX = 36,   // Key Exchanger	[RFC2230]
    CERT = 37, // CERT	[RFC4398]
    A6 = 38,   // A6 (OBSOLETE - use AAAA)	[RFC2874][RFC3226][RFC6563]
    DNAME = 39, // DNAME	[RFC6672]
    SINK = 40, // SINK	[Donald_E_Eastlake][draft-eastlake-kitchen-sink]		1997-11
    OPT = 41,  // OPT	[RFC3225][RFC6891]
    APL = 42,  // APL	[RFC3123]
    DS = 43,   // Delegation Signer	[RFC4034]
    SSHFP = 44, // SSH Key Fingerprint	[RFC4255]
    IPSECKEY = 45, // IPSECKEY	[RFC4025]
    RRSIG = 46, // RRSIG	[RFC4034]
    NSEC = 47, // NSEC	[RFC4034][RFC9077]
    DNSKEY = 48, // DNSKEY	[RFC4034]
    DHCID = 49, // DHCID	[RFC4701]
    NSEC3 = 50, // NSEC3	[RFC5155][RFC9077]
    NSEC3PARAM = 51, // NSEC3PARAM	[RFC5155]
    TLSA = 52, // TLSA	[RFC6698]
    SMIMEA = 53, // S/MIME cert association	[RFC8162]	SMIMEA/smimea-completed-template	2015-12-01
    Unassigned = 54, //
    HIP = 55,  // Host Identity Protocol	[RFC8005]
    NINFO = 56, // NINFO	[Jim_Reid]	NINFO/ninfo-completed-template	2008-01-21
    RKEY = 57, // RKEY	[Jim_Reid]	RKEY/rkey-completed-template	2008-01-21
    TALINK = 58, // Trust Anchor LINK	[Wouter_Wijngaards]	TALINK/talink-completed-template	2010-02-17
    CDS = 59,  // Child DS	[RFC7344]	CDS/cds-completed-template	2011-06-06
    CDNSKEY = 60, // DNSKEY(s) the Child wants reflected in DS	[RFC7344]		2014-06-16
    OPENPGPKEY = 61, // OpenPGP Key	[RFC7929]	OPENPGPKEY/openpgpkey-completed-template	2014-08-12
    CSYNC = 62, // Child-To-Parent Synchronization	[RFC7477]		2015-01-27
    ZONEMD = 63, // Message Digest Over Zone Data	[RFC8976]	ZONEMD/zonemd-completed-template	2018-12-12
    SVCB = 64, // Service Binding	[draft-ietf-dnsop-svcb-https-00]	SVCB/svcb-completed-template	2020-06-30
    HTTPS = 65, // HTTPS Binding	[draft-ietf-dnsop-svcb-https-00]	HTTPS/https-completed-template	2020-06-30
    // Unassigned	66-98
    SPF = 99,     // [RFC7208]
    UINFO = 100,  // [IANA-Reserved]
    UID = 101,    // [IANA-Reserved]
    GID = 102,    // [IANA-Reserved]
    UNSPEC = 103, // [IANA-Reserved]
    NID = 104,    // [RFC6742]	ILNP/nid-completed-template
    L32 = 105,    // [RFC6742]	ILNP/l32-completed-template
    L64 = 106,    // [RFC6742]	ILNP/l64-completed-template
    LP = 107,     // [RFC6742]	ILNP/lp-completed-template
    EUI48 = 108,  // an EUI-48 address	[RFC7043]	EUI48/eui48-completed-template	2013-03-27
    EUI64 = 109,  // an EUI-64 address	[RFC7043]	EUI64/eui64-completed-template	2013-03-27
    // Unassigned	110-248
    TKEY = 249,     // Transaction Key	[RFC2930]
    TSIG = 250,     // Transaction Signature	[RFC8945]
    IXFR = 251,     // incremental transfer	[RFC1995]
    AXFR = 252,     // transfer of an entire zone	[RFC1035][RFC5936]
    MAILB = 253,    // mailbox-related RRs (MB, MG or MR)	[RFC1035]
    MAILA = 254,    // mail agent RRs (OBSOLETE - see MX)	[RFC1035]
    ANY = 255, // A request for some or all records the server has available	[RFC1035][RFC6895][RFC8482]
    URI = 256, // URI	[RFC7553]	URI/uri-completed-template	2011-02-22
    CAA = 257, // Certification Authority Restriction	[RFC8659]	CAA/caa-completed-template	2011-04-07
    AVC = 258, // Application Visibility and Control	[Wolfgang_Riedel]	AVC/avc-completed-template	2016-02-26
    DOA = 259, // Digital Object Architecture	[draft-durand-doa-over-dns]	DOA/doa-completed-template	2017-08-30
    AMTRELAY = 260, // Automatic Multicast Tunneling Relay	[RFC8777]	AMTRELAY/amtrelay-completed-template	2019-02-06
    // Unassigned	261-32767
    TA = 32768, // DNSSEC Trust Authorities	[Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]		2005-12-13
    DLV = 32769, // DNSSEC Lookaside Validation (OBSOLETE)	[RFC8749][RFC4431]
}

// RR Class values: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
#[derive(Debug, Copy, Clone, PartialEq, DnsEnum)]
#[repr(u16)]
pub enum QClass {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
    ANY = 255,
}

// Character string as described in: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default, PartialEq)]
pub struct CharacterString<'a> {
    pub length: u8,
    pub data: &'a str,
}

/// ```
/// use std::io::Cursor;
/// use dnslib::rfc1035::CharacterString;
///
/// let cs = CharacterString::from("www");
/// assert_eq!(cs.length, 3u8);
/// assert_eq!(cs.data, "www");
/// ```  
impl<'a> From<&'a str> for CharacterString<'a> {
    fn from(s: &'a str) -> Self {
        CharacterString {
            length: s.len() as u8,
            data: s,
        }
    }
}

/// ```
/// use std::io::Cursor;
/// use dnslib::rfc1035::CharacterString;
///
/// let cs = CharacterString::from("www");
/// assert_eq!(cs.length, 3);
/// assert_eq!(cs.to_string(), "www");
/// ```
impl<'a> fmt::Display for CharacterString<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data)
    }
}

// Domain name: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, PartialEq)]
pub enum LabelType<'a> {
    Label(CharacterString<'a>),
    Root,
}

impl<'a> LabelType<'a> {
    pub fn is_root(&self) -> bool {
        matches!(self, LabelType::Root)
    }
}

impl<'a> fmt::Display for LabelType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelType::Label(label) => write!(f, "{}", label)?,
            LabelType::Root => write!(f, ".")?,
        }
        Ok(())
    }
}

// Domain name: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default)]
pub struct DomainName<'a> {
    pub labels: Vec<LabelType<'a>>,
}

impl<'a> DomainName<'a> {
    pub fn from_position(&mut self, pos: usize, buffer: &&'a [u8]) -> DNSResult<usize> {
        let mut index = pos;

        // println!(
        //     "starting at position: {} with value: {:X?} ({})",
        //     index, buffer[index], buffer[index]
        // );

        loop {
            // we reach the sentinel
            if buffer[index] == 0 {
                break;
            }

            // we reached a pointer
            // From RFC1035:
            //
            // The pointer takes the form of a two octet sequence:
            // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // | 1  1|                OFFSET                   |
            // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //    The first two bits are ones.  This allows a pointer to be distinguished
            //    from a label, since the label must begin with two zero bits because
            //    labels are restricted to 63 octets or less.  (The 10 and 01 combinations
            //    are reserved for future use.)  The OFFSET field specifies an offset from
            //    the start of the message (i.e., the first octet of the ID field in the
            //    domain header).  A zero offset specifies the first byte of the ID field,
            //    etc.
            //if buffer[index] >= 192 {
            if is_pointer(buffer[index]) {
                // get pointer which is on 2 bytes
                let ptr = [buffer[index], buffer[index + 1]];
                let pointer = u16::from_be_bytes(ptr);

                // println!("pointer={:0b}", pointer);
                // println!("pointer shifted={:0b}", (pointer << 2) >> 2);

                let pointer = ((pointer << 2) >> 2) as usize;
                //println!("pointer={:0b}", pointer);

                // recursively call the same method with the pointer as starting point
                let _ = self.from_position(pointer as usize, buffer);
                return Ok(index + 2);
            }

            // otherwise, regular processing: the first byte is the string length
            let size = buffer[index] as usize;

            // then we convert the label into UTF8
            let label = &buffer[index + 1..index + size + 1];
            let label_as_utf8 = std::str::from_utf8(label)?;
            //println!("ss={}", ss);

            self.labels
                .push(LabelType::Label(CharacterString::from(label_as_utf8)));

            // adjust index
            index += size + 1;
        }

        // add the root
        self.labels.push(LabelType::Root);

        // println!(
        //     "end index: {} with value: {:X?}",
        //     index + 1,
        //     buffer[index + 1]
        // );

        Ok(index + 1)
    }
}

/// ```
/// use dnslib::rfc1035::DomainName;
///
/// let mut dn = DomainName::try_from("www.google.com").unwrap();
/// assert_eq!(dn.to_string(), "www.google.com.");
///
/// let mut dn = DomainName::try_from("www.google.ie.").unwrap();
/// assert_eq!(dn.to_string(), "www.google.ie.");
/// ```
impl<'a> fmt::Display for DomainName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_assert!(self.labels.len() >= 1);

        // if only the root
        if self.labels[0].is_root() {
            write!(f, ".")?;
        } else {
            // just print out all data
            for label in &self.labels {
                if !label.is_root() {
                    write!(f, "{}.", label)?;
                }
            }
        }
        Ok(())
    }
}

/// ```
/// use dnslib::rfc1035::{DomainName, LabelType, CharacterString};
///
/// let dn = DomainName::try_from("www.example.com").unwrap();
/// assert_eq!(dn.labels.len(), 4);
/// assert_eq!(dn.labels, &[
///     LabelType::Label(CharacterString::from("www")),
///     LabelType::Label(CharacterString::from("example")),
///     LabelType::Label(CharacterString::from("com")),
///     LabelType::Root
/// ]);
///
/// let dn = DomainName::try_from("com.").unwrap();
/// assert_eq!(dn.labels.len(), 2);
/// assert_eq!(dn.labels, &[LabelType::Label(CharacterString::from("com")), LabelType::Root]);
///
/// let dn = DomainName::try_from(".").unwrap();
/// assert_eq!(dn.labels.len(), 1);
/// assert_eq!(dn.labels, &[LabelType::Root]);

/// assert!(DomainName::try_from("").is_err());
/// ```
impl<'a> TryFrom<&'a str> for DomainName<'a> {
    type Error = DNSError;

    fn try_from(domain: &'a str) -> Result<Self, Self::Error> {
        // safeguard
        if domain.is_empty() {
            return Err(DNSError::DNSInternalError(InternalError::EmptyDomainName));
        }

        // handle case for root domain
        let mut label_list: Vec<_> = if domain == "." {
            vec![]
        } else {
            domain
                .split('.')
                .filter(|x| !x.is_empty())
                .map(|x| LabelType::Label(CharacterString::from(x)))
                .collect()
        };

        // add final root
        label_list.push(LabelType::Root);

        Ok(DomainName { labels: label_list })
    }
}

//--------------------------------------------------------------------------------
// Question structure: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
//--------------------------------------------------------------------------------
#[derive(Debug, Default, DnsStruct)]
pub struct DNSQuestion<'a> {
    pub name: DomainName<'a>,
    pub r#type: QType,
    pub class: QClass,
}

impl<'a> DNSQuestion<'a> {
    /// Create a new question. By default, the IN class is used if None is provided
    /// as the qclass parameter
    pub fn new(domain: &'a str, qtype: QType, qclass: Option<QClass>) -> DNSResult<Self> {
        let dn = DomainName::try_from(domain)?;
        let question = DNSQuestion {
            name: dn,
            r#type: qtype,
            class: qclass.unwrap_or(QClass::IN),
        };

        Ok(question)
    }
}

//------------------------------------------------------------------------
// Definition of a resource record in the RFC1035
//------------------------------------------------------------------------
#[derive(Debug, DnsStruct)]
pub struct DNSResourceRecord<'a> {
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
    pub rd_data: Option<Vec<Box<dyn ToFromNetworkOrder<'a>>>>,
                        //  a variable length string of octets that describes the
                        //  resource.  The format of this information varies
                        //  according to the TYPE and CLASS of the resource record.
}

//------------------------------------------------------------------------
// Definition of all RRs from all different RFCs starting with RFC1035
//------------------------------------------------------------------------

// A RR
pub type A = u32;

// HINFO RR
#[derive(Debug, Default, DnsStruct)]
pub struct HINFO<'a> {
    pub cpu: CharacterString<'a>,
    pub os: CharacterString<'a>,
}

// CNAME RR
pub type CNAME<'a> = DomainName<'a>;

// NS RR
pub type NS<'a> = DomainName<'a>;

// AAAA RR
pub type AAAA = [u8; 16];

// SOA RR
#[derive(Debug, Default, DnsStruct)]
pub struct SOA<'a> {
    pub mname: DomainName<'a>, // The <domain-name> of the name server that was the
    // original or primary source of data for this zone.
    pub rname: DomainName<'a>, // A <domain-name> which specifies the mailbox of the
    // person responsible for this zone.
    pub serial: u32, // The unsigned 32 bit version number of the original copy
    // of the zone.  Zone transfers preserve this value.  This
    // value wraps and should be compared using sequence space
    // arithmetic.
    pub refresh: u32, // A 32 bit time interval before the zone should be
    // refreshed.
    pub retry: u32, // A 32 bit time interval that should elapse before a
    // failed refresh should be retried.
    pub expire: u32, // A 32 bit time value that specifies the upper limit on
    // the time interval that can elapse before the zone is no
    // longer authoritative.
    pub minimum: u32, //The unsigned 32 bit minimum TTL field that should be
                      //exported with any RR from this zone.
}

// PTR RR
pub type PTR<'a> = DomainName<'a>;

// MX RR
#[derive(Debug, Default, DnsStruct)]
pub struct MX<'a> {
    pub preference: u16, // A 16 bit integer which specifies the preference given to
    // this RR among others at the same owner.  Lower values
    // are preferred.
    pub exchange: DomainName<'a>, // A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.
}

// TXT RR
pub type TXT<'a> = CharacterString<'a>;

// RDATA RR
pub type RDATA = u32;

// OPT RR: https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2
// RR format
// +------------+--------------+------------------------------+
// | Field Name | Field Type   | Description                  |
// +------------+--------------+------------------------------+
// | NAME       | domain name  | MUST be 0 (root domain)      |
// | TYPE       | u_int16_t    | OPT (41)                     |
// | CLASS      | u_int16_t    | requestor's UDP payload size |
// | TTL        | u_int32_t    | extended RCODE and flags     |
// | RDLEN      | u_int16_t    | length of all RDATA          |
// | RDATA      | octet stream | {attribute,value} pairs      |
// +------------+--------------+------------------------------+
#[derive(Debug, DnsStruct)]
pub struct OPT<'a> {
    pub name: u8,                                              // MUST be 0 (root domain)
    pub r#type: QType,                                         // OPT (41)
    pub udp_payload_size: u16,                                 // requestor's UDP payload size
    pub ttl: OptTTL,                                           // extended RCODE and flags
    pub rd_length: u16,                                        // length of all RDATA
    pub rd_data: Option<Vec<Box<dyn ToFromNetworkOrder<'a>>>>, // {attribute,value} pairs (OptData struct)
}

impl<'a> Default for OPT<'a> {
    fn default() -> Self {
        Self {
            name: 0,
            r#type: QType::OPT,
            udp_payload_size: 4096,
            ttl: OptTTL::default(),
            rd_length: 0,
            rd_data: None,
        }
    }
}

//             +0 (MSB)                            +1 (LSB)
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 0: |         EXTENDED-RCODE        |            VERSION            |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 2: | DO|                           Z                               |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
#[derive(Debug, Default, DnsStruct)]
pub struct OptTTL {
    extented_rcode: u8, // Forms the upper 8 bits of extended 12-bit RCODE (together with the
    // 4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
    // indicates that an unextended RCODE is in use (values 0 through
    // 15).
    version: u8, // Indicates the implementation level of the setter.  Full
    // conformance with this specification is indicated by version '0'.
    // Requestors are encouraged to set this to the lowest implemented
    // level capable of expressing a transaction, to minimise the
    // responder and network load of discovering the greatest common
    // implementation level between requestor and responder.  A
    // requestor's version numbering strategy MAY ideally be a run-time
    // configuration option.
    // If a responder does not implement the VERSION level of the
    // request, then it MUST respond with RCODE=BADVERS.  All responses
    // MUST be limited in format to the VERSION level of the request, but
    // the VERSION of each response SHOULD be the highest implementation
    // level of the responder.  In this way, a requestor will learn the
    // implementation level of a responder as a side effect of every
    // response, including error responses and including RCODE=BADVERS.
    z: u16, // zi is D0+Z actually
}

impl OptTTL {
    pub fn set_d0(&mut self) {
        self.z = self.z | 0b1000_0000_0000_0000;
    }
}

//             +0 (MSB)                            +1 (LSB)
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 0: |                          OPTION-CODE                          |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 2: |                         OPTION-LENGTH                         |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 4: |                                                               |
//    /                          OPTION-DATA                          /
//    /                                                               /
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

#[derive(Debug, Default, DnsStruct)]
pub struct OptData<'a, T: Debug + ToFromNetworkOrder<'a>> {
    option_code: u16, // Assigned by the Expert Review process as defined by the DNSEXT
    // working group and the IESG.
    option_length: u16,                       // Size (in octets) of OPTION-DATA.
    option_data: T, // Varies per OPTION-CODE.  MUST be treated as a bit field
    phantom: std::marker::PhantomData<&'a T>, // the trick for Rust
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::get_sample_slice;
    use crate::{test_from_network, test_to_network};

    #[test]
    fn dns_packet_header() {
        const PACKET: &'static str = r#"
0000   76 86 81 a0 00 01 00 08 00 00 00 01 
        "#;

        // from
        let dns_packet_header = test_from_network!(PACKET, DNSPacketHeader);
        assert_eq!(dns_packet_header.id, 0x7686);
        assert_eq!(dns_packet_header.flags.packet_type, PacketType::Response);
        assert_eq!(dns_packet_header.flags.op_code, OpCode::Query);
        assert!(!dns_packet_header.flags.authorative_answer);
        assert!(!dns_packet_header.flags.truncated);
        assert!(dns_packet_header.flags.recursion_desired);
        assert!(dns_packet_header.flags.recursion_available);
        assert!(!dns_packet_header.flags.z);
        assert!(dns_packet_header.flags.authentic_data);
        assert!(!dns_packet_header.flags.checking_disabled);
        assert_eq!(dns_packet_header.flags.response_code, ResponseCode::NoError);
        assert_eq!(dns_packet_header.qd_count, 1);
        assert_eq!(dns_packet_header.an_count, 8);
        assert_eq!(dns_packet_header.ns_count, 0);
        assert_eq!(dns_packet_header.ar_count, 1);

        // to
        let values = test_to_network!(dns_packet_header);
        assert_eq!(values.0, get_sample_slice(PACKET));
        assert_eq!(values.1, 12);
    }

    #[test]
    fn domain_name_from_position() {
        const PACKET: &'static str = r#"
0000   76 86 81 a0 00 01 00 08 00 00 00 01 02 68 6b 00
0010   00 02 00 01 c0 0c 00 02 00 01 00 00 54 60 00 0e
0020   01 7a 05 68 6b 69 72 63 03 6e 65 74 c0 0c c0 0c
0030   00 02 00 01 00 00 54 60 00 04 01 64 c0 22 c0 0c
0040   00 02 00 01 00 00 54 60 00 04 01 78 c0 22 c0 0c
0050   00 02 00 01 00 00 54 60 00 04 01 75 c0 22 c0 0c
0060   00 02 00 01 00 00 54 60 00 04 01 63 c0 22 c0 0c
0070   00 02 00 01 00 00 54 60 00 04 01 74 c0 22 c0 0c
0080   00 02 00 01 00 00 54 60 00 04 01 76 c0 22 c0 0c
0090   00 02 00 01 00 00 54 60 00 04 01 79 c0 22 00 00
00a0   29 02 00 00 00 00 00 00 00
"#;

        let v = get_sample_slice(PACKET);
        let s = v.as_slice();
        let cursor = std::io::Cursor::new(&s);

        let mut dn = DomainName::default();
        let i = dn.from_position(12, &cursor.get_ref()).unwrap();
        assert_eq!(i, 16);
        assert_eq!(
            dn.labels,
            &[
                LabelType::Label(CharacterString::from("hk")),
                LabelType::Root
            ]
        );

        let mut dn = DomainName::default();
        let i = dn.from_position(20, &cursor.get_ref()).unwrap();
        assert_eq!(i, 22);
        assert_eq!(
            dn.labels,
            &[
                LabelType::Label(CharacterString::from("hk")),
                LabelType::Root
            ]
        );

        let mut dn = DomainName::default();
        let i = dn.from_position(32, &cursor.get_ref()).unwrap();
        assert_eq!(i, 46);
        assert_eq!(
            dn.labels,
            &[
                LabelType::Label(CharacterString::from("z")),
                LabelType::Label(CharacterString::from("hkirc")),
                LabelType::Label(CharacterString::from("net")),
                LabelType::Label(CharacterString::from("hk")),
                LabelType::Root
            ]
        );

        let mut dn = DomainName::default();
        let i = dn.from_position(58, &cursor.get_ref()).unwrap();
        assert_eq!(i, 62);
        assert_eq!(
            dn.labels,
            &[
                LabelType::Label(CharacterString::from("d")),
                LabelType::Label(CharacterString::from("hkirc")),
                LabelType::Label(CharacterString::from("net")),
                LabelType::Label(CharacterString::from("hk")),
                LabelType::Root
            ]
        );

        let mut dn = DomainName::default();
        let i = dn.from_position(58 + 16, &cursor.get_ref()).unwrap();
        assert_eq!(i, 62 + 16);
        assert_eq!(
            dn.labels,
            &[
                LabelType::Label(CharacterString::from("x")),
                LabelType::Label(CharacterString::from("hkirc")),
                LabelType::Label(CharacterString::from("net")),
                LabelType::Label(CharacterString::from("hk")),
                LabelType::Root
            ]
        );
    }
}
