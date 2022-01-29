//! Base structures for DNS messages. Taken from https://datatracker.ietf.org/doc/html/rfc1035
//!
//! The DnsStruct procedural macro automatically defines the implementation of the ToFromNetworkOrder trait.
//! The DnsEnum procedural macro automatically implements Default, FromStr, TryFrom<u8> and TryFrom<u16>
use std::fmt;
use std::str;

use crate::error::{DNSError, DNSResult, InternalError};
use crate::network_order::ToFromNetworkOrder;
use crate::util::is_pointer;

use dns_derive::{DnsEnum, DnsStruct};

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
    pub z: u8, // Reserved for future use.  Must be zero in all queries and responses.
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
#[derive(Debug, Default)]
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

// impl Default for QType {
//     fn default() -> Self {
//         QType::A
//     }
// }

// /// ```
// /// use dnslib::rfc1035::QType;
// ///
// /// let qt = QType::try_from(14u16).unwrap();
// /// assert_eq!(qt, QType::MINFO);
// /// assert!(QType::try_from(0xFFFF).is_err());
// /// ```
// impl TryFrom<u16> for QType {
//     type Error = String;

//     fn try_from(value: u16) -> Result<Self, Self::Error> {
//         match value {
//             1 => Ok(QType::A),           // a host address	[RFC1035]
//             2 => Ok(QType::NS),          // an authoritative name server	[RFC1035]
//             3 => Ok(QType::MD),          // a mail destination (OBSOLETE - use MX)	[RFC1035]
//             4 => Ok(QType::MF),          // a mail forwarder (OBSOLETE - use MX)	[RFC1035]
//             5 => Ok(QType::CNAME),       // the canonical name for an alias	[RFC1035]
//             6 => Ok(QType::SOA),         // marks the start of a zone of authority	[RFC1035]
//             7 => Ok(QType::MB),          // a mailbox domain name (EXPERIMENTAL)	[RFC1035]
//             8 => Ok(QType::MG),          // a mail group member (EXPERIMENTAL)	[RFC1035]
//             9 => Ok(QType::MR),          // a mail rename domain name (EXPERIMENTAL)	[RFC1035]
//             10 => Ok(QType::NULL),       // a null RR (EXPERIMENTAL)	[RFC1035]
//             11 => Ok(QType::WKS),        // a well known service description	[RFC1035]
//             12 => Ok(QType::PTR),        // a domain name pointer	[RFC1035]
//             13 => Ok(QType::HINFO),      // host information	[RFC1035]
//             14 => Ok(QType::MINFO),      // mailbox or mail list information	[RFC1035]
//             15 => Ok(QType::MX),         // mail exchange	[RFC1035]
//             16 => Ok(QType::TXT),        // text strings	[RFC1035]
//             17 => Ok(QType::RP),         // for Responsible Person	[RFC1183]
//             18 => Ok(QType::AFSDB),      // for AFS Data Base location	[RFC1183][RFC5864]
//             19 => Ok(QType::X25),        // for X.25 PSDN address	[RFC1183]
//             20 => Ok(QType::ISDN),       // for ISDN address	[RFC1183]
//             21 => Ok(QType::RT),         // for Route Through	[RFC1183]
//             22 => Ok(QType::NSAP),       // for NSAP address, NSAP style A record	[RFC1706]
//             23 => Ok(QType::NSAPPTR),    // for domain name pointer, NSAP style	[RFC1706]
//             24 => Ok(QType::SIG), // for security signature	[RFC2536][RFC2931][RFC3110][RFC4034]
//             25 => Ok(QType::KEY), // for security key	[RFC2536][RFC2539][RFC3110][RFC4034]
//             26 => Ok(QType::PX),  // X.400 mail mapping information	[RFC2163]
//             27 => Ok(QType::GPOS), // Geographical Position	[RFC1712]
//             28 => Ok(QType::AAAA), // IP6 Address	[RFC3596]
//             29 => Ok(QType::LOC), // Location Information	[RFC1876]
//             30 => Ok(QType::NXT), // Next Domain (OBSOLETE)	[RFC2535][RFC3755]
//             31 => Ok(QType::EID), // Endpoint Identifier	[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]		1995-06
//             32 => Ok(QType::NIMLOC), // Nimrod Locator	[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]		1995-06
//             33 => Ok(QType::SRV),    // Server Selection	[1][RFC2782]
//             34 => Ok(QType::ATMA), // ATM Address	[ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
//             35 => Ok(QType::NAPTR), // Naming Authority Pointer	[RFC3403]
//             36 => Ok(QType::KX),   // Key Exchanger	[RFC2230]
//             37 => Ok(QType::CERT), // CERT	[RFC4398]
//             38 => Ok(QType::A6),   // A6 (OBSOLETE - use AAAA)	[RFC2874][RFC3226][RFC6563]
//             39 => Ok(QType::DNAME), // DNAME	[RFC6672]
//             40 => Ok(QType::SINK), // SINK	[Donald_E_Eastlake][draft-eastlake-kitchen-sink]		1997-11
//             41 => Ok(QType::OPT),  // OPT	[RFC3225][RFC6891]
//             42 => Ok(QType::APL),  // APL	[RFC3123]
//             43 => Ok(QType::DS),   // Delegation Signer	[RFC4034]
//             44 => Ok(QType::SSHFP), // SSH Key Fingerprint	[RFC4255]
//             45 => Ok(QType::IPSECKEY), // IPSECKEY	[RFC4025]
//             46 => Ok(QType::RRSIG), // RRSIG	[RFC4034]
//             47 => Ok(QType::NSEC), // NSEC	[RFC4034][RFC9077]
//             48 => Ok(QType::DNSKEY), // DNSKEY	[RFC4034]
//             49 => Ok(QType::DHCID), // DHCID	[RFC4701]
//             50 => Ok(QType::NSEC3), // NSEC3	[RFC5155][RFC9077]
//             51 => Ok(QType::NSEC3PARAM), // NSEC3PARAM	[RFC5155]
//             52 => Ok(QType::TLSA), // TLSA	[RFC6698]
//             53 => Ok(QType::SMIMEA), // S/MIME cert association	[RFC8162]	SMIMEA/smimea-completed-template	2015-12-01
//             54 => Ok(QType::Unassigned), //
//             55 => Ok(QType::HIP),    // Host Identity Protocol	[RFC8005]
//             56 => Ok(QType::NINFO),  // NINFO	[Jim_Reid]	NINFO/ninfo-completed-template	2008-01-21
//             57 => Ok(QType::RKEY),   // RKEY	[Jim_Reid]	RKEY/rkey-completed-template	2008-01-21
//             58 => Ok(QType::TALINK), // Trust Anchor LINK	[Wouter_Wijngaards]	TALINK/talink-completed-template	2010-02-17
//             59 => Ok(QType::CDS),    // Child DS	[RFC7344]	CDS/cds-completed-template	2011-06-06
//             60 => Ok(QType::CDNSKEY), // DNSKEY(s) the Child wants reflected in DS	[RFC7344]		2014-06-16
//             61 => Ok(QType::OPENPGPKEY), // OpenPGP Key	[RFC7929]	OPENPGPKEY/openpgpkey-completed-template	2014-08-12
//             62 => Ok(QType::CSYNC),      // Child-To-Parent Synchronization	[RFC7477]		2015-01-27
//             63 => Ok(QType::ZONEMD), // Message Digest Over Zone Data	[RFC8976]	ZONEMD/zonemd-completed-template	2018-12-12
//             64 => Ok(QType::SVCB), // Service Binding	[draft-ietf-dnsop-svcb-https-00]	SVCB/svcb-completed-template	2020-06-30
//             65 => Ok(QType::HTTPS), // HTTPS Binding	[draft-ietf-dnsop-svcb-https-00]	HTTPS/https-completed-template	2020-06-30
//             // Unassigned	66-98
//             99 => Ok(QType::SPF),     // [RFC7208]
//             100 => Ok(QType::UINFO),  // [IANA-Reserved]
//             101 => Ok(QType::UID),    // [IANA-Reserved]
//             102 => Ok(QType::GID),    // [IANA-Reserved]
//             103 => Ok(QType::UNSPEC), // [IANA-Reserved]
//             104 => Ok(QType::NID),    // [RFC6742]	ILNP/nid-completed-template
//             105 => Ok(QType::L32),    // [RFC6742]	ILNP/l32-completed-template
//             106 => Ok(QType::L64),    // [RFC6742]	ILNP/l64-completed-template
//             107 => Ok(QType::LP),     // [RFC6742]	ILNP/lp-completed-template
//             108 => Ok(QType::EUI48), // an EUI-48 address	[RFC7043]	EUI48/eui48-completed-template	2013-03-27
//             109 => Ok(QType::EUI64), // an EUI-64 address	[RFC7043]	EUI64/eui64-completed-template	2013-03-27
//             // Unassigned	110-248
//             249 => Ok(QType::TKEY),     // Transaction Key	[RFC2930]
//             250 => Ok(QType::TSIG),     // Transaction Signature	[RFC8945]
//             251 => Ok(QType::IXFR),     // incremental transfer	[RFC1995]
//             252 => Ok(QType::AXFR),     // transfer of an entire zone	[RFC1035][RFC5936]
//             253 => Ok(QType::MAILB),    // mailbox-related RRs (MB, MG or MR)	[RFC1035]
//             254 => Ok(QType::MAILA),    // mail agent RRs (OBSOLETE - see MX)	[RFC1035]
//             255 => Ok(QType::STAR), // A request for some or all records the server has available	[RFC1035][RFC6895][RFC8482]
//             256 => Ok(QType::URI),  // URI	[RFC7553]	URI/uri-completed-template	2011-02-22
//             257 => Ok(QType::CAA), // Certification Authority Restriction	[RFC8659]	CAA/caa-completed-template	2011-04-07
//             258 => Ok(QType::AVC), // Application Visibility and Control	[Wolfgang_Riedel]	AVC/avc-completed-template	2016-02-26
//             259 => Ok(QType::DOA), // Digital Object Architecture	[draft-durand-doa-over-dns]	DOA/doa-completed-template	2017-08-30
//             260 => Ok(QType::AMTRELAY), // Automatic Multicast Tunneling Relay	[RFC8777]	AMTRELAY/amtrelay-completed-template	2019-02-06
//             // Unassigned	261-32767
//             32768 => Ok(QType::TA), // DNSSEC Trust Authorities	[Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]		2005-12-13
//             32769 => Ok(QType::DLV), // DNSSEC Lookaside Validation (OBSOLETE)	[RFC8749][RFC4431]
//             _ => Err(format!("Invalid QType value: {}!", value)),
//         }
//     }
// }

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

// Domain name: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default)]
pub struct DomainName<'a> {
    pub labels: Vec<(u8, DomainType<'a>)>,
    pub length: usize,
}

#[derive(Debug, PartialEq)]
pub enum DomainType<'a> {
    Label(&'a [u8]),
    Null,
    Pointer(u8),
}

impl<'a> DomainName<'a> {
    /// ```
    /// use dnslib::rfc1035::{DomainName, DomainType};
    /// use dnslib::network_order::dns::{SAMPLE_DOMAIN, SAMPLE_SLICE};
    ///
    /// let mut dn = DomainName::default();
    /// dn.push_slice(SAMPLE_SLICE.as_slice());
    ///
    /// assert_eq!(dn.labels.len(), 4);
    /// assert_eq!(dn.labels.get(0).unwrap(), &(3_u8, DomainType::Label("www".as_bytes())));
    /// assert_eq!(dn.labels.get(1).unwrap(), &(6_u8, DomainType::Label("google".as_bytes())));
    /// assert_eq!(dn.labels.get(2).unwrap(), &(2_u8, DomainType::Label("ie".as_bytes())));
    /// assert_eq!(dn.labels.get(3).unwrap(), &(0_u8, DomainType::Null));
    /// assert_eq!(dn.length, 11);
    /// ```    
    pub fn push_slice(&mut self, value: &'a [u8]) -> DNSResult<()> {
        //dbg!(value[0]);
        //println!("slice====> {:X?}", value);

        // if we already have a sentinel, delete it because it'll be added
        // with new slice
        if !self.labels.is_empty() {
            self.labels.truncate(self.labels.len());
        }

        // loop through the vector
        let mut index = 0usize;

        loop {
            let size = value[index];

            // if we've reached a sentinel, exit
            if size == 0 {
                self.labels.push((0, DomainType::Null));
                break;
            } else if is_pointer(size) {
                self.labels.push((size, DomainType::Pointer(size)));
                break;
            // otherwise copy references to inner data
            } else {
                self.labels.push((
                    size,
                    DomainType::Label(&value[index + 1..index + 1 + size as usize]),
                ));
                self.length += size as usize;

                // adjust index
                index += size as usize + 1;
            }
        }

        Ok(())
    }
}

/// ```
/// use dnslib::rfc1035::{DomainName, DomainType};
///
/// let dn = DomainName::try_from("www.example.com").unwrap();
/// assert_eq!(dn.labels.len(), 4);
/// assert_eq!(dn.labels.get(0).unwrap(), &(3_u8, DomainType::Label("www".as_bytes())));
/// assert_eq!(dn.labels.get(1).unwrap(), &(7_u8, DomainType::Label("example".as_bytes())));
/// assert_eq!(dn.labels.get(2).unwrap(), &(3_u8, DomainType::Label("com".as_bytes())));
/// assert_eq!(dn.labels.get(3).unwrap(), &(0_u8, DomainType::Null));
/// assert_eq!(dn.length, 13);
///
/// let dn = DomainName::try_from("com.").unwrap();
/// assert_eq!(dn.labels.len(), 2);
/// assert_eq!(dn.labels.get(0).unwrap(), &(3_u8, DomainType::Label("com".as_bytes())));
/// assert_eq!(dn.labels.get(1).unwrap(), &(0_u8, DomainType::Null));
/// assert_eq!(dn.length, 3);
///
/// let dn = DomainName::try_from(".").unwrap();
/// assert_eq!(dn.labels.len(), 1);
/// assert_eq!(dn.labels.get(0).unwrap().1, DomainType::Null);
/// assert_eq!(dn.length, 0);
///
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
        let label_list: Vec<_> = if domain == "." {
            vec![(0, DomainType::Null)]
        } else {
            // split input into individual labels
            let mut labels: Vec<_> = domain.split('.').collect();

            // for: "www.example.com" => ["www", "example", "com"]
            // for: "www.example.com." => ["www", "example", "com", ""]
            // for: "com" => ["com"]
            // to handle these cases, need to check the if the last element is not ""
            if labels.is_empty() {
                return Err(DNSError::DNSInternalError(InternalError::EmptyDomainName));
            }

            if !labels.last().unwrap().is_empty() {
                labels.push("");
            }

            labels
                .iter()
                .map(|x| {
                    if x.is_empty() {
                        (0, DomainType::Null)
                    } else {
                        (x.len() as u8, DomainType::Label(x.as_bytes()))
                    }
                })
                .collect()
        };

        // calculate domain name length
        let length = label_list.iter().map(|x| x.0 as usize).sum();

        // check length
        debug_assert!(length <= 255);

        // check whether label's length is <= 63
        // for label in &label_list {
        //     if label.as_bytes().len() > 63 {
        //         return Err(format!("label <{}> length is over 63 characters", label));
        //     }
        // }

        Ok(DomainName {
            labels: label_list,
            length: length,
        })
    }
}

/// ```
/// use dnslib::rfc1035::DomainName;
/// use dnslib::network_order::dns::{SAMPLE_DOMAIN, SAMPLE_SLICE};
///
/// let mut dn = DomainName::default();
/// dn.push_slice(SAMPLE_SLICE.as_slice());
///
/// assert_eq!(dn.to_string(), "www.google.ie.");
/// ```
impl<'a> fmt::Display for DomainName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();

        self.labels.iter().for_each(|label| {
            if let DomainType::Label(l) = label.1 {
                s.push_str(str::from_utf8(l).unwrap());
                s.push_str(".");
            }
        });

        write!(f, "{}", s)
    }
}

// Character string as described in: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
pub type CharacterString<'a> = &'a str;

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
#[derive(Debug, DnsStruct)]
pub struct OPT {
    pub name: u8,              // MUST be 0 (root domain)
    pub r#type: QType,         // OPT (41)
    pub udp_payload_size: u16, // requestor's UDP payload size
    pub ttl: OptTTL,           // extended RCODE and flags
    pub rd_length: u16,        // length of all RDATA
                               //pub r_data: T              // {attribute,value} pairs
}

impl Default for OPT {
    fn default() -> Self {
        Self {
            name: 0,
            r#type: QType::OPT,
            udp_payload_size: 4096,
            ttl: OptTTL::default(),
            rd_length: 0,
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

pub struct OptData<T> {
    option_code: u16, // Assigned by the Expert Review process as defined by the DNSEXT
    // working group and the IESG.
    option_length: u16, // Size (in octets) of OPTION-DATA.
    option_data: T,     // Varies per OPTION-CODE.  MUST be treated as a bit field
}
