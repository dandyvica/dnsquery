//! Manage command line arguments here.
use std::str::FromStr;
use clap::{App, Arg};

use dnslib::rfc1035::QType;

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    pub qtype: QType,
    pub host: String,
    pub debug: bool,
}

impl CliOptions {
    pub fn options() -> Self {
        let matches = App::new("DNS query tool")
            .version("0.1")
            .author("Alain Viguier dandyvica@gmail.com")
            .about(
                r#"A simple DNS query client

            Project home page: https://github.com/dandyvica/dnsquery
            
            "#,
            )
            .arg(
                Arg::new("qtype")
                    .short('q')
                    .long("qtype")
                    .required(true)
                    .long_help("QType value")
                    .takes_value(true),
            )
            .arg(
                Arg::new("host")
                    .short('h')
                    .long("host")
                    .required(true)
                    .long_help("DNS host to query")
                    .takes_value(true),
            )
            .arg(
                Arg::new("debug")
                    .short('d')
                    .long("debug")
                    .required(false)
                    .long_help("Debug mode")
                    .takes_value(false),
            )
            .get_matches();

        // save all cli options into a structure
        let mut options = CliOptions::default();

        options.host = String::from(matches.value_of("host").unwrap());
        options.qtype = QType::from_str(matches.value_of("qtype").unwrap()).unwrap();
        options.debug = matches.is_present("debug");

        options
    }
}
