//! Manage command line arguments here.
use std::path::PathBuf;

use dnslib::rfc1035::QType;

use clap::{App, Arg};

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    pub qtype: QType,
    pub host: String,
}

impl CliOptions {
    pub fn options() -> Self {
        let matches = App::new("DNS query tool")
            .version("0.1")
            .author("Alain Viguier dandyvica@gmail.com")
            .about(
                r#"

            Project home page: https://github.com/dandyvica/clf
            
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
            .get_matches();

        // save all cli options into a structure
        let mut options = CliOptions::default();

        options.host = String::from(matches.value_of("host").unwrap());
        options.qtype = 

        options
    }
}
