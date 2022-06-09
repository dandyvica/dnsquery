//! Manage command line arguments here.
use std::fs::OpenOptions;
use std::str::FromStr;

use clap::{Arg, Command};
use simplelog::*;

use dnslib::{error::DNSResult, rfc1035::QType};

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    pub qtype: QType,
    pub ns: String,
    pub domain: String,
    pub no_opt: bool,
    pub debug: bool,
}

impl CliOptions {
    pub fn options() -> DNSResult<Self> {
        let matches = Command::new("DNS query tool")
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
                Arg::new("ns")
                    .short('n')
                    .long("ns")
                    .required(true)
                    .long_help("DNS server to address")
                    .takes_value(true),
            )
            .arg(
                Arg::new("domain")
                    .short('d')
                    .long("domain")
                    .required(true)
                    .long_help("Domain to query")
                    .takes_value(true),
            )
            .arg(
                Arg::new("debug")
                    .short('g')
                    .long("debug")
                    .required(false)
                    .long_help("Debug mode")
                    .takes_value(false),
            )
            .arg(
                Arg::new("no-opt")
                    .short('o')
                    .long("no-opt")
                    .required(false)
                    .long_help("Use OPT record")
                    .takes_value(false),
            )
            .get_matches();

        // save all cli options into a structure
        let mut options = CliOptions::default();

        options.ns = String::from(matches.value_of("ns").unwrap());
        options.domain = String::from(matches.value_of("domain").unwrap());
        options.qtype = QType::from_str(&matches.value_of("qtype").unwrap().to_uppercase())?;
        options.no_opt = matches.is_present("no-opt");
        options.debug = matches.is_present("debug");

        // create logfile only if requested. Logfile is gathering a bunch of information used for debugging
        if options.debug {
            init_logger("dnsq.log")?;
        }

        Ok(options)
    }
}

// Initialize logger: either create it or use it
fn init_logger(logfile: &str) -> DNSResult<()> {
    // initialize logger
    let writable = OpenOptions::new().append(true).open(logfile)?;

    WriteLogger::init(
        LevelFilter::Trace,
        simplelog::ConfigBuilder::new()
            .set_time_format_rfc3339()
            // .set_time_format_custom(format_description!(
            //     "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]"
            .build(),
        writable,
    )?;

    Ok(())
}
