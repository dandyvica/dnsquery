//! A dedicated error for all possible errors in DNS queries: I/O, DNS packet unconsistencies, etc
use std::io;
use std::str;

#[derive(Debug)]
pub enum DNSError {
    Io(io::Error),
    FromUtf8(std::string::FromUtf8Error),
    Utf8(str::Utf8Error),
    LoggerError(log::SetLoggerError),
    DNS(String),
    DNSInternalError(InternalError),
}

#[derive(Debug)]
pub enum InternalError {
    DnsDomainNameTooLong,
    EmptyDomainName,
}

impl DNSError {
    // Helper function to create a new DNS error from a string
    pub fn new(s: &str) -> Self {
        DNSError::DNS(String::from(s))
    }
}

/// A specific custom `Result` for all functions
pub type DNSResult<T> = Result<T, DNSError>;

// All convertion for internal errors for DNSError
impl From<io::Error> for DNSError {
    fn from(err: io::Error) -> Self {
        DNSError::Io(err)
    }
}

impl From<String> for DNSError {
    fn from(err: String) -> Self {
        DNSError::DNS(err)
    }
}

impl From<std::string::FromUtf8Error> for DNSError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        DNSError::FromUtf8(err)
    }
}

impl From<str::Utf8Error> for DNSError {
    fn from(err: str::Utf8Error) -> Self {
        DNSError::Utf8(err)
    }
}

impl From<log::SetLoggerError> for DNSError {
    fn from(err: log::SetLoggerError) -> Self {
        DNSError::LoggerError(err)
    }
}
