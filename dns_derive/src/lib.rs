//! Derive macros for implementing the `ToNetworkBytes` trait for structures used
//! in the DNS lib, and Default, TryFrom<u8>, TryFrom<u16> and FromStr for enums
use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod dns_struct;
use dns_struct::{dns_from_network, dns_to_network};

mod dns_enum;
use dns_enum::dns_enum;

// Used to for unit tests
#[cfg(test)]
pub fn get_derive_input(s: &str) -> DeriveInput {
    use std::str::FromStr;

    let tokens = proc_macro2::TokenStream::from_str(s).unwrap();
    syn::parse2(tokens).unwrap()
}

// Auto-implement the ToNetworkBytes trait for a structure
#[proc_macro_derive(DnsToNetwork)]
pub fn dns_to(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    proc_macro::TokenStream::from(dns_to_network(&ast))
}

// Auto-implement the ToNetworkBytes trait for a structure
#[proc_macro_derive(DnsFromNetwork)]
pub fn dns_from(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    proc_macro::TokenStream::from(dns_from_network(&ast))
}

// Auto-implement the Default, TryFrom<u8>, TryFrom<u16> and FromStr for enums
// used in DNS lib
#[proc_macro_derive(DnsEnum)]
pub fn tls_macro_enum(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    dns_enum(&ast)
}
