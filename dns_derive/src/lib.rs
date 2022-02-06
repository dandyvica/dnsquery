//! Derive macros for implementing the `ToNetworkBytes` trait for structures used
//! in the DNS lib, and Default, TryFrom<u8>, TryFrom<u16> and FromStr for enums
use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod dns_struct;
use dns_struct::dns_derive;

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
#[proc_macro_derive(DnsStruct)]
pub fn dns_macro_length(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    proc_macro::TokenStream::from(dns_derive(&ast))
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
