// all helper functions for derive macros used in DNS structures
use proc_macro::TokenStream;
use quote::quote;
use syn::visit::{self, Visit};
use syn::{parse_macro_input, Data, DataStruct, DeriveInput, Ident, TraitBound, TypeParam, Lifetime};

mod dns_struct;
use dns_struct::dns_derive;

mod dns_enum;
use dns_enum::dns_enum;

#[proc_macro_derive(DnsDerive)]
pub fn dns_macro_length(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    dns_derive(&ast)
}

#[proc_macro_derive(DnsEnum)]
pub fn tls_macro_enum(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    dns_enum(&ast)
}