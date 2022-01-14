// all helper functions for derive macros used in DNS structures
use proc_macro::TokenStream;
use quote::quote;
use syn::visit::{self, Visit};
use syn::{Data, DataStruct, DeriveInput, Ident, TraitBound, TypeParam, Lifetime};

// structure used with the visit methods: stores generic parameter existence and list of bounds
#[derive(Default)]
struct ExprVisitor<'ast> {
    is_generic: bool,
    is_lifetime: bool,
    bounds: Vec<&'ast Ident>,
}

impl<'ast> Visit<'ast> for ExprVisitor<'ast> {
    fn visit_type_param(&mut self, node: &'ast TypeParam) {
        self.is_generic = true;
        visit::visit_type_param(self, node);
    }

    fn visit_lifetime(&mut self, node: &'ast Lifetime) {
        self.is_lifetime = true;
        visit::visit_lifetime(self, node);
    }

    fn visit_trait_bound(&mut self, node: &'ast TraitBound) {
        //println!("TraitBound={:?}", node.path.segments[0].ident.to_string());
        if node.path.segments.len() > 0 {
            self.bounds.push(&node.path.segments[0].ident);
        }
        visit::visit_trait_bound(self, node);
    }
}

// helper function to check whether the structure being derived is a generic one
// and stores bounds if any
fn get_generic_data(derive_input: &DeriveInput) -> Option<proc_macro2::TokenStream> {
    // check whether we have generic type and bounds
    let mut visitor = ExprVisitor::default();
    visitor.visit_derive_input(&derive_input);

    // we have a generic type and maybe bounds
    if visitor.is_generic {
        // if no bound, empty token is used, otherwise the "where" keyword
        let where_bound = if visitor.bounds.len() == 0 {
            quote!()
        } else {
            quote!(where)
        };

        // now build the list of bounds as tokenstreams
        let trait_bound = visitor.bounds.iter().map(|bound| {
            // get name of the field as TokenStream
            let trait_bound = bound;

            quote! {
                T: #trait_bound,
            }
        });

        Some(quote!(#where_bound #(#trait_bound)*))
    } else {
        None
    }
}

// helper function to check whether the structure owns a lifetime
fn is_lifetime(derive_input: &DeriveInput) -> bool {
    // check whether we have generic type and bounds
    let mut visitor = ExprVisitor::default();
    visitor.visit_derive_input(&derive_input);

    visitor.is_lifetime
}

// verify if the derive macro is applied to a structure
fn get_struct(ast: &DeriveInput) -> &DataStruct {
    if let Data::Struct(struct_token) = &ast.data {
        struct_token
    } else {
        panic!("<{}> is not a struct!", ast.ident.to_string());
    }
}

// create the impl methods for trait ToFromNetworkOrder
pub fn dns_derive(ast: &DeriveInput) -> TokenStream {
    // get generic parameter if any
    let lifetime = is_lifetime(&ast);

    // get struct data or panic
    let struct_token = get_struct(&ast);

    // save structure name because we're gonna use it soon
    let structure_name = &ast.ident;

    // call to_network_bytes() call for each field
    let to_method_calls = struct_token.fields.iter().map(|f| {
        // get name of the field as TokenStream
        let field_name = f.ident.as_ref().unwrap();

        quote! {
            length += ToFromNetworkOrder::to_network_bytes(&self.#field_name, buffer)?;
        }
    });

    // call from_network_bytes() call for each field
    let from_method_calls = struct_token.fields.iter().map(|f| {
        // get name of the field as TokenStream
        let field_name = f.ident.as_ref().unwrap();

        quote! {
            ToFromNetworkOrder::from_network_bytes(&mut self.#field_name, buffer)?;
        }
    });

    // implement the Structurizer trait for function length()
    let new_code = if lifetime {
        //let bounds: proc_macro2::TokenStream = param.unwrap();

        quote! {
            // the generated impl.
            impl<'a> ToFromNetworkOrder<'a> for #structure_name<'a> {
                fn to_network_bytes(&self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
                    let mut length = 0usize;
                    #( #to_method_calls)*
                    Ok(length)
                }

                fn from_network_bytes(&mut self, buffer: &mut std::io::Cursor<&'a [u8]>) -> DNSResult<()> {
                    #( #from_method_calls)*
                    Ok(())
                }
            }
        }
    } else {
        quote! {
            // the generated impl.
            impl<'a> ToFromNetworkOrder<'a> for #structure_name  {
                fn to_network_bytes(&self, buffer: &mut Vec<u8>)-> std::io::Result<usize> {
                    let mut length = 0usize;
                    #( #to_method_calls)*
                    Ok(length)
                }

                fn from_network_bytes(&mut self, buffer: &mut std::io::Cursor<&'a [u8]>) -> DNSResult<()> {
                    #( #from_method_calls)*
                    Ok(())
                }
            }
        }
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(new_code)
}
