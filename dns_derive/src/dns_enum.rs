// Create enum implementations for Default, TryFrom, FromStr for DNS enums
// which are always of the same category.
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput};

// Verify if the derive macro can applied to an enum which has no
// non-unit variants
//
// This function panics in this cases:
//  enum Foo { A(u8), B, C } : all enum variants not unit variants
//  enum Foo { A = 1, B, C, D } : at least one variant has no discriminant
//  enum Foo { A = 1, B = 3*4 } : at least one variant discriminant is not a literal
fn get_enum_data(ast: &DeriveInput) -> Vec<(String, String)> {
    // check first this is an enum
    if let Data::Enum(enum_token) = &ast.data {
        // get all variants
        let variants: Vec<_> = enum_token.variants.iter().collect();

        // this will hold all variant data
        let mut variant_data = Vec::new();

        // test all variants
        for v in variants {
            // all enum variants should be unit variants
            if !matches!(v.fields, syn::Fields::Unit) {
                panic!(
                    "variant {} for enum {} is not a unit variant!",
                    v.ident, ast.ident
                );
            }

            // at least one variant has no discriminant
            if v.discriminant.is_none() {
                panic!("at least one variant for enum {} has no value!", ast.ident);
            }

            // we can create the discriminant now and make other checks
            let discriminant = v.discriminant.as_ref().unwrap();
            let literal = &discriminant.1;

            // all discriminants should be literals
            if let syn::Expr::Lit(expr_lit) = literal {
                //println!("expr_lit={:?}", expr_lit);

                // expression should contain an integer
                if let syn::Lit::Int(e) = &expr_lit.lit {
                    variant_data.push((v.ident.to_string(), e.base10_digits().to_string()));
                } else {
                    panic!(
                        "variant {} is not an integer literal for enum {}",
                        ast.ident,
                        v.ident.to_string()
                    );
                }
            } else {
                panic!(
                    "not ExprLit for enum {} and variant {}!",
                    ast.ident,
                    v.ident.to_string()
                );
            }
        }

        // now it's safe to return the enum
        variant_data
    } else {
        panic!("<{}> is not an enum!", ast.ident.to_string());
    }
}

// create code for implementation of standard trait: Default, TryFrom<u8>, FromStr
pub fn dns_enum(ast: &DeriveInput) -> TokenStream {
    // get enum data or panic
    let variant_data = get_enum_data(&ast);

    // grab enum name as an ident and as a string
    let enum_name = &ast.ident;
    let enum_name_s = enum_name.to_string();

    // create tokenstreams for impl Default, TryFrom, FromStr
    let default_variant = format_ident!("{}", variant_data[0].0);

    let try_from_u16 = variant_data.iter().map(|v| {
        // create value and identifier
        let value = v.1.parse::<u16>().unwrap();
        let variant = format_ident!("{}", v.0);

        quote! {
            #value => Ok(#enum_name::#variant),
        }
    });

    let from_str = variant_data.iter().map(|v| {
        // create value and identifier
        let value = &v.0;
        let variant = format_ident!("{}", &v.0);

        quote! {
            #value => Ok(#enum_name::#variant),
        }
    });

    // now create code for implementation of Default, TryFrom<u8>, FromStr
    let impls = quote! {
        // impl Default
        impl Default for #enum_name  {
            fn default() -> Self {
                #enum_name::#default_variant
            }
        }

        // impl TryFrom<u8>
        impl std::convert::TryFrom<u8> for #enum_name  {
            type Error = String;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                <#enum_name>::try_from(value as u16)
            }
        }

        // impl TryFrom<u16>
        impl std::convert::TryFrom<u16> for #enum_name  {
            type Error = String;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    #(#try_from_u16)*
                    _ => Err(format!("error converting u16 value <{}> to enum type {}", value, #enum_name_s)),
                }
            }
        }

        // impl FromStr
        impl std::str::FromStr for #enum_name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    #(#from_str)*
                    _ => Err(format!("error converting string '{}' to enum type {}", s, #enum_name_s)),
                }
            }
        }
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(impls)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::get_derive_input;

    const E1: &'static str = "enum Foo { A(u8), B, C }";
    const E2: &'static str = "enum Foo { A = 1, B, C, D }";
    const E3: &'static str = "enum Foo { A = 2*3, B = 1 }";
    const E4: &'static str = "enum Foo { A = 1, B = 2, C = 3 }";
    const S1: &'static str = "struct Point { x : f64 , y : u8 , z : u32 }";

    #[test]
    #[should_panic]
    fn not_an_enum() {
        let input = get_derive_input(S1);
        let _ = get_enum_data(&input);
    }

    #[test]
    #[should_panic]
    fn not_all_unit_variants() {
        let input = get_derive_input(E1);
        let _ = get_enum_data(&input);
    }

    #[test]
    #[should_panic]
    fn not_all_unit_discriminants() {
        let input = get_derive_input(E2);
        let _ = get_enum_data(&input);
    }

    #[test]
    #[should_panic]
    fn not_all_literal_discriminants() {
        let input = get_derive_input(E3);
        let _ = get_enum_data(&input);
    }

    #[test]
    fn variant_data() {
        let input = get_derive_input(E4);
        let v = get_enum_data(&input);

        assert_eq!(
            v,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "2".to_string()),
                ("C".to_string(), "3".to_string()),
            ]
        );
    }
}
