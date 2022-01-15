// create enum implementations for Default, TryFrom, FromStr for TLS enums
// which are always of the same category.
//
// Ex
//
// enum Foo {
//     x = 0,
//     y = 1,
//     z = 2,
//     t = 255,
// }
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DeriveInput};

// verify if the derive macro is applied to an enum
fn get_enum(ast: &DeriveInput) -> &DataEnum {
    if let Data::Enum(struct_token) = &ast.data {
        struct_token
    } else {
        panic!("<{}> is not an enum!", ast.ident.to_string());
    }
}

// create code for implementation of standard trait: Default, TryFrom<u8>, FromStr
pub fn dns_enum(ast: &DeriveInput) -> TokenStream {
    // get enum data or panic
    let enum_token = get_enum(&ast);

    // grab enum name as an ident and as a string
    let enum_name = &ast.ident;
    let enum_name_s = enum_name.to_string();

    // get vector of tuples: (variant name, variant value)
    let variant_data: Vec<_> = enum_token
        .variants
        .iter()
        .map(|v| {
            //println!("{:?}", v);

            if !matches!(v.fields, syn::Fields::Unit) {
                panic!(
                    "not a unit enum variant for enum {} for variant {}!",
                    enum_name,
                    v.ident.to_string()
                );
            }

            if v.discriminant.is_none() {
                panic!(
                    "wrong variant {} category for enum {}!",
                    v.ident.to_string(),
                    enum_name
                );
            }

            let disc = v.discriminant.as_ref().unwrap();
            let lit = &disc.1;

            if let syn::Expr::Lit(expr_lit) = lit {
                //println!("expr_lit={:?}", expr_lit);

                // expression should contain an integer
                if let syn::Lit::Int(e) = &expr_lit.lit {
                    (v.ident.to_string(), e.base10_digits())
                } else {
                    panic!(
                        "variant {} is not an integer literal for enum {}",
                        enum_name,
                        v.ident.to_string()
                    );
                }
            } else {
                panic!(
                    "not ExprLit for enum {} and variant {}!",
                    enum_name,
                    v.ident.to_string()
                );
            }
        })
        .collect();

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

    // let display = variant_data.iter().map(|v| {
    //     // create value and identifier
    //     let value_variant = &v.0;
    //     let value_int = v.1.parse::<u8>().unwrap();
    //     let variant = format_ident!("{}", &v.0);

    //     quote! {
    //         #enum_name::#variant => write!(f, "{}({})", #value_variant, #value_int),
    //     }
    // });

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
                    _ => Err(format!("error converting <{}> to enum type {}", value, #enum_name_s)),
                }
            }
        }

        // impl FromStr
        impl std::str::FromStr for #enum_name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    #(#from_str)*
                    _ => Err(format!("error converting string <{}> to enum type {}", s, #enum_name_s)),
                }
            }
        }

        // impl Display
        // impl std::fmt::Display for #enum_name {
        //     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //         match self {
        //             #(#display)*
        //         }
        //     }
        // }
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(impls)
}
