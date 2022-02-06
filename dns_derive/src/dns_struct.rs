// all helper functions for derive macros used in DNS structures
use quote::quote;
use syn::visit::{self, Visit};
use syn::{Data, DataStruct, DeriveInput, Ident, Lifetime, PathArguments, TraitBound, TypeParam};

// structure used with the visit methods: stores generic parameter, lifetime
// existence and list of bounds if any with possible lifetimes
#[derive(Default, Debug)]
struct ExprVisitor<'ast> {
    is_generic: bool,
    is_lifetime: bool,
    bounds: Vec<(&'ast Ident, bool)>,
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
        //println!("TraitBound={:#?}", node.path.segments);
        if !node.path.segments.is_empty() {
            self.bounds.push((
                &node.path.segments[0].ident,
                matches!(
                    &node.path.segments[0].arguments,
                    PathArguments::AngleBracketed(_)
                ),
            ));
        }
        visit::visit_trait_bound(self, node);
    }
}

// helper function to check whether the structure being derived is a generic one
// and return the impl clause
fn get_where_clause(visitor: &ExprVisitor) -> Option<proc_macro2::TokenStream> {
    // we have a generic type and maybe bounds
    if visitor.is_generic {
        // if no bound, empty token is used, otherwise the "where" keyword
        if visitor.bounds.is_empty() {
            Some(quote!())
        } else {
            // now build the list of bounds as tokenstreams
            let trait_bounds = visitor.bounds.iter().map(|bound| {
                // get name of the field as TokenStream
                let trait_bound = bound.0;

                // if the trait bound has a lifetime
                if bound.1 {
                    quote! {
                        #trait_bound<'a>
                    }
                } else {
                    quote! {
                        #trait_bound
                    }
                }
            });

            Some(quote!(where T:#(#trait_bounds) + *))
        }
    } else {
        None
    }
}

// Build the impl for  the ToFromNetworkOrder trait code depending on whether the struct has a lifetime, a generic
// type
fn get_impl(derive_input: &DeriveInput) -> proc_macro2::TokenStream {
    // get ident from input
    let ident = &derive_input.ident;

    // visit AST to check whether the structure has a lifetime, a generic type or both
    // The ExprVisitor structure will also get trait bounds
    let mut visitor = ExprVisitor::default();
    visitor.visit_derive_input(&derive_input);

    // build where clause if any
    let where_clause = get_where_clause(&visitor);

    // both a lifetime and a generic
    if visitor.is_lifetime && visitor.is_generic {
        let where_bound = where_clause.unwrap();
        quote! {
            impl<'a, T> ToFromNetworkOrder<'a> for #ident<'a, T> #where_bound
        }
    // only a lifetime
    } else if visitor.is_lifetime {
        quote! {
            impl<'a> ToFromNetworkOrder<'a> for #ident<'a>
        }
    // only a generic type
    } else if visitor.is_generic {
        let where_bound = where_clause.unwrap();
        quote! {
            impl<'a, T> ToFromNetworkOrder<'a> for #ident<T> #where_bound
        }
    // neither a lifetime nor a generic
    } else {
        quote! {
            impl<'a> ToFromNetworkOrder<'a> for #ident
        }
    }
}

// Verify if the derive macro is applied to a structure and return
// the AST structure if any
pub(crate) fn get_struct(ast: &DeriveInput) -> &DataStruct {
    if let Data::Struct(struct_token) = &ast.data {
        struct_token
    } else {
        panic!("<{}> is not a struct!", ast.ident.to_string());
    }
}

// create the impl methods for trait ToFromNetworkOrder
pub fn dns_derive(ast: &DeriveInput) -> proc_macro2::TokenStream {
    // get struct data or panic
    let struct_token = get_struct(&ast);

    // build impl clause
    let impl_clause = get_impl(&ast);

    // call to_network_bytes() call for each field
    let to_method_calls = struct_token.fields.iter().map(|f| {
        // get name of the field as TokenStream
        //println!("field={:#?}", f);
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

    // return code to the compiler
    let new_code = quote! {
        #impl_clause {
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
    };

    new_code

    // Hand the output tokens back to the compiler
    //TokenStream::from(new_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::get_derive_input;

    const E1: &'static str = "enum Foo { A, B }";
    const S1: &'static str = "struct Point { x : f64 , y : u8 , z : u32 }";
    const S2: &'static str = "struct Point<'a> { x : f64 , y : u8 , z : &'a str }";
    const S3: &'static str = "struct Point<'a, T> { x : f64 , y : T , z : &'a str }";
    const S4: &'static str = "struct Point<T> { x : f64 , y : T , z : u32 }";
    const S5: &'static str = "struct Point<'a, T: Debug+Copy> { x : f64 , y : T , z : &'a str }";
    const S6: &'static str =
        "struct Point<T: Debug + ToFromNetworkOrder<'a>> { x : f64 , y : T , z : u32 }";
    const S7: &'static str = "struct Foo(pub u64);";

    // fn get_derive_input(s: &str) -> DeriveInput {
    //     let tokens = proc_macro2::TokenStream::from_str(s).unwrap();
    //     syn::parse2(tokens).unwrap()
    // }

    #[test]
    fn visitor() {
        // S1
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S1);
        visitor.visit_derive_input(&input);
        assert!(!visitor.is_lifetime);
        assert!(!visitor.is_generic);
        assert!(visitor.bounds.is_empty());

        // S2
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S2);
        visitor.visit_derive_input(&input);
        assert!(visitor.is_lifetime);
        assert!(!visitor.is_generic);
        assert!(visitor.bounds.is_empty());

        // S3
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S3);
        visitor.visit_derive_input(&input);
        assert!(visitor.is_lifetime);
        assert!(visitor.is_generic);
        assert!(visitor.bounds.is_empty());

        // S4
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S4);
        visitor.visit_derive_input(&input);
        assert!(!visitor.is_lifetime);
        assert!(visitor.is_generic);
        assert!(visitor.bounds.is_empty());

        // S5
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S5);
        visitor.visit_derive_input(&input);
        assert!(visitor.is_lifetime);
        assert!(visitor.is_generic);
        assert!(!visitor.bounds.is_empty());

        // no trait has a lifetime
        assert!(visitor.bounds.iter().all(|x| !x.1));

        // S6
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S6);
        visitor.visit_derive_input(&input);

        assert!(visitor.is_lifetime);
        assert!(visitor.is_generic);
        assert!(!visitor.bounds.is_empty());

        // ToFromNetworkOrder has a lifetime
        let b: Vec<_> = visitor
            .bounds
            .iter()
            .filter(|b| &b.0.to_string() == "ToFromNetworkOrder")
            .collect();
        assert!(b[0].1);
    }

    #[test]
    fn where_clause() {
        // S1
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S1);
        visitor.visit_derive_input(&input);
        let where_clause = get_where_clause(&visitor);
        assert!(where_clause.is_none());

        // S2
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S2);
        visitor.visit_derive_input(&input);
        let where_clause = get_where_clause(&visitor);
        assert!(where_clause.is_none());

        // S3
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S3);
        visitor.visit_derive_input(&input);
        let where_clause = get_where_clause(&visitor);
        assert!(&where_clause.unwrap().to_string().is_empty());

        // S4
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S4);
        visitor.visit_derive_input(&input);
        let where_clause = get_where_clause(&visitor);
        assert!(&where_clause.unwrap().to_string().is_empty());

        // S5
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S5);
        visitor.visit_derive_input(&input);
        let where_clause = get_where_clause(&visitor);
        assert_eq!(&where_clause.unwrap().to_string(), "where T : Debug + Copy");

        // S6
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S6);
        visitor.visit_derive_input(&input);
        let where_clause = get_where_clause(&visitor);
        assert_eq!(
            &where_clause.unwrap().to_string(),
            "where T : Debug + ToFromNetworkOrder < 'a >"
        );

        // S7
        let mut visitor = ExprVisitor::default();
        let input = get_derive_input(S7);
        visitor.visit_derive_input(&input);
        let where_clause = get_where_clause(&visitor);
        assert!(where_clause.is_none());
    }

    #[test]
    fn impl_clause() {
        // S1
        let input = get_derive_input(S1);
        let impl_clause = get_impl(&input);
        assert_eq!(
            &impl_clause.to_string(),
            "impl < 'a > ToFromNetworkOrder < 'a > for Point"
        );

        // S2
        let input = get_derive_input(S2);
        let impl_clause = get_impl(&input);
        assert_eq!(
            &impl_clause.to_string(),
            "impl < 'a > ToFromNetworkOrder < 'a > for Point < 'a >"
        );

        // S3
        let input = get_derive_input(S3);
        let impl_clause = get_impl(&input);
        assert_eq!(
            &impl_clause.to_string(),
            "impl < 'a , T > ToFromNetworkOrder < 'a > for Point < 'a , T >"
        );

        // S4
        let input = get_derive_input(S4);
        let impl_clause = get_impl(&input);
        assert_eq!(
            &impl_clause.to_string(),
            "impl < 'a , T > ToFromNetworkOrder < 'a > for Point < T >"
        );

        // S5
        let input = get_derive_input(S5);
        let impl_clause = get_impl(&input);
        assert_eq!(
            &impl_clause.to_string(),
            "impl < 'a , T > ToFromNetworkOrder < 'a > for Point < 'a , T > where T : Debug + Copy"
        );

        // S6
        let input = get_derive_input(S6);
        let impl_clause = get_impl(&input);
        assert_eq!(&impl_clause.to_string(), "impl < 'a , T > ToFromNetworkOrder < 'a > for Point < 'a , T > where T : Debug + ToFromNetworkOrder < 'a >");

        // S7
        let input = get_derive_input(S7);
        let impl_clause = get_impl(&input);
        assert_eq!(
            &impl_clause.to_string(),
            "impl < 'a > ToFromNetworkOrder < 'a > for Foo"
        );
    }

    #[test]
    fn a_structure() {
        // S1
        let input = get_derive_input(S1);
        let structure = get_struct(&input);
        assert!(matches!(structure.fields, syn::Fields::Named(_)));

        // S7
        let input = get_derive_input(S7);
        let structure = get_struct(&input);
        assert!(matches!(structure.fields, syn::Fields::Unnamed(_)));
    }

    #[test]
    #[should_panic]
    fn not_a_structure() {
        // E1
        let input = get_derive_input(E1);
        let _ = get_struct(&input);
    }

    #[test]
    fn build_impl() {
        // S1
        let input = get_derive_input(S1);
        let new_code = dns_derive(&input).to_string();
        assert!(new_code.contains("self . x"));
        assert!(new_code.contains("self . y"));
        assert!(new_code.contains("self . z"));

        // S7
        // let input = get_derive_input(S7);
        // let new_code = dns_derive(&input).to_string();
        // assert_eq!(new_code, "");
    }
}
