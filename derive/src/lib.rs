use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Fields};

#[proc_macro_derive(DorySerialize)]
pub fn derive_dory_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let serialize_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let field_serialize = fields.named.iter().map(|f| {
                    let field_name = &f.ident;
                    quote! {
                        self.#field_name.serialize_with_mode(&mut writer, compress)?;
                    }
                });
                quote! { #(#field_serialize)* }
            }
            Fields::Unnamed(fields) => {
                let field_serialize = fields.unnamed.iter().enumerate().map(|(i, _)| {
                    let index = syn::Index::from(i);
                    quote! {
                        self.#index.serialize_with_mode(&mut writer, compress)?;
                    }
                });
                quote! { #(#field_serialize)* }
            }
            Fields::Unit => quote! {},
        },
        Data::Enum(_) => {
            return syn::Error::new_spanned(input, "DorySerialize cannot be derived for enums yet")
                .to_compile_error()
                .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(input, "DorySerialize cannot be derived for unions")
                .to_compile_error()
                .into();
        }
    };

    let size_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let field_size = fields.named.iter().map(|f| {
                    let field_name = &f.ident;
                    quote! {
                        size += self.#field_name.serialized_size(compress);
                    }
                });
                quote! { #(#field_size)* }
            }
            Fields::Unnamed(fields) => {
                let field_size = fields.unnamed.iter().enumerate().map(|(i, _)| {
                    let index = syn::Index::from(i);
                    quote! {
                        size += self.#index.serialized_size(compress);
                    }
                });
                quote! { #(#field_size)* }
            }
            Fields::Unit => quote! {},
        },
        _ => unreachable!(),
    };

    let expanded = quote! {
        impl DorySerialize for #name {
            fn serialize_with_mode<W: std::io::Write>(
                &self,
                mut writer: W,
                compress: Compress,
            ) -> Result<(), SerializationError> {
                #serialize_fields
                Ok(())
            }

            fn serialized_size(&self, compress: Compress) -> usize {
                let mut size = 0;
                #size_fields
                size
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(DoryDeserialize)]
pub fn derive_dory_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let deserialize_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let field_names = fields.named.iter().map(|f| &f.ident);
                let field_deserialize = fields.named.iter().map(|f| {
                    let field_name = &f.ident;
                    let field_ty = &f.ty;
                    quote! {
                        let #field_name = <#field_ty>::deserialize_with_mode(&mut reader, compress, validate)?;
                    }
                });
                quote! {
                    #(#field_deserialize)*
                    Ok(Self { #(#field_names),* })
                }
            }
            Fields::Unnamed(fields) => {
                let field_deserialize = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let field_name = syn::Ident::new(&format!("field_{}", i), f.ty.span());
                    let field_ty = &f.ty;
                    quote! {
                        let #field_name = <#field_ty>::deserialize_with_mode(&mut reader, compress, validate)?;
                    }
                });
                let field_names = (0..fields.unnamed.len())
                    .map(|i| syn::Ident::new(&format!("field_{}", i), fields.unnamed.span()));
                quote! {
                    #(#field_deserialize)*
                    Ok(Self(#(#field_names),*))
                }
            }
            Fields::Unit => quote! { Ok(Self) },
        },
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                input,
                "DoryDeserialize cannot be derived for enums yet",
            )
            .to_compile_error()
            .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(input, "DoryDeserialize cannot be derived for unions")
                .to_compile_error()
                .into();
        }
    };

    let expanded = quote! {
        impl DoryDeserialize for #name {
            fn deserialize_with_mode<R: std::io::Read>(
                mut reader: R,
                compress: Compress,
                validate: Validate,
            ) -> Result<Self, SerializationError> {
                #deserialize_fields
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Valid)]
pub fn derive_valid(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let check_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let field_checks = fields.named.iter().map(|f| {
                    let field_name = &f.ident;
                    quote! {
                        self.#field_name.check()?;
                    }
                });
                quote! { #(#field_checks)* }
            }
            Fields::Unnamed(fields) => {
                let field_checks = fields.unnamed.iter().enumerate().map(|(i, _)| {
                    let index = syn::Index::from(i);
                    quote! {
                        self.#index.check()?;
                    }
                });
                quote! { #(#field_checks)* }
            }
            Fields::Unit => quote! {},
        },
        Data::Enum(_) => {
            return syn::Error::new_spanned(input, "Valid cannot be derived for enums yet")
                .to_compile_error()
                .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(input, "Valid cannot be derived for unions")
                .to_compile_error()
                .into();
        }
    };

    let expanded = quote! {
        impl Valid for #name {
            fn check(&self) -> Result<(), SerializationError> {
                #check_fields
                Ok(())
            }
        }
    };

    TokenStream::from(expanded)
}
