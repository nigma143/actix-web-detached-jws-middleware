//! Actix-web middleware to sign and verify detached jws ([Detached JWS](https://medium.com/gin-and-tonic/implementing-detached-json-web-signature-9ca5665ddcfc))
//!
//! # Example:
//! ```ignore
//! use std::{io::Read, sync::Arc};
//! 
//! use actix_web::{
//!     dev::ServiceRequest,
//!     error::{ErrorForbidden, ErrorInternalServerError},
//!     web::{self},
//!     App, Error, HttpServer, Responder,
//! };
//! use actix_web_detached_jws_middleware::{
//!     DetachedJwsSign, DetachedJwsSignConfig, DetachedJwsVerify, DetachedJwsVerifyConfig,
//!     VerifyErrorType,
//! };
//! use detached_jws::JwsHeader;
//! use futures::future::{ready, Ready};
//! use openssl::{
//!     hash::MessageDigest,
//!     pkcs12::{ParsedPkcs12, Pkcs12},
//!     rsa::Padding,
//!     sign::{Signer, Verifier},
//! };
//! 
//! async fn index() -> impl Responder {
//!     "this_is_response_body"
//! }
//! 
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let config = Arc::new(Config::new());
//! 
//!     HttpServer::new(move || {
//!         App::new()
//!             .service(
//!                 web::resource("/protected")
//!                     .wrap(DetachedJwsVerify::new(config.clone()))
//!                     .wrap(DetachedJwsSign::new(config.clone()))
//!                     .route(web::post().to(index)),
//!             )
//!             .service(web::resource("/simple").route(web::post().to(index)))
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//! 
//! struct Config {
//!     cert_rs256: ParsedPkcs12,
//!     cert_ps256: ParsedPkcs12,
//! }
//! 
//! impl Config {
//!     fn new() -> Self {
//!         let load_pkcs12 = |path, pass| {
//!             let mut file = std::fs::File::open(path).unwrap();
//!             let mut pkcs12 = vec![];
//!             file.read_to_end(&mut pkcs12).unwrap();
//! 
//!             let pkcs12 = Pkcs12::from_der(&pkcs12).unwrap();
//!             pkcs12.parse(pass).unwrap()
//!         };
//! 
//!         Self {
//!             cert_rs256: load_pkcs12("examples/cert_for_rs256.pfx", "123456"),
//!             cert_ps256: load_pkcs12("examples/cert_for_ps256.pfx", "123456"),
//!         }
//!     }
//! }
//! 
//! impl<'a> DetachedJwsVerifyConfig<'a> for Config {
//!     type Verifier = Verifier<'a>;
//!     type ErrorHandler = Ready<Error>;
//! 
//!     fn get_verifier(&'a self, h: &JwsHeader) -> Option<Self::Verifier> {
//!         match h.get("alg")?.as_str()? {
//!             "RS256" => {
//!                 let mut verifier =
//!                     Verifier::new(MessageDigest::sha256(), &self.cert_rs256.pkey).unwrap();
//!                 verifier.set_rsa_padding(Padding::PKCS1).unwrap();
//!                 Some(verifier)
//!             }
//!             "PS256" => {
//!                 let mut verifier =
//!                     Verifier::new(MessageDigest::sha256(), &self.cert_ps256.pkey).unwrap();
//!                 verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
//!                 Some(verifier)
//!             }
//!             _ => None,
//!         }
//!     }
//! 
//!     fn error_handler(
//!         &'a self,
//!         _: &'a mut ServiceRequest,
//!         error: VerifyErrorType,
//!     ) -> Self::ErrorHandler {
//!         ready(match error {
//!             VerifyErrorType::HeaderNotFound => ErrorForbidden("Header Not Found"),
//!             VerifyErrorType::IncorrectSignature => ErrorForbidden("Incorrect Signature"),
//!             VerifyErrorType::Other(e) => ErrorInternalServerError(e),
//!         })
//!     }
//! }
//! 
//! impl<'a> DetachedJwsSignConfig<'a> for Config {
//!     type Signer = Signer<'a>;
//! 
//!     fn get_signer(&'a self) -> (Self::Signer, String, JwsHeader) {
//!         let mut signer = Signer::new(MessageDigest::sha256(), &self.cert_ps256.pkey).unwrap();
//!         signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
//! 
//!         (signer, "PS256".into(), JwsHeader::new())
//!     }
//! }
//! 
//! ```
pub mod sign;
pub mod verify;

pub use crate::sign::{DetachedJwsSign, DetachedJwsSignConfig};
pub use crate::verify::{DetachedJwsVerify, DetachedJwsVerifyConfig, VerifyErrorType};
