use std::{
    borrow::BorrowMut,
    fmt::Display,
    fs::File,
    io::{Read, Write},
    marker::PhantomData,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    thread,
};

use actix_service::{boxed::factory, Service, Transform};
use actix_web::{
    body::BodyStream,
    dev::ServiceRequest,
    error::ErrorForbidden,
    get,
    middleware::errhandlers::ErrorHandlers,
    rt::{blocking, System},
    web::{self, BytesMut},
    App, Error, FromRequest, HttpMessage, HttpResponse, HttpServer, Responder,
};
use actix_web_detached_jws_middleware::verify::{
    DetachedJwsConfig, DetachedJwsVerify, ShouldVerify, VerifyErrorType,
};
use detached_jws::{JwsHeader, Verify};
use executor::block_on_stream;
use futures::{
    executor,
    future::{ok, ready, FutureExt, LocalBoxFuture, Ready},
};
use futures::{Future, StreamExt};
use openssl::{
    hash::MessageDigest,
    pkcs12::{ParsedPkcs12, Pkcs12},
    pkey::PKey,
    rsa::Padding,
    sign::{Signer, Verifier},
};

#[get("/{id}/{name}/index.html")]
async fn index(web::Path((id, name)): web::Path<(u32, String)>) -> impl Responder {
    format!("Hello {}! id:{}", name, id)
}

struct Config {
    cert_rs256: ParsedPkcs12,
    cert_ps256: ParsedPkcs12,
}

impl Config {
    fn new() -> Self {
        let load_pkcs12 = |path, pass| {
            let mut file = File::open(path).unwrap();
            let mut pkcs12 = vec![];
            file.read_to_end(&mut pkcs12).unwrap();

            let pkcs12 = Pkcs12::from_der(&pkcs12).unwrap();
            pkcs12.parse(pass).unwrap()
        };

        Self {
            cert_rs256: load_pkcs12("examples/cert_for_rs256.pfx", "123456"),
            cert_ps256: load_pkcs12("examples/cert_for_ps256.pfx", "123456"),
        }
    }
}

impl<'a> DetachedJwsConfig<'a> for Config {
    type Verifier = Verifier<'a>;
    type ShouldVerify = Ready<ShouldVerify>;
    type ErrorHandler = Ready<Error>;

    fn get_verifier(&'a self, h: &JwsHeader) -> Option<Self::Verifier> {
        match h.get("alg")?.as_str()? {
            "RS256" => {
                let mut verifier = Verifier::new(MessageDigest::sha256(), &self.cert_rs256.pkey).unwrap();
                verifier.set_rsa_padding(Padding::PKCS1).unwrap();
                Some(verifier)
            },
            "PS256" => {
                let mut verifier = Verifier::new(MessageDigest::sha256(), &self.cert_ps256.pkey).unwrap();
                verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                Some(verifier)
            },
            _ => None,
        }
    }

    fn should_verify(&'a self, req: &ServiceRequest) -> Self::ShouldVerify {
        ready(req.headers().contains_key("X-JWS-Signature"))
    }

    fn error_handler(&'a self, req: &ServiceRequest, error: VerifyErrorType) -> Self::ErrorHandler {
        ready(match error {
            VerifyErrorType::HeaderNotFound => ErrorForbidden("Header Not Found"),
            VerifyErrorType::IncorrectSignature => ErrorForbidden("Incorrect Signature"),
            VerifyErrorType::Other(e) => ErrorForbidden(e),
        })
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = Arc::new(Config::new());

    HttpServer::new(move || {
        App::new()
            .wrap(DetachedJwsVerify::new(config.clone()))
            .service(web::resource("/test").route(web::get().to(|| HttpResponse::Ok())))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
