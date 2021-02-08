#[macro_use]
extern crate lazy_static;

use actix_service::{IntoService, Transform};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    http::{header::CONTENT_TYPE, HeaderValue, StatusCode},
    middleware::errhandlers::{ErrorHandlerResponse, ErrorHandlers},
    test::{self, TestRequest},
    HttpResponse,
};
use actix_web_detached_jws_middleware::verify::DetachedJwsVerify;
use detached_jws::JwsHeader;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    pkey::Private,
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
};

#[actix_rt::test]
async fn test_handler() {
    lazy_static! {
        static ref KEYPAIR_PS256: PKey<Private> =
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    }

    let mut signer = Signer::new(MessageDigest::sha256(), &KEYPAIR_PS256).unwrap();
    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

    let payload: Vec<u8> = (0..255).collect();

    let jws = detached_jws::serialize(
        "PS256".to_owned(),
        JwsHeader::new(),
        &mut payload.as_slice(),
        signer,
    )
    .unwrap();

    let srv =
        |req: ServiceRequest| futures::future::ok(req.into_response(HttpResponse::Ok().finish()));

    let mut mw = DetachedJwsVerify::new(|_| -> Option<Verifier> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &KEYPAIR_PS256).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        Some(verifier)
    })
    .new_transform(srv.into_service())
    .await
    .unwrap();

    let resp = test::call_service(
        &mut mw,
        TestRequest::default()
            .header("X-JWS-Signature", jws)
            .set_payload(payload)
            .to_srv_request(),
    )
    .await;
}
