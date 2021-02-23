use std::{fmt::Display, marker::PhantomData, pin::Pin, rc::Rc};

use actix_service::{boxed::factory, Service};
use actix_web::{
    dev::ServiceRequest,
    error::ErrorForbidden,
    get,
    middleware::errhandlers::ErrorHandlers,
    rt::blocking,
    web::{self, BytesMut},
    App, FromRequest, HttpMessage, HttpResponse, HttpServer, Responder,
};
use actix_web_detached_jws_middleware::verify::{
    DetachedJwsVerify, MiddlewareOptions, ShouldVerify, VerifyErrorType,
};
use detached_jws::JwsHeader;
use executor::block_on_stream;
use futures::{
    executor,
    future::{FutureExt, LocalBoxFuture},
};
use futures::{Future, StreamExt};
use openssl::sign::Verifier;

#[get("/{id}/{name}/index.html")]
async fn index(web::Path((id, name)): web::Path<(u32, String)>) -> impl Responder {
    format!("Hello {}! id:{}", name, id)
}

fn aaa(n: &JwsHeader) -> Option<Verifier<'static>> {
    None
}

async fn should_verify(mut req: ServiceRequest) -> (ServiceRequest, ShouldVerify) {
    let mut body = BytesMut::new();
    let mut stream = req.take_payload();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.unwrap());
    }

    //println!("request body: {:?}", body);

    (req, true)
}

async fn error_handler(
    _req: ServiceRequest,
    error_type: VerifyErrorType,
) -> actix_web::error::Error {
    match error_type {
        VerifyErrorType::HeaderNotFound => ErrorForbidden("Header Not Found"),
        VerifyErrorType::IncorrectSignature => ErrorForbidden("Incorrect Signature"),
        VerifyErrorType::Other => ErrorForbidden("Other"),
    }
}

//aync fn mv(s: &mut ServiceRequest, r: &mut AppRouting) ->

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(
                DetachedJwsVerify::new(aaa).should_verify(should_verify).error_handler(error_handler)
                //DetachedJwsVerify::new(|h: &JwsHeader| -> Option<Verifier> {None})
                //DetachedJwsVerify::new(aaa).should_verify(should),
            )
            /*.wrap(
            ErrorHandlers::new()
                        .handler(http::StatusCode::INTERNAL_SERVER_ERROR, render_500),
                )*/
            .service(web::resource("/test").route(web::get().to(|| HttpResponse::Ok())))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
