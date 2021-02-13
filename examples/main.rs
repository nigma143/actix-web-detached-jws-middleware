use std::{fmt::Display, pin::Pin, rc::Rc};

use actix_service::boxed::factory;
use actix_web::{App, HttpMessage, HttpResponse, HttpServer, Responder, dev::ServiceRequest, get, middleware::errhandlers::ErrorHandlers, rt::blocking, web::{self, BytesMut}};
use actix_web_detached_jws_middleware::verify::{
    DetachedJwsVerify, MiddlewareOptions, ShouldVerify,
};
use detached_jws::JwsHeader;
use executor::block_on_stream;
use futures::{executor, future::{FutureExt, LocalBoxFuture}};
use futures::{Future, StreamExt};
use openssl::sign::Verifier;

#[get("/{id}/{name}/index.html")]
async fn index(web::Path((id, name)): web::Path<(u32, String)>) -> impl Responder {
    format!("Hello {}! id:{}", name, id)
}

fn aaa(n: &JwsHeader) -> Option<Verifier<'static>> {
    None
}

async fn a_should(req: &mut ServiceRequest) -> bool {
    let mut body = BytesMut::new();
    let mut stream = req.take_payload();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.unwrap());
    }

    println!("request body: {:?}", body);

    false
}

fn should(req: &mut ServiceRequest) -> ShouldVerify {
    
    println!("here1");

    let jws = req.headers().get("X-JWS-Signature");

    let mut body = BytesMut::new();
    //req.take_payload().
    println!("here2");
    let stream = req.take_payload();
    
    let mut das = executor::block_on_stream(stream);
    
    println!("here3");
    while let Some(chunk) = das.next() {
        
    println!("here4");
        body.extend_from_slice(&chunk.unwrap());
    }

    println!("request body: {:?}", body);

    false
}

struct TestS {
    fun: Box<dyn Fn(usize) -> LocalBoxFuture<'static, usize>>
}

impl TestS {
    fn new(f: dyn Fn(usize) -> LocalBoxFuture<'static, usize>) -> Self
     {
         Self {
             fun: Box::new(f)
         }

    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(
                DetachedJwsVerify::new(aaa).should_verify(should)
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
