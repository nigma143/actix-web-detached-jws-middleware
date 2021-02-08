use actix_web::{
    get, middleware::errhandlers::ErrorHandlers, web, App, HttpResponse, HttpServer, Responder,
};
use actix_web_detached_jws_middleware::verify::DetachedJwsVerify;
use detached_jws::JwsHeader;
use openssl::sign::Verifier;

#[get("/{id}/{name}/index.html")]
async fn index(web::Path((id, name)): web::Path<(u32, String)>) -> impl Responder {
    format!("Hello {}! id:{}", name, id)
}

fn sdfdsf(h: &JwsHeader) -> Option<Verifier> {
    None
}

fn aaa(n: &JwsHeader) -> Option<Verifier<'static>> {
    None
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(
                //DetachedJwsVerify::new(|h: &JwsHeader| -> Option<Verifier> {None})
                DetachedJwsVerify::new(aaa),
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
