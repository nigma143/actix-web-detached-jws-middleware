use core::future;
use std::{
    any::Any,
    task::{Context, Poll},
};
use std::{borrow::BorrowMut, pin::Pin};
use std::{cell::RefCell, io::Write};
use std::{fmt::Display, rc::Rc};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::{
    error::{ErrorBadRequest, ErrorUnauthorized},
    web::BytesMut,
    HttpResponse,
};
use detached_jws::{DeserializeJwsWriter, JwsHeader, Verify};
use futures::future::{ok, Future, LocalBoxFuture, Ready};
use futures::stream::StreamExt;

pub type ShouldVerify = bool;

pub struct MiddlewareOptions<S> {
    pub verify_selector: S,
    pub should_verify: Option<Box<dyn Fn(&mut ServiceRequest) -> ShouldVerify>>,
}

pub struct DetachedJwsVerify<S> {
    pub options: Rc<MiddlewareOptions<S>>,
}

impl<S> DetachedJwsVerify<S> {
    pub fn new(selector: S) -> Self {
        Self {
            options: Rc::new(MiddlewareOptions {
                verify_selector: selector,
                should_verify: None,
            }),
        }
    }

    pub fn should_verify<F>(mut self, f: F) -> Self
    where
        F: Fn(&mut ServiceRequest) -> ShouldVerify + 'static,
    {
        Rc::get_mut(&mut self.options).unwrap().should_verify = Some(Box::new(f));
        self
    }
}

impl<S, B, SV, V> Transform<S> for DetachedJwsVerify<SV>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    SV: Fn(&JwsHeader) -> Option<V> + 'static,
    V: Verify + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = Middleware<S, SV>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let options = self.options.clone();

        ok(Middleware {
            service: Rc::new(RefCell::new(service)),
            options: options,
        })
    }
}

pub struct Middleware<S, SV> {
    // This is special: We need this to avoid lifetime issues.
    service: Rc<RefCell<S>>,
    options: Rc<MiddlewareOptions<SV>>,
}

impl<S, B, SV, V> Service for Middleware<S, SV>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    SV: Fn(&JwsHeader) -> Option<V> + 'static,
    V: Verify + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, mut req: ServiceRequest) -> Self::Future {
        let mut svc = self.service.clone();
        let options = self.options.clone();

        Box::pin(async move {
            
            let should_verify = match options.should_verify {
                Some(ref f) => f(&mut req),
                None => true,
            };


            let jws = match req.headers().get("X-JWS-Signature") {
                Some(h) => h,
                None => Err(ErrorBadRequest("`X-JWS-Signature` header not declared"))?,
            };

            let mut encoder =
                match DeserializeJwsWriter::new(&jws, |h| (options.verify_selector)(h)) {
                    Ok(o) => o,
                    Err(e) => Err(ErrorBadRequest(e))?,
                };

            let mut stream = req.take_payload();
            while let Some(chunk) = stream.next().await {
                encoder.write_all(&chunk?)?;
            }

            let _ = match encoder.finish() {
                Ok(o) => o,
                Err(e) => Err(ErrorBadRequest(e))?,
            };

            Ok(svc.call(req).await?)
        })
    }
}
