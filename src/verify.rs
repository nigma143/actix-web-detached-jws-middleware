use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::{cell::RefCell, io::Write};

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

pub struct DetachedJwsVerify<VS> {
    pub selector: Rc<VS>,
}

impl<VS, V> DetachedJwsVerify<VS>
where
    VS: Fn(&JwsHeader) -> Option<V>,
    V: Verify,
{
    pub fn new(selector: VS) -> Self {
        Self {
            selector: Rc::new(selector),
        }
    }
}

impl<S, B, VS, V> Transform<S> for DetachedJwsVerify<VS>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    VS: Fn(&JwsHeader) -> Option<V> + 'static,
    V: Verify,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = DetachedJwsVerifyService<S, VS>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let selector = self.selector.clone();

        ok(DetachedJwsVerifyService {
            service: Rc::new(RefCell::new(service)),
            selector: selector,
        })
    }
}

pub struct DetachedJwsVerifyService<S, VS> {
    // This is special: We need this to avoid lifetime issues.
    service: Rc<RefCell<S>>,
    selector: Rc<VS>,
}

impl<S, B, VS, V> Service for DetachedJwsVerifyService<S, VS>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    VS: Fn(&JwsHeader) -> Option<V> + 'static,
    V: Verify,
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
        let selector = self.selector.clone();

        Box::pin(async move {
            let jws = match req.headers().get("X-JWS-Signature") {
                Some(h) => h,
                None => Err(ErrorBadRequest("`X-JWS-Signature` header not declared"))?,
            };

            let mut encoder = match DeserializeJwsWriter::new(&jws, |h| selector(h)) {
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
