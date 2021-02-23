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
use futures::stream::StreamExt;
use futures::{
    future::{ok, Future, LocalBoxFuture, Ready},
    FutureExt,
};

pub type ShouldVerify = bool;

type FnShouldVerify =
    dyn Fn(ServiceRequest) -> LocalBoxFuture<'static, (ServiceRequest, ShouldVerify)>;

pub enum VerifyErrorType {
    HeaderNotFound,
    IncorrectSignature,
    Other,
}

type FnErrorHandler = dyn Fn(ServiceRequest, VerifyErrorType) -> LocalBoxFuture<'static, Error>;

pub struct MiddlewareOptions<S> {
    pub verify_selector: S,
    pub should_verify: Option<Box<FnShouldVerify>>,
    pub error_handler: Option<Box<FnErrorHandler>>,
}

pub struct DetachedJwsVerify<S> {
    pub options: Rc<MiddlewareOptions<S>>,
}

impl<S> DetachedJwsVerify<S> {
    pub fn new<V>(selector: S) -> Self
    where
        S: Fn(&JwsHeader) -> Option<V>,
        V: Verify + 'static,
    {
        Self {
            options: Rc::new(MiddlewareOptions {
                verify_selector: selector,
                should_verify: None,
                error_handler: None,
            }),
        }
    }

    pub fn should_verify<F, Out>(mut self, f: F) -> Self
    where
        F: Fn(ServiceRequest) -> Out + 'static,
        Out: Future<Output = (ServiceRequest, ShouldVerify)> + 'static,
    {
        Rc::get_mut(&mut self.options).unwrap().should_verify =
            Some(Box::new(move |r| f(r).boxed_local()));
        self
    }

    pub fn error_handler<F, Out>(mut self, f: F) -> Self
    where
        F: Fn(ServiceRequest, VerifyErrorType) -> Out + 'static,
        Out: Future<Output = Error> + 'static,
    {
        Rc::get_mut(&mut self.options).unwrap().error_handler =
            Some(Box::new(move |r, e| f(r, e).boxed_local()));
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
        ok(Middleware {
            service: Rc::new(RefCell::new(service)),
            options: self.options.clone(),
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

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut svc = self.service.clone();
        let options = self.options.clone();

        Box::pin(async move {
            let (mut req, should_verify) = match options.should_verify {
                Some(ref f) => f(req).await,
                None => (req, true),
            };

            if should_verify {
                let jws = match req.headers().get("X-JWS-Signature") {
                    Some(h) => h,
                    None => {
                        return match options.error_handler {
                            Some(ref f) => Err(f(req, VerifyErrorType::HeaderNotFound).await),
                            None => Err(ErrorBadRequest("Jws detached header is not declared")),
                        }
                    }
                };

                let mut encoder =
                    match DeserializeJwsWriter::new(&jws, |h| (options.verify_selector)(h)) {
                        Ok(o) => o,
                        Err(e) => {
                            return match options.error_handler {
                                Some(ref f) => Err(f(req, VerifyErrorType::Other).await),
                                None => Err(ErrorBadRequest(e)),
                            }
                        }
                    };

                let mut stream = req.take_payload();
                while let Some(chunk) = stream.next().await {
                    encoder.write_all(&chunk?)?;
                }

                let _ = match encoder.finish() {
                    Ok(o) => o,
                    Err(e) => {
                        return match options.error_handler {
                            Some(ref f) => Err(f(req, VerifyErrorType::Other).await),
                            None => Err(ErrorBadRequest(e)),
                        }
                    }
                };
            }

            Ok(svc.call(req).await?)
        })
    }
}
