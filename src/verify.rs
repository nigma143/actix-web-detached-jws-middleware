use core::future;
use std::{
    any::Any,
    marker::PhantomData,
    sync::Arc,
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
use futures::future::{ok, Future, Ready};
use futures::stream::StreamExt;

pub type ShouldVerify = bool;

pub enum VerifyErrorType {
    HeaderNotFound,
    IncorrectSignature,
    Other(anyhow::Error),
}

pub trait DetachedJwsConfig<'a> {
    type Verifier: Verify;
    type ShouldVerify: Future<Output = ShouldVerify>;
    type ErrorHandler: Future<Output = Error>;

    fn get_verifier(&'a self, h: &JwsHeader) -> Option<Self::Verifier>;

    fn should_verify(&'a self, req: &ServiceRequest) -> Self::ShouldVerify;

    fn error_handler(&'a self, req: &ServiceRequest, error: VerifyErrorType) -> Self::ErrorHandler;
}

pub struct DetachedJwsVerify<T> {
    config: Arc<T>,
}

impl<T> DetachedJwsVerify<T> {
    pub fn new(config: Arc<T>) -> Self {
        Self { config }
    }
}

impl<S, B, T> Transform<S> for DetachedJwsVerify<T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    T: for<'a> DetachedJwsConfig<'a> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = Middleware<S, T>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(Middleware {
            service: Rc::new(RefCell::new(service)),
            config: self.config.clone(),
        })
    }
}

pub struct Middleware<S, T> {
    // This is special: We need this to avoid lifetime issues.
    service: Rc<RefCell<S>>,
    config: Arc<T>,
}

impl<S, B, T> Service for Middleware<S, T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    //S::Future: 'static,
    T: for<'a> DetachedJwsConfig<'a> + 'static,
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
        let config = self.config.clone();

        Box::pin(async move {
            let should_verify = config.should_verify(&req).await;

            if should_verify {
                let jws = match req.headers().get("X-JWS-Signature") {
                    Some(h) => h,
                    None => {
                        return Err(config
                            .error_handler(&req, VerifyErrorType::HeaderNotFound)
                            .await)
                    }
                };

                let mut encoder = match DeserializeJwsWriter::new(&jws, |h| config.get_verifier(h))
                {
                    Ok(o) => o,
                    Err(e) => {
                        return Err(config.error_handler(&req, VerifyErrorType::Other(e)).await)
                    }
                };

                let mut stream = req.take_payload();
                while let Some(chunk) = stream.next().await {
                    encoder.write_all(&chunk?)?;
                }

                let _ = match encoder.finish() {
                    Ok(o) => o,
                    Err(_) => {
                        return Err(config
                            .error_handler(&req, VerifyErrorType::IncorrectSignature)
                            .await)
                    }
                };
            }

            Ok(svc.call(req).await?)
        })
    }
}
