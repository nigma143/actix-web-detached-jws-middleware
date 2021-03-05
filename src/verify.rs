use std::pin::Pin;
use std::rc::Rc;
use std::{cell::RefCell, io::Write};
use std::{
    sync::Arc,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_web::{
    dev::ServiceRequest,
    dev::{Body, ServiceResponse},
    Error, HttpMessage,
};
use actix_web_buffering::{enable_request_buffering, FileBufferingStreamWrapper};
use detached_jws::{DeserializeJwsWriter, JwsHeader, Verify};
use futures::future::{ok, Future, Ready};
use futures::{stream::StreamExt, FutureExt};

pub enum VerifyErrorType {
    HeaderNotFound,
    IncorrectSignature,
    Other(anyhow::Error),
}

pub trait DetachedJwsVerifyConfig<'a> {
    type Verifier: Verify;
    type ErrorHandler: Future<Output = Error>;

    fn get_verifier(&'a self, h: &JwsHeader) -> Option<Self::Verifier>;

    fn error_handler(
        &'a self,
        req: &'a mut ServiceRequest,
        error: VerifyErrorType,
    ) -> Self::ErrorHandler;
}

pub struct DetachedJwsVerify<T> {
    config: Arc<T>,
    buffering: Rc<FileBufferingStreamWrapper>,
}

impl<T> DetachedJwsVerify<T> {
    pub fn new(config: Arc<T>) -> Self {
        Self {
            config,
            buffering: Rc::new(FileBufferingStreamWrapper::new()),
        }
    }

    pub fn override_buffering(mut self, v: Rc<FileBufferingStreamWrapper>) -> Self {
        self.buffering = v;
        self
    }
}

impl<S, T> Transform<S> for DetachedJwsVerify<T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    T: for<'a> DetachedJwsVerifyConfig<'a> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type InitError = ();
    type Transform = Middleware<S, T>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(Middleware {
            service: Rc::new(RefCell::new(service)),
            config: Arc::clone(&self.config),
            buffering: Rc::clone(&self.buffering),
        })
    }
}

pub struct Middleware<S, T> {
    // This is special: We need this to avoid lifetime issues.
    service: Rc<RefCell<S>>,
    config: Arc<T>,
    buffering: Rc<FileBufferingStreamWrapper>,
}

impl<S, T> Service for Middleware<S, T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    T: for<'a> DetachedJwsVerifyConfig<'a> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, mut req: ServiceRequest) -> Self::Future {
        let mut svc = self.service.clone();
        let config = self.config.clone();

        enable_request_buffering(&self.buffering, &mut req);

        async move {
            let jws = match req.headers().get("x-jws-signature") {
                Some(h) => h,
                None => {
                    return Err(config
                        .error_handler(&mut req, VerifyErrorType::HeaderNotFound)
                        .await)
                }
            };

            let mut writer = match DeserializeJwsWriter::new(&jws, |h| config.get_verifier(h)) {
                Ok(o) => o,
                Err(e) => {
                    return Err(config
                        .error_handler(&mut req, VerifyErrorType::Other(e))
                        .await)
                }
            };

            let mut stream = req.take_payload();
            while let Some(chunk) = stream.next().await {
                writer.write_all(&chunk?)?;
            }

            let _ = match writer.finish() {
                Ok(o) => o,
                Err(_) => {
                    return Err(config
                        .error_handler(&mut req, VerifyErrorType::IncorrectSignature)
                        .await)
                }
            };

            svc.call(req).await
        }
        .boxed_local()
    }
}
