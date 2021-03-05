use std::io::Write;
use std::pin::Pin;
use std::{
    sync::Arc,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_web::{
    dev::ServiceRequest,
    dev::{Body, ServiceResponse},
    error::ErrorInternalServerError,
    http::{HeaderName, HeaderValue},
    Error,
};
use actix_web_buffering::{enable_response_buffering, FileBufferingStreamWrapper};
use detached_jws::{JwsHeader, SerializeJwsWriter, Sign};
use futures::future::{ok, Future, Ready};
use futures::{stream::StreamExt, FutureExt};

pub trait DetachedJwsSignConfig<'a> {
    type Signer: Sign;

    fn get_signer(&'a self) -> (Self::Signer, String, JwsHeader);
}

pub struct DetachedJwsSign<T> {
    config: Arc<T>,
    buffering: Arc<FileBufferingStreamWrapper>,
}

impl<T> DetachedJwsSign<T> {
    pub fn new(config: Arc<T>) -> Self {
        Self {
            config,
            buffering: Arc::new(FileBufferingStreamWrapper::new()),
        }
    }

    pub fn override_buffering(mut self, v: Arc<FileBufferingStreamWrapper>) -> Self {
        self.buffering = v;
        self
    }
}

impl<S, T> Transform<S> for DetachedJwsSign<T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    T: for<'a> DetachedJwsSignConfig<'a> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type InitError = ();
    type Transform = Middleware<S, T>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(Middleware {
            service: service,
            config: Arc::clone(&self.config),
            buffering: Arc::clone(&self.buffering),
        })
    }
}

pub struct Middleware<S, T> {
    service: S,
    config: Arc<T>,
    buffering: Arc<FileBufferingStreamWrapper>,
}

impl<S, T> Service for Middleware<S, T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    T: for<'a> DetachedJwsSignConfig<'a> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        let config = self.config.clone();
        let buffering = self.buffering.clone();

        async move {
            let svc_res = fut.await?;

            let mut svc_res = enable_response_buffering(&buffering, svc_res);

            let (signer, algorithm, jws_header) = config.get_signer();

            let mut writer = SerializeJwsWriter::new(Vec::new(), algorithm, jws_header, signer)
                .map_err(|e| ErrorInternalServerError(e))?;

            let mut stream = svc_res.take_body();
            while let Some(chunk) = stream.next().await {
                writer.write_all(&chunk?)?;
            }

            let jws_detached = writer.finish().map_err(|e| ErrorInternalServerError(e))?;

            let mut svc_res = svc_res.map_body(|_, _| stream);
            svc_res.headers_mut().insert(
                HeaderName::from_static("x-jws-signature"),
                HeaderValue::from_bytes(&jws_detached).unwrap(),
            );

            Ok(svc_res)
        }
        .boxed_local()
    }
}
