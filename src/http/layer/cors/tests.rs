use std::convert::Infallible;

use crate::http::{header, Body, HeaderValue, Request, Response};
use crate::service::{service_fn, Context, Layer, Service};

use crate::http::layer::cors::CorsLayer;

#[tokio::test]
#[allow(
    clippy::declare_interior_mutable_const,
    clippy::borrow_interior_mutable_const
)]
async fn vary_set_by_inner_service() {
    const CUSTOM_VARY_HEADERS: HeaderValue = HeaderValue::from_static("accept, accept-encoding");
    const PERMISSIVE_CORS_VARY_HEADERS: HeaderValue = HeaderValue::from_static(
        "origin, access-control-request-method, access-control-request-headers",
    );

    async fn inner_svc(_: Request) -> Result<Response, Infallible> {
        Ok(Response::builder()
            .header(header::VARY, CUSTOM_VARY_HEADERS)
            .body(Body::empty())
            .unwrap())
    }

    let svc = CorsLayer::permissive().layer(service_fn(inner_svc));
    let res = svc
        .serve(Context::default(), Request::new(Body::empty()))
        .await
        .unwrap();
    let mut vary_headers = res.headers().get_all(header::VARY).into_iter();
    assert_eq!(vary_headers.next(), Some(&PERMISSIVE_CORS_VARY_HEADERS));
    assert_eq!(vary_headers.next(), Some(&CUSTOM_VARY_HEADERS));
    assert_eq!(vary_headers.next(), None);
}
