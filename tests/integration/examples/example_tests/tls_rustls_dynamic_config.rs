use super::utils::{self, ClientService};
use rama::{
    Context, Layer, Service,
    context::RequestContextExt,
    error::BoxError,
    http::{
        Response,
        client::EasyHttpWebClient,
        layer::{
            decompression::DecompressionLayer,
            follow_redirect::FollowRedirectLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer, managed::DoNotRetry},
            trace::TraceLayer,
        },
    },
    layer::{MapResultLayer, layer_fn},
    net::{
        address::Domain,
        tls::{
            DataEncoding,
            client::{NegotiatedTlsParameters, ServerVerifyMode},
        },
    },
    tls::boring::{client::TlsConnectorDataBuilder, core::x509::X509},
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};
use tokio_test::assert_err;

use std::{str::FromStr, time::Duration};

#[tokio::test]
#[ignore]
async fn test_tls_rustls_dynamic_config() {
    utils::init_tracing();

    let chain = DataEncoding::DerStack(
        X509::stack_from_pem(include_bytes!(
            "../../../../examples/assets/example.com.crt"
        ))
        .unwrap()
        .into_iter()
        .map(|i| i.to_der().unwrap())
        .collect(),
    );

    let second_chain = DataEncoding::DerStack(
        X509::stack_from_pem(include_bytes!(
            "../../../../examples/assets/second_example.com.crt"
        ))
        .unwrap()
        .into_iter()
        .map(|i| i.to_der().unwrap())
        .collect(),
    );

    let tests: Vec<(DataEncoding, Option<&'static str>)> = vec![
        (chain, Some("example")),
        (second_chain, Some("second.example")),
    ];

    let mut runner = utils::ExampleRunner::interactive("tls_rustls_dynamic_config", Some("rustls"));

    for (chain, host) in tests.into_iter() {
        let client = http_client(&host);
        runner.set_client(client);

        let response = runner
            .get("https://127.0.0.1:64804")
            .send(Context::default())
            .await
            .unwrap();

        let certificates = response
            .extensions()
            .get::<RequestContextExt>()
            .and_then(|ext| ext.get::<NegotiatedTlsParameters>())
            .unwrap()
            .peer_certificate_chain
            .clone()
            .unwrap();

        assert_eq!(chain, certificates);
    }

    // Connections for unknown or empty sni values should fail
    let mut ctx = Context::default();
    ctx.insert(DoNotRetry::default());

    let client = http_client(&Some("unknown.value"));
    runner.set_client(client);
    let result = runner
        .get("https://127.0.0.1:64804")
        .send(ctx.clone())
        .await;
    assert_err!(result);

    let client = http_client(&None);
    runner.set_client(client);

    let mut ctx = Context::default();
    ctx.insert(DoNotRetry::default());
    let result = runner.get("https://127.0.0.1:64804").send(ctx).await;
    assert_err!(result);
}

fn http_client<State>(host: &Option<&str>) -> ClientService<State>
where
    State: Clone + Send + Sync + 'static,
{
    let host = host.map(|host| Domain::from_str(host).unwrap());
    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .maybe_with_server_name(host)
        .with_store_server_certificate_chain(true)
        .into_shared_builder();
    let inner_client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
        .build();

    (
        MapResultLayer::new(map_internal_client_error),
        TraceLayer::new_for_http(),
        #[cfg(feature = "compression")]
        DecompressionLayer::new(),
        FollowRedirectLayer::default(),
        layer_fn(|inner| inner),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(60),
                    0.01,
                    HasherRng::default,
                )
                .unwrap(),
            ),
        ),
        AddRequiredRequestHeadersLayer::default(),
    )
        .into_layer(inner_client)
        .boxed()
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, rama::error::BoxError>
where
    E: Into<rama::error::BoxError>,
    Body: rama::http::dep::http_body::Body<Data = bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
