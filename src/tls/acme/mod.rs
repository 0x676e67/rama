use parking_lot::Mutex;
use rama_core::{
    error::{ErrorContext, ErrorExt, OpaqueError},
    service::BoxService,
};
use rama_http::{Body, dep::http_body_util::BodyExt, utils::HeaderValueGetter};
use rama_net::stream::Stream;
use rama_tls_rustls::dep::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    rcgen::{self, CustomExtension, KeyPair},
    rustls::{
        crypto::aws_lc_rs::sign::any_ecdsa_type, server::ClientHello as RustlsClientHello,
        server::ResolvesServerCert, sign::CertifiedKey,
    },
};
// use rama_tls::{
//     rustls::dep::{
//         pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
//         rcgen::{self, CustomExtension, KeyPair},
//         rustls::{
//             crypto::aws_lc_rs::sign::any_ecdsa_type,
//             server::{ClientHello as RustlsClientHello, ResolvesServerCert},
//             sign::CertifiedKey,
//         },
//     },
//     std::dep::boring::{
//         asn1::Asn1Time,
//         hash::MessageDigest,
//         x509::{
//             X509,
//             extension::{BasicConstraints, SubjectAlternativeName},
//         },
//     },
// };
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, timeout};

use crate::{
    Context, Layer, Service,
    error::BoxError,
    http::{
        BodyExtractExt, HeaderValue, Request, Response,
        client::EasyHttpWebClient,
        layer::{
            decompression::DecompressionLayer,
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            required_header::AddRequiredRequestHeadersLayer,
            timeout::TimeoutLayer,
        },
        service::client::HttpClientExt,
    },
    layer::MapResultLayer,
};
use std::{convert::Infallible, error::Error, sync::Arc, time::Duration};

use proto::{
    client::{
        CreateAccountOptions, Jws, Key, KeyAuthorization, NewOrderPayload, ProtectedHeader,
        ProtectedHeaderKey, Signer,
    },
    server::{self, Problem},
};

pub mod proto;

// TODO user_agent: rame version
// TODO accept_language: en
// TODO binary base64url (trailing = stripped)
// TODO body inside jws acc private key, flattened serialisation
//      protected header: alg, nonce, url, jwk|kid
// signature es256 or EdDsa (Ed25519 variant)
// TODO content_type: application/jose+json

// POST as get = get -> post ''

// GET possible for directory and newNonce

/*
Happy path
- get directory
- get nonce head
- create acc
- submit order
- fetch challenges post as get
- respond to challenges
- poll status
- finalize order
- poll status
- download cert
*/

const REPLAY_NONCE_HEADER: &str = "replay-nonce";
const LOCATION_HEADER: &str = "location";

/// Acme client that will used for all acme operations
pub struct Client {
    https_client: AcmeHttpsClient,
    directory: server::Directory,
    nonce: Mutex<Option<String>>,
}

/// Alias for http client used by acme client
type AcmeHttpsClient = BoxService<(), Request, Response, BoxError>;

impl Client {
    /// Create a new acme [`Client`] for the given directory url and using the default https client
    pub async fn new(directory_url: &str) -> Result<Client, OpaqueError> {
        let https_client = create_https_client();
        Self::new_with_https_client(directory_url, https_client).await
    }

    /// Create a new acme [`Client`] for the given acme provider and using the default https client
    pub async fn new_for_provider(provider: &AcmeProvider) -> Result<Client, OpaqueError> {
        let https_client = create_https_client();
        Self::new_with_https_client(provider.as_str(), https_client).await
    }

    /// Create a new acme [`Client`] for the given directory url and using the provided https client
    pub async fn new_with_https_client(
        directory_url: &str,
        https_client: AcmeHttpsClient,
    ) -> Result<Client, OpaqueError> {
        let directory = https_client
            .get(format!("{}/dir", directory_url))
            .send(Context::default())
            .await?
            .try_into_json::<server::Directory>()
            .await?;

        Ok(Self {
            https_client,
            directory,
            nonce: Mutex::new(None),
        })
    }

    /// Create a new acme [`Client`] for the given acme provider and using the provided https client
    pub async fn new_for_provider_with_https_client(
        provider: &AcmeProvider,
    ) -> Result<Client, OpaqueError> {
        let https_client = create_https_client();
        Self::new_with_https_client(provider.as_str(), https_client).await
    }

    /// Get a nonce for making requests, if no nonce from a previous request is
    /// available this function will try to fetch a new one
    async fn nonce(&self) -> Result<String, OpaqueError> {
        if let Some(nonce) = self.nonce.lock().take() {
            return Ok(nonce);
        }

        let response = self
            .https_client
            .head(&self.directory.new_nonce)
            .send(Context::default())
            .await
            .context("fetch new nonce")?;

        let nonce = Self::get_nonce_from_response(&response)?;
        Ok(nonce)
    }

    fn get_nonce_from_response(response: &Response<Body>) -> Result<String, OpaqueError> {
        Ok(response
            .header_str(REPLAY_NONCE_HEADER)
            .context("get nonce from headers")?
            .to_owned())
    }

    pub async fn create_account(
        &self,
        options: CreateAccountOptions,
    ) -> Result<Account, OpaqueError> {
        let (key, _) = Key::generate().context("generate key for account")?;

        let response = self
            .post::<server::Account>(&self.directory.new_account, Some(&options), &key)
            .await
            .context("create account request")?;

        let location: String = response.header_str("location").unwrap().into();
        println!("Status code: {}", response.status());
        let account = response.into_body().context("accound info")?;

        Ok(Account {
            client: self,
            inner: account,
            credentials: AccountCredentials {
                key: key,
                kid: location,
            },
        })
    }

    async fn post<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
        signer: &impl Signer,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        loop {
            let nonce = self.nonce().await?;
            let protected_header = signer.protected_header(Some(&nonce), url);

            let jws = Jws::new(payload, &protected_header, signer).context("create jws payload")?;
            // println!("jose_json: {:?}", jose_json);
            let request = self
                .https_client
                .post(url)
                .header("content-type", "application/jose+json")
                // TODO use const
                .header("user-agent", "rama")
                .json(&jws);

            // println!("Request: {:?}", request);
            let response = request.send(Context::default()).await?;

            *self.nonce.lock() = Some(Self::get_nonce_from_response(&response)?);

            let response = Self::parse_response::<T>(response).await.unwrap();
            match response.body() {
                Ok(_) => return Ok(response),
                Err(problem) => {
                    if let server::Problem::BadNonce(_) = problem {
                        continue;
                    }
                    return Ok(response);
                }
            }
        }
    }

    async fn parse_response<T: serde::de::DeserializeOwned + Send + 'static>(
        response: Response,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        let result = serde_json::from_slice::<T>(&bytes);
        match result {
            Ok(result) => Ok(Response::from_parts(parts, Ok(result))),
            Err(err) => {
                let problem = serde_json::from_slice::<server::Problem>(&bytes);
                match problem {
                    Ok(problem) => Ok(Response::from_parts(parts, Err(problem))),
                    Err(_err) => Err(err.context("parse problem response")),
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
/// Enum of popular acme providers and their directory url
pub enum AcmeProvider {
    LetsEncrypt(&'static str),
    ZeroSsl(&'static str),
    GoogleTrustServices(&'static str),
}

impl AcmeProvider {
    pub const LETSENCRYPT_PRODUCTION: Self =
        Self::LetsEncrypt("https://acme-v01.api.letsencrypt.org/directory");

    pub const LETSENCRYPT_STAGING: Self =
        Self::LetsEncrypt("https://acme-staging-v02.api.letsencrypt.org/directory");

    pub const ZERO_SSL_PRODUCTION: Self = Self::ZeroSsl("https://acme.zerossl.com/v2/DV90");

    pub const GOOGLE_TRUST_SERVICES_PRODUCTION: Self =
        Self::GoogleTrustServices("https://dv.acme-v02.api.pki.goog/directory");

    pub const GOOGLE_TRUST_SERVICES_STAGING: Self =
        Self::GoogleTrustServices("https://dv.acme-v02.test-api.pki.goog/directory");

    pub fn as_str(&self) -> &str {
        match self {
            AcmeProvider::LetsEncrypt(url) => url,
            AcmeProvider::ZeroSsl(url) => url,
            AcmeProvider::GoogleTrustServices(url) => url,
        }
    }
}

pub struct Account<'a> {
    client: &'a Client,
    credentials: AccountCredentials,
    inner: server::Account,
}

struct AccountCredentials {
    key: Key,
    kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Empty {}

impl<'a> Account<'a> {
    pub async fn new_order(&self, new_order: NewOrderPayload) -> Result<Order, OpaqueError> {
        let response = self
            .post::<server::Order>(&self.client.directory.new_order.clone(), Some(&new_order))
            .await?;

        let location: String = response.header_str(LOCATION_HEADER).unwrap().into();
        let order = response.into_body().context("create order info")?;
        Ok(Order {
            account: self,
            url: location,
            inner: order,
        })
    }

    pub async fn orders(&self) -> Result<server::OrdersList, OpaqueError> {
        let response = self
            .post::<server::OrdersList>(&self.inner.orders, None::<&Empty>)
            .await?;

        let orders = response.into_body().context("open order list")?;
        Ok(orders)
    }

    pub async fn get_order(&self, order_url: &str) -> Result<Order, OpaqueError> {
        let response = self
            .post::<server::Order>(&order_url, None::<&Empty>)
            .await?;

        let location: String = response.header_str(LOCATION_HEADER).unwrap().into();

        let order = response.into_body().context("order info")?;
        Ok(Order {
            account: self,
            url: location,
            inner: order,
        })
    }

    async fn post<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        self.client.post::<T>(url, payload, &self.credentials).await
    }
}

pub struct Order<'a> {
    account: &'a Account<'a>,
    url: String,
    inner: server::Order,
}

impl Signer for AccountCredentials {
    type Signature = <Key as Signer>::Signature;

    fn protected_header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> ProtectedHeader<'n> {
        ProtectedHeader {
            alg: self.key.signing_algorithm,
            key: ProtectedHeaderKey::KeyID(&self.kid),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError> {
        self.key.sign(payload)
    }
}

impl<'a> Order<'a> {
    pub async fn refresh(&mut self) -> Result<(), OpaqueError> {
        let response = self
            .account
            .post::<server::Order>(&self.url, None::<&Empty>)
            .await?;
        self.inner = response.into_body().context("order info")?;
        Ok(())
    }

    pub async fn get_authorizations(&self) -> Result<Vec<server::Authorization>, OpaqueError> {
        let mut authz: Vec<server::Authorization> =
            Vec::with_capacity(self.inner.authorizations.len());
        for auth_url in self.inner.authorizations.iter() {
            let auth = self.get_authorization(auth_url.as_str()).await?;
            authz.push(auth);
        }

        Ok(authz)
    }

    pub async fn get_authorization(
        &self,
        authorization_url: &str,
    ) -> Result<server::Authorization, OpaqueError> {
        let response = self
            .account
            .post::<server::Authorization>(&authorization_url, None::<&Empty>)
            .await?;

        let authorization = response.into_body().context("authorization info")?;
        Ok(authorization)
    }

    pub async fn poll_until_all_authorizations_finished(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<(), OpaqueError> {
        timeout(timeout_duration, async {
            loop {
                self.refresh().await.unwrap();
                if self.inner.status != server::OrderStatus::Pending {
                    break;
                }
                // TODO use retry header
                sleep(Duration::from_millis(1000)).await;
            }
            Ok(())
        })
        .await
        .context("poll until complete")?
    }

    pub async fn refresh_challenge(
        &self,
        challenge: &mut server::Challenge,
    ) -> Result<(), OpaqueError> {
        let response = self
            .post::<server::Challenge>(&challenge.url, None::<&Empty>)
            .await
            .unwrap();

        *challenge = response.into_body().context("challenge info")?;
        Ok(())
    }

    pub async fn notify_challenge_ready(
        &self,
        challenge: &server::Challenge,
    ) -> Result<(), OpaqueError> {
        self.post::<Empty>(&challenge.url, Some(&Empty {}))
            .await?
            .into_body()
            .context("empty confirmation")?;

        Ok(())
    }

    pub fn create_key_authorization(&self, challenge: &server::Challenge) -> KeyAuthorization {
        KeyAuthorization::new(challenge, &self.account.credentials.key)
    }

    // TODO boring variants

    pub fn create_rustls_cert_for_acme_authz<'b>(
        &self,
        authorization: &'b server::Authorization,
    ) -> Result<(&'b server::Challenge, CertifiedKey), OpaqueError> {
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.r#type == server::ChallengeType::TlsAlpn01)
            .unwrap();

        let key_authz = self.create_key_authorization(challenge);

        let mut cert_params =
            rcgen::CertificateParams::new(vec![authorization.identifier.clone().into()]).unwrap();
        cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        cert_params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
            key_authz.digest().as_ref(),
        )];

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let key_der = key_pair.serialize_der();

        let cert = cert_params.self_signed(&key_pair).unwrap();
        println!("{:?}", cert.pem());
        // let cert_der = cert.der();

        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        let cert_key = CertifiedKey::new(
            vec![cert.der().clone()],
            any_ecdsa_type(&pk).unwrap().into(),
        );

        Ok((challenge, cert_key))
    }

    pub async fn poll_until_challenge_finished(
        &self,
        challenge: &mut server::Challenge,
        timeout_duration: Duration,
    ) -> Result<(), OpaqueError> {
        timeout(timeout_duration, async {
            loop {
                self.refresh_challenge(challenge).await?;
                println!("{challenge:?}");

                if challenge.status == server::ChallengeStatus::Valid
                    || challenge.status == server::ChallengeStatus::Invalid
                {
                    break;
                }

                // TODO use retry after header
                sleep(Duration::from_millis(1000)).await;
            }

            Ok(())
        })
        .await
        .context("poll until challenge ready")?
    }

    async fn post<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        self.account.post::<T>(url, payload).await
    }
}

#[cfg(test)]
mod tests {
    use proto::client::KeyAuthorization;
    use proto::server::ChallengeType;
    use proto::server::OrderStatus;
    use rama_core::rt::Executor;
    use rama_core::service::service_fn;
    use rama_http::layer::trace::TraceLayer;
    use rama_http::{layer::compression::CompressionLayer, service::web::WebService};
    use rama_http_backend::server::HttpServer;
    use rama_tcp::server::TcpListener;
    use std::sync::Arc;
    use tokio::time::sleep;

    use crate::http;
    use crate::tls::acme::proto::common::Identifier;

    use super::*;

    const TEST_DIRECTORY_URL: &str = "https://localhost:14000";

    const CREATE_ACCOUNT_OPTIONS: CreateAccountOptions = CreateAccountOptions {
        terms_of_service_agreed: Some(true),
        contact: None,
        external_account_binding: None,
        only_return_existing: None,
    };

    #[tokio::test]
    async fn directory_request() {
        let client = Client::new(TEST_DIRECTORY_URL).await.unwrap();
        let directory = &client.directory;
        assert_eq!(directory.new_account, "https://localhost:14000/sign-me-up");

        let nonce = client.nonce().await.unwrap();
        assert!(nonce.len() > 0);
    }

    #[tokio::test]
    async fn new_account_request() {
        let client = Client::new(TEST_DIRECTORY_URL).await.unwrap();
        let account = client.create_account(CREATE_ACCOUNT_OPTIONS).await.unwrap();
        assert!(true);
    }

    #[tokio::test]
    async fn new_order_request() {
        let client = Client::new(TEST_DIRECTORY_URL).await.unwrap();
        let account = client.create_account(CREATE_ACCOUNT_OPTIONS).await.unwrap();
        // account.new_order().await.unwrap();
        assert!(true);
    }

    #[derive(Debug)]
    struct ChallengeState {
        key_authz: KeyAuthorization,
    }

    const ADDR: &str = "0.0.0.0:5002";

    #[tokio::test]
    async fn http1_challenge() {
        let client = Client::new(TEST_DIRECTORY_URL).await.unwrap();

        let account = client.create_account(CREATE_ACCOUNT_OPTIONS).await.unwrap();
        let mut order = account
            .new_order(NewOrderPayload {
                identifiers: vec![Identifier::Dns("test.dev".into())],
                ..Default::default()
            })
            .await
            .unwrap();

        let authz = order.get_authorizations().await.unwrap();
        // println!("authz: {:?}", authz);
        // println!("challenges: {:?}", authz[0].challenges);

        let auth = &authz[0];
        let mut challenge = auth
            .challenges
            .iter()
            .find(|challenge| challenge.r#type == ChallengeType::Http01)
            .unwrap()
            .to_owned();

        let key_authz = order.create_key_authorization(&challenge);

        let path = format!(".well-known/acme-challenge/{}", challenge.token);

        println!("localhost:5002/{}", path);
        tracing::info!("running service at: {ADDR}");

        let state = Arc::new(ChallengeState {
            key_authz: key_authz.clone(),
        });

        let graceful = crate::graceful::Shutdown::default();

        graceful.spawn_task_fn(|guard| async move {
            let exec = Executor::graceful(guard.clone());
            HttpServer::auto(exec)
                .listen_with_state(
                    state,
                    ADDR,
                    (TraceLayer::new_for_http(), CompressionLayer::new()).layer(
                        WebService::default().get(
                            &path,
                            |ctx: Context<Arc<ChallengeState>>| async move {
                                println!("receving get request");
                                let mut response = http::Response::new(Body::from(format!(
                                    "{}",
                                    ctx.state().key_authz.as_str()
                                )));
                                let headers = response.headers_mut();
                                headers.append(
                                    "content-type",
                                    HeaderValue::from_str("application/octet-stream").unwrap(),
                                );
                                response
                            },
                        ),
                    ),
                )
                .await
                .unwrap();
        });

        sleep(Duration::from_millis(1000)).await;

        order.notify_challenge_ready(&challenge).await.unwrap();

        println!("waiting for challenge");
        order
            .poll_until_challenge_finished(&mut challenge, Duration::from_secs(30))
            .await
            .unwrap();

        println!("waiting for order");
        order
            .poll_until_all_authorizations_finished(Duration::from_secs(3))
            .await
            .unwrap();

        println!("new order state: {:?}", order.inner);
        assert_eq!(order.inner.status, OrderStatus::Ready);
    }

    #[tokio::test]
    async fn rustls_acme_challenge() {
        use rama_tls_rustls::dep::rustls;
        use rama_tls_rustls::server::{TlsAcceptorData, TlsAcceptorLayer};

        let client = Client::new(TEST_DIRECTORY_URL).await.unwrap();
        let account = client.create_account(CREATE_ACCOUNT_OPTIONS).await.unwrap();
        let mut order = account
            .new_order(NewOrderPayload {
                identifiers: vec![Identifier::Dns("test.dev".into())],
                ..Default::default()
            })
            .await
            .unwrap();

        let authz = order.get_authorizations().await.unwrap();
        // println!("authz: {:?}", authz);
        // println!("challenges: {:?}", authz[0].challenges);

        let auth = &authz[0];

        tracing::info!("running service at: {ADDR}");

        let graceful = crate::graceful::Shutdown::default();

        let (challenge, cert_key) = order.create_rustls_cert_for_acme_authz(auth).unwrap();
        let mut challenge = challenge.to_owned();

        let cert_resolver = Arc::new(ResolvesServerCertAcme::new(cert_key));

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);

        server_config.alpn_protocols = vec![rama_net::tls::ApplicationProtocol::ACME_TLS.into()];

        let acceptor_data = TlsAcceptorData::try_from(server_config).expect("create acceptor data");

        graceful.spawn_task_fn(|guard| async move {
            let tcp_service =
                TlsAcceptorLayer::new(acceptor_data).layer(service_fn(internal_tcp_service_fn));

            TcpListener::bind("127.0.0.1:5001")
                .await
                .expect("bind TCP Listener: tls")
                .serve_graceful(guard, tcp_service)
                .await;
        });

        sleep(Duration::from_millis(1000)).await;

        order.notify_challenge_ready(&challenge).await.unwrap();

        println!("waiting for challenge");
        order
            .poll_until_challenge_finished(&mut challenge, Duration::from_secs(30))
            .await
            .unwrap();

        println!("waiting for order");
        order
            .poll_until_all_authorizations_finished(Duration::from_secs(3))
            .await
            .unwrap();

        println!("new order state: {:?}", order.inner);
        assert_eq!(order.inner.status, OrderStatus::Ready);
    }

    // #[tokio::test]
    // async fn boring_acme_challenge() {
    //     use rama_tls::boring::dep::boring;
    //     use rama_tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer};

    //     let client = Client::new(TEST_DIRECTORY_URL).await;
    //     let account = client.create_account(CREATE_ACCOUNT_OPTIONS).await.unwrap();
    //     let mut order = account
    //         .new_order(NewOrderPayload {
    //             identifiers: vec![Identifier::Dns("test.dev".into())],
    //         })
    //         .await
    //         .unwrap();

    //     let authz = order.get_authorizations().await.unwrap();
    //     // println!("authz: {:?}", authz);
    //     // println!("challenges: {:?}", authz[0].challenges);

    //     let auth = &authz[0];

    //     tracing::info!("running service at: {ADDR}");

    //     let graceful = crate::graceful::Shutdown::default();

    //     // TODO implement this for boring
    //     let (challenge, server_auth) = order.create_boring_cert_for_acme_authz(auth).unwrap();
    //     let mut challenge = challenge.to_owned();

    //     let issuer = BroringAcmeIssuer {
    //         acme_data: server_auth,
    //     };

    //     let mut tls_server_config =
    //         ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
    //             kind: issuer.into(),
    //             cache_kind: CacheKind::Disabled,
    //             ..Default::default()
    //         }));

    //     tls_server_config.application_layer_protocol_negotiation =
    //         Some(vec![ApplicationProtocol::ACME_TLS]);

    //     let acceptor_data =
    //         TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

    //     graceful.spawn_task_fn(|guard| async move {
    //         let tcp_service =
    //             TlsAcceptorLayer::new(acceptor_data).layer(service_fn(internal_tcp_service_fn));

    //         TcpListener::bind("127.0.0.1:5001")
    //             .await
    //             .expect("bind TCP Listener: tls")
    //             .serve_graceful(guard, tcp_service)
    //             .await;
    //     });

    //     sleep(Duration::from_millis(1000)).await;

    //     order.notify_challenge_ready(&challenge).await.unwrap();

    //     println!("waiting for challenge");
    //     order
    //         .poll_until_challenge_finished(&mut challenge, Duration::from_secs(30))
    //         .await
    //         .unwrap();

    //     println!("waiting for order");
    //     order
    //         .poll_until_all_authorizations_finished(Duration::from_secs(3))
    //         .await
    //         .unwrap();

    //     println!("new order state: {:?}", order.inner);
    //     assert_eq!(order.inner.status, OrderStatus::Ready);
    // }
}

// /*
// Testing stuff

fn self_signed_server_auth_for_acme(
    dns_name: String,
    key_authz: &KeyAuthorization,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), OpaqueError> {
    // Create an issuer CA cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

    let server_key_pair =
        KeyPair::generate_for(alg).context("self-signed: create server key pair")?;

    let mut server_ee_params = rcgen::CertificateParams::new(vec![dns_name])
        .context("self-signed: create server EE params")?;

    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    server_ee_params.custom_extensions = vec![CustomExtension::new_acme_identifier(
        key_authz.digest().as_ref(),
    )];

    let server_cert = server_ee_params
        .self_signed(&server_key_pair)
        .context("self-signed: sign servert cert")?;

    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    Ok((
        server_cert_der,
        PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
    ))
}

async fn internal_tcp_service_fn<S>(ctx: Context<()>, mut stream: S) -> Result<(), Infallible>
where
    S: Stream + Unpin,
{
    Ok(())
}

fn create_https_client() -> BoxService<(), Request, Response, BoxError> {
    let http_client = EasyHttpWebClient::default();

    (
        MapResultLayer::new(map_internal_client_error),
        TimeoutLayer::new(Duration::from_secs(15)),
        DecompressionLayer::new(),
        FollowRedirectLayer::with_policy(Limited::default()),
        AddRequiredRequestHeadersLayer::default()
            .user_agent_header_value(HeaderValue::from_static("todo")),
    )
        .layer(http_client)
        .boxed()
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, BoxError>
where
    E: Into<BoxError>,
    Body: crate::http::dep::http_body::Body<Data = bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    match result {
        Ok(response) => Ok(response.map(crate::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}

// Resolvers for rustls

#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new(key: CertifiedKey) -> Self {
        Self { key: Arc::new(key) }
    }
}

impl ResolvesServerCert for ResolvesServerCertAcme {
    fn resolve(&self, _client_hello: RustlsClientHello) -> Option<Arc<CertifiedKey>> {
        return Some(self.key.clone());
    }
}
