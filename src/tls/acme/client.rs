use super::proto::{
    client::{
        CreateAccountOptions, Jws, Key, KeyAuthorization, NewOrderPayload, ProtectedHeader,
        ProtectedHeaderKey, Signer,
    },
    server::{self, Problem},
};
use crate::{
    Context, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    http::{
        Body, BodyExtractExt, Request, Response, client::EasyHttpWebClient,
        dep::http_body_util::BodyExt, service::client::HttpClientExt, utils::HeaderValueGetter,
    },
    service::BoxService,
    tls::rustls::dep::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        rcgen::{self},
        rustls::{crypto::aws_lc_rs::sign::any_ecdsa_type, sign::CertifiedKey},
    },
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::{sleep, timeout};

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
type AcmeHttpsClient = BoxService<(), Request, Response, OpaqueError>;

impl Client {
    /// Create a new acme [`Client`] for the given directory url and using the default https client
    pub async fn new(directory_url: &str) -> Result<Client, OpaqueError> {
        let https_client = EasyHttpWebClient::default().boxed();
        Self::new_with_https_client(directory_url, https_client).await
    }

    /// Create a new acme [`Client`] for the given acme provider and using the default https client
    pub async fn new_for_provider(provider: &AcmeProvider) -> Result<Client, OpaqueError> {
        let https_client = EasyHttpWebClient::default().boxed();
        Self::new_with_https_client(provider.as_str(), https_client).await
    }

    /// Create a new acme [`Client`] for the given directory url and using the provided https client
    pub async fn new_with_https_client(
        directory_url: &str,
        https_client: AcmeHttpsClient,
    ) -> Result<Client, OpaqueError> {
        let directory = https_client
            .get(directory_url)
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
        let https_client = EasyHttpWebClient::default().boxed();
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

        println!("response: {:?}", response);

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
    pub fn state(&self) -> &server::Account {
        &self.inner
    }

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
    pub fn state(&self) -> &server::Order {
        &self.inner
    }

    pub fn account(&self) -> &'a Account<'a> {
        self.account
    }

    pub async fn refresh(&mut self) -> Result<&server::Order, OpaqueError> {
        let response = self
            .account
            .post::<server::Order>(&self.url, None::<&Empty>)
            .await?;
        self.inner = response.into_body().context("order info")?;
        Ok(&self.inner)
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
    ) -> Result<&server::Order, OpaqueError> {
        timeout(timeout_duration, async {
            loop {
                self.refresh().await.unwrap();
                if self.inner.status != server::OrderStatus::Pending {
                    break;
                }
                // TODO use retry header
                sleep(Duration::from_millis(1000)).await;
            }
        })
        .await
        .context("poll until complete")?;

        Ok(&self.inner)
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

// #[cfg(test)]
// mod tests {
//     use rama_http::Response;
//     use rama_http::service::web::Router;
//     use rama_http::service::web::response::Html;
//     use std::sync::Arc;
//     use std::sync::atomic::AtomicU64;

//     use super::*;

//     use rama_core::layer::MapErrLayer;
//     use rama_http::service::web::response::Json;

//     const HOST: &str = "https://example.com";
//     const DIRECTORY_PATH: &str = "/directory";
//     const NONCE_PATH: &str = "/nonce";
//     const NEW_ACCOUNT_PATH: &str = "/account";

//     fn with_host(path: &str) -> String {
//         format!("{}{}", HOST, path)
//     }

//     fn test_server() -> AcmeHttpsClient {
//         let nonce = Arc::new(AtomicU64::new(0));

//         struct NonceEndpoint {
//             nonce: Arc<AtomicU64>,
//         }

//         struct NonceProtectedService<S> {
//             nonce: Arc<AtomicU64>,
//             inner: S,
//         }

//         impl<State> Service<State, Request> for NonceEndpoint
//         where
//             State: Send + Sync + 'static,
//         {
//             type Error = Infallible;
//             type Response = Response;

//             async fn serve(
//                 &self,
//                 _ctx: Context<State>,
//                 _req: Request,
//             ) -> Result<Self::Response, Self::Error> {
//                 let nonce = self.nonce.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

//                 let resp = Response::builder()
//                     .header(REPLAY_NONCE_HEADER, nonce.clone())
//                     .body(rama_http::Body::empty())
//                     .unwrap();

//                 resp.header_str(REPLAY_NONCE_HEADER).unwrap();
//                 Ok(resp)
//             }
//         }

//         #[derive(Default, Clone, Debug, PartialEq, Eq)]
//         struct NonceValue(u64);

//         impl<State, S> Service<State, Request> for NonceProtectedService<S>
//         where
//             State: Send + Sync + 'static,
//             S: Service<State, Request, Response = Response, Error = Infallible>,
//         {
//             type Error = Infallible;
//             type Response = Response;

//             async fn serve(
//                 &self,
//                 mut ctx: Context<State>,
//                 req: Request,
//             ) -> Result<Self::Response, Self::Error> {
//                 let nonce = self.nonce.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
//                 ctx.insert(NonceValue(nonce));
//                 let mut resp = self.inner.serve(ctx, req).await?;

//                 let nonce = self.nonce.load(std::sync::atomic::Ordering::Acquire);
//                 resp.headers_mut().insert(REPLAY_NONCE_HEADER, nonce.into());
//                 println!("response: {:?}", resp);
//                 Ok(resp)
//             }
//         }

//         let nonce_endpoint = NonceEndpoint {
//             nonce: nonce.clone(),
//         };

//         let protected_router: Router<()> = Router::new();
//         // .post(NEW_ACCOUNT_PATH, async |ctx: Context<()>, req: Request| {
//         //     println!("body: {:?}", req.body());
//         //     Ok::<_, Infallible>(
//         //         Json(server::Account {
//         //             status: server::AccountStatus::Valid,
//         //             contact: None,
//         //             terms_of_service_agreed: None,
//         //             external_account_binding: None,
//         //             orders: String::new(),
//         //         })
//         //         .into_response(),
//         //     )
//         // });

//         let protected_router = NonceProtectedService {
//             inner: protected_router,
//             nonce: nonce.clone(),
//         };

//         let router: Router<()> = Router::new()
//             .get("/", Html("Very basic acme server".to_owned()))
//             .get(
//                 DIRECTORY_PATH,
//                 Json(server::Directory {
//                     new_nonce: with_host(NONCE_PATH),
//                     key_change: String::new(),
//                     new_account: with_host(NEW_ACCOUNT_PATH),
//                     new_authz: None,
//                     new_order: String::new(),
//                     revoke_cert: String::new(),
//                     meta: None,
//                 }),
//             )
//             .head(NONCE_PATH, nonce_endpoint)
//             .sub("", protected_router);

//         (MapErrLayer::new(|_err| OpaqueError::from_display("something went wrong")))
//             .into_layer(router)
//             .boxed()
//     }

//     #[tokio::test]
//     async fn local_test() {
//         let local_client = test_server();
//         let mut test_nonce: u64 = 0;

//         let acme_client = Client::new_with_https_client(
//             format!("https://example.com{}", DIRECTORY_PATH).as_str(),
//             local_client,
//         )
//         .await
//         .unwrap();

//         // Should fetch a nonce from server
//         let nonce = acme_client.nonce().await.unwrap();
//         assert_eq!(nonce, test_nonce.to_string());

//         *acme_client.nonce.lock() = Some(test_nonce.to_string());
//         let nonce = acme_client.nonce().await.unwrap();
//         assert_eq!(nonce, test_nonce.to_string());

//         let account = acme_client
//             .create_account(CreateAccountOptions {
//                 terms_of_service_agreed: Some(true),
//                 contact: None,
//                 external_account_binding: None,
//                 only_return_existing: None,
//             })
//             .await
//             .unwrap();
//     }
// }
