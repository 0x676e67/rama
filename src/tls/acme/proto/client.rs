use super::{common::Identifier, server::Challenge};
use aws_lc_rs::{
    digest::{Digest, SHA256, digest},
    error::{KeyRejected, Unspecified},
    pkcs8,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    signature::{KeyPair, Signature},
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
/// Options used to create a new account, or request an identifier for an existing account, defined in [rfc8555 section 7.3]
///
/// [rfc8555 section 7.3]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.3
pub struct CreateAccountOptions {
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: Option<bool>,
    pub only_return_existing: Option<bool>,
    /// TODO support binding external accounts to acme account
    pub external_account_binding: Option<()>,
}

#[derive(Default, Debug, Serialize)]
/// List of [`Identifier`] for which we want to issue certificate(s), defined in [rfc8555 section 7.4]
///
/// [rfc8555 section 7.4]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.4
pub struct NewOrderPayload {
    /// Identifiers for which we want to issue certificate(s)
    pub identifiers: Vec<Identifier>,
    /// Requested value of not_before field in certificate
    pub not_before: Option<String>,
    /// Requested value of not_after field in certificate
    pub not_after: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
/// [`KeyAuthorization`] concatenates the token for a challenge with key fingerprint, defined in [rfc8555 section 8.1]
///
/// [rfc8555 section 8.1]: https://datatracker.ietf.org/doc/html/rfc8555/#section-8.1
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    /// Create [`KeyAuthorization`] for the given challenge and key
    pub(crate) fn new(challenge: &Challenge, key: &Key) -> Self {
        Self(format!("{}.{}", challenge.token, &key.thumb))
    }

    /// Encode [`KeyAuthorization`] for use in Http challenge
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encode [`KeyAuthorization`] for use in tls alpn challenge
    pub fn digest(&self) -> impl AsRef<[u8]> {
        digest(&SHA256, self.0.as_bytes())
    }

    /// Encode [`KeyAuthorization`] for use in dns challenge
    pub fn dns_value(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.digest())
    }
}

// TODO move common crypto logic such as JWK to rama-crypto and work it more out there

#[derive(Debug, Serialize)]
/// ProtectedHeader is the first part of the JWS that contains
/// all the metadata that is needed to guarantee the integrity and
/// authenticy of this request
pub(crate) struct ProtectedHeader<'a> {
    /// Algorithm that was used to sign the JWS
    pub(crate) alg: SigningAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Previous nonce that was given by the server to use
    pub(crate) nonce: Option<&'a str>,
    /// Url of the acme endpoint for which we are making a request
    pub(crate) url: &'a str,
    #[serde(flatten)]
    /// JWK or KeyId which is used to identify this request
    pub(crate) key: ProtectedHeaderKey<'a>,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
/// Algorithm that was used to sign
pub(crate) enum SigningAlgorithm {
    ES256,
    /// TODO support his one
    _EdDSA,
}

#[derive(Debug, Serialize)]
/// [`ProtectedHeaderKey`] send as key for [`ProtectedHeader`]
///
/// `JWK` is used for the first request to create an account, once we
/// have an account we use the `KeyID` instead
pub(crate) enum ProtectedHeaderKey<'a> {
    #[serde(rename = "jwk")]
    JWK(Jwk),
    #[serde(rename = "kid")]
    KeyID(&'a str),
}

#[derive(Debug, Serialize)]
/// [`Jwk`] or JSON Web Key used to create a new account
///
/// This key contains the public correspending to our
/// private key which will be using to sign requests
pub(crate) struct Jwk {
    alg: SigningAlgorithm,
    crv: &'static str,
    kty: &'static str,
    r#use: &'static str,
    x: String,
    y: String,
}

#[derive(Debug, Serialize)]
/// [`JwkThumb`] as defined in [`rfc7638`] is url safe identifier for a [`Jwk`]
///
/// [`rfc7638`]: https://datatracker.ietf.org/doc/html/rfc7638
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}

#[derive(Debug)]
/// Failures that can happen when using Jwk
pub(crate) enum JwkFailure {
    /// Serde failed to serialize our key
    JwkThumbSerializationFailed,
    /// Key was rejected for some explained reason
    KeyRejected(&'static str),
    /// Key was rejected for an unknown reason
    Unspecified,
}

impl std::fmt::Display for JwkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwkFailure::JwkThumbSerializationFailed => write!(f, "failed to serialize key"),
            JwkFailure::KeyRejected(error) => write!(f, "key rejected: {error}"),
            JwkFailure::Unspecified => write!(f, "key rejected for unknown reason"),
        }
    }
}

impl std::error::Error for JwkFailure {}

impl From<serde_json::Error> for JwkFailure {
    fn from(_value: serde_json::Error) -> Self {
        return Self::JwkThumbSerializationFailed;
    }
}

impl From<KeyRejected> for JwkFailure {
    fn from(value: KeyRejected) -> Self {
        return Self::KeyRejected(value.description_());
    }
}

impl From<Unspecified> for JwkFailure {
    fn from(_value: Unspecified) -> Self {
        return Self::Unspecified;
    }
}

impl Jwk {
    fn new(key: &EcdsaKeyPair) -> Self {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: SigningAlgorithm::ES256,
            crv: "P-256",
            kty: "EC",
            r#use: "sig",
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
        }
    }

    // rfc7638
    fn thumb_sha256(&self) -> Result<Digest, JwkFailure> {
        Ok(digest(
            &SHA256,
            &serde_json::to_vec(&JwkThumb {
                crv: self.crv,
                kty: self.kty,
                x: &self.x,
                y: &self.y,
            })?,
        ))
    }
}

/// [`Key`] which is used to identify and authenticate our requests
pub(crate) struct Key {
    rng: SystemRandom,
    pub(crate) signing_algorithm: SigningAlgorithm,
    inner: EcdsaKeyPair,
    pub(super) thumb: String,
}

impl Key {
    /// Create a new [`Key`] from the given pkcs8 der key and the given rng
    ///
    /// WARNING: right now we only support an ECDSA key pair
    pub(crate) fn new(pkcs8_der: &[u8], rng: SystemRandom) -> Result<Self, JwkFailure> {
        // TODO support other algorithms
        let inner = Self::ecdsa_key_pair_from_pkcs8(pkcs8_der, &rng)?;
        let thumb_sha256 = Jwk::new(&inner).thumb_sha256()?;
        let thumb = BASE64_URL_SAFE_NO_PAD.encode(thumb_sha256);
        Ok(Self {
            rng,
            signing_algorithm: SigningAlgorithm::ES256,
            inner,
            thumb,
        })
    }

    /// Create a new [`Key`] from the given pkcs8 der key containing an ECDSA key pair
    fn ecdsa_key_pair_from_pkcs8(
        pkcs8: &[u8],
        _: &SystemRandom,
    ) -> Result<EcdsaKeyPair, JwkFailure> {
        Ok(EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
        )?)
    }

    /// Generate a new [`Key`] from a newly generated [`EcdsaKeyPair`]
    pub(crate) fn generate() -> Result<(Self, pkcs8::Document), JwkFailure> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        Self::new(pkcs8.as_ref(), rng).map(|key| (key, pkcs8))
    }

    #[allow(dead_code)]
    /// Generate a new [`Key`] from the given pkcs8 der
    ///
    /// WARNING: right now we only support an ECDSA key pair
    pub(crate) fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, JwkFailure> {
        Self::new(pkcs8_der, SystemRandom::new())
    }
}

/// [`Signer`] implements all methods which are needed to sign our JWS requests
pub(crate) trait Signer {
    type Signature: AsRef<[u8]>;

    fn protected_header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> ProtectedHeader<'n>;

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError>;
}

fn encode_base64_url(data: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(data)?))
}

impl Signer for Key {
    type Signature = Signature;

    fn protected_header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> ProtectedHeader<'n> {
        ProtectedHeader {
            alg: self.signing_algorithm,
            key: ProtectedHeaderKey::from_key(&self.inner),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError> {
        Ok(self.inner.sign(&self.rng, payload)?)
    }
}

impl<'a> ProtectedHeaderKey<'a> {
    /// Create a [`ProtectedHeaderKey`] with a JWK encoded [`EcdsaKeyPair`]
    pub(crate) fn from_key(key: &EcdsaKeyPair) -> ProtectedHeaderKey<'static> {
        ProtectedHeaderKey::JWK(Jwk::new(key))
    }
}

#[derive(Clone, Debug, Serialize)]
/// [`Jws`] combines [`ProtectedHeader`], payload, and signature into one
pub(crate) struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

impl Jws {
    pub(crate) fn new(
        payload: Option<&impl Serialize>,
        protected: &ProtectedHeader<'_>,
        signer: &impl Signer,
    ) -> Result<Self, OpaqueError> {
        let protected = encode_base64_url(protected).context("encode base64 protected header")?;
        let payload = match payload {
            Some(data) => encode_base64_url(&data).context("encode base64 protected payload")?,
            None => String::new(),
        };

        let combined = format!("{protected}.{payload}");
        let signature = signer
            .sign(combined.as_bytes())
            .map_err(|err| OpaqueError::from_boxed(err))
            .context("create signature over protected payload")?;
        Ok(Self {
            protected,
            payload,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    fn decode_base64_url<T>(data: &str) -> T
    where
        T: DeserializeOwned,
    {
        let sl = BASE64_URL_SAFE_NO_PAD.decode(data).unwrap();
        serde_json::from_slice(sl.as_slice()).unwrap()
    }

    #[test]
    fn can_generate_and_reuse_keys() {
        let (generated_key, pkcs8_document) = Key::generate().unwrap();
        let recreated_key = Key::from_pkcs8_der(pkcs8_document.as_ref()).unwrap();
        assert_eq!(generated_key.thumb, recreated_key.thumb)
    }

    #[test]
    fn can_create_jws() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let payload = String::from("test_payload");
        let protected_header = key.protected_header(Some(nonce), url);
        let jose_json = Jws::new(Some(&payload), &protected_header, &key).unwrap();

        let decoded_payload = decode_base64_url::<String>(jose_json.payload.as_str());
        assert_eq!(decoded_payload, payload);
    }
}
