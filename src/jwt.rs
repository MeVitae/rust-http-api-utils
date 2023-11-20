use std::borrow::Cow;
use std::future::Future;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use biscuit::jwk::JWKSet;
use biscuit::{ClaimsSet, JWT};
use rocket::{
    request::{self, FromRequest},
    Request,
};
use serde::{Deserialize, Serialize};

const BEARER_SPACE: &str = "Bearer ";

/// A verified JWT token. These can only be constructed through its implementation of
/// [`FromRequest`] and hence there must have been a corresponding request with a valid
/// Authorization header.
///
/// The generic parameters are:
/// - `S` the type of the `KeySetSource` to load the valid signing keys from. This must be managed
///   as state by rocket.
/// - `C` the type of the `JwtPayloadVerifier` to validate the JWT payload with. This must be
///   managed as state by rocket.
/// - `T` is the type of the private token claims, and
/// - `H` is the type of the private token headers.
pub struct VerifiedToken<
    S: KeySetSource,
    C: JwtPayloadVerifier<T> = DefaultJwtPayloadVerifier,
    T: for<'de> Deserialize<'de> + Serialize = (),
    H: for<'de> Deserialize<'de> + Serialize = (),
> {
    pub jwt: JWT<T, H>,

    /// A field that exists to prevent creation of a `VerifiedToken` outside of our control.
    _must_be_verified: (),

    phantom_source: PhantomData<S>,
    phantom_checker: PhantomData<C>,
}

#[rocket::async_trait]
impl<'r, S, C, T, H> FromRequest<'r> for VerifiedToken<S, C, T, H>
where
    S: KeySetSource,
    C: JwtPayloadVerifier<T>,
    T: for<'de> Deserialize<'de> + Serialize + Send,
    H: for<'de> Deserialize<'de> + Serialize + Send,
{
    type Error = ();

    async fn from_request(
        req: &'r Request<'_>,
    ) -> request::Outcome<VerifiedToken<S, C, T, H>, Self::Error> {
        // Load the key set:
        let key_set_source = req.rocket().state::<S>().unwrap();
        let mut key_set = key_set_source.get_key_set();
        let mut refreshed = false;

        // If the set is empty, there's no point checking the keys, just do a refresh!
        if key_set.keys.is_empty() {
            if let Some(new_set) = key_set_source.refresh_key_set().await {
                key_set = new_set;
            }
            // If it's still empty, then return now.
            if key_set.keys.is_empty() {
                return request::Outcome::Error((rocket::http::Status::Unauthorized, ()));
            }
            refreshed = true;
        }

        macro_rules! get_verified_jwt {
            ($key_set:expr) => {
                req.headers()
                    .get(http::header::AUTHORIZATION.as_str())
                    // The authorization header value must start with "Bearer ":
                    .filter_map(|auth| dbg!(auth.strip_prefix(BEARER_SPACE)))
                    // It must then succesfully be verified when decoded:
                    .map(JWT::new_encoded)
                    .filter_map(|token| token.decode_with_jwks($key_set, None).ok())
                    // We only need to find the first token that is succesfully verified.
                    .next()
            };
        }

        let signed_token = loop {
            match get_verified_jwt!(dbg!(key_set.deref())) {
                // If a JWT was verified, return it!
                Some(jwt) => break jwt,

                // Otherwise, if we've not yet refreshed, refresh once before giving up.
                None => {
                    if !refreshed {
                        if let Some(new_set) = key_set_source.refresh_key_set().await {
                            key_set = new_set;
                            refreshed = true;
                            continue;
                        }
                    }
                    return request::Outcome::Error((rocket::http::Status::Unauthorized, ()));
                }
            }
        };

        // Load the checker and check the key:
        let checker = req.rocket().state::<C>().unwrap();
        let payload = signed_token.payload().unwrap();
        if dbg!(checker.check(payload)) {
            request::Outcome::Success(VerifiedToken {
                jwt: signed_token,
                _must_be_verified: (),
                phantom_source: PhantomData,
                phantom_checker: PhantomData,
            })
        } else {
            request::Outcome::Error((rocket::http::Status::Unauthorized, ()))
        }
    }
}

/// A trait for verifying the payload of a JWT token.
pub trait JwtPayloadVerifier<T>: Send + Sync + 'static {
    fn check(&self, token_payload: &ClaimsSet<T>) -> bool;
}

/// A sensible implementation of `JwtPayloadVerifier`.
pub struct DefaultJwtPayloadVerifier {
    /// If `Some`, it asserts that the issuer is one of the values listed. If `None`, the issuer
    /// isn't checked.
    pub issuer: Option<Vec<String>>,

    /// If `Some`, it asserts that the subject is one of the values listed. If `None`, the subject
    /// isn't checked.
    pub subject: Option<Vec<String>>,

    /// Each scope listed MUST be in the audience of the token (hence, if the list is empty,
    /// nothing is checked).
    pub scopes: Vec<String>,
}

impl<T> JwtPayloadVerifier<T> for DefaultJwtPayloadVerifier {
    fn check(&self, token_payload: &ClaimsSet<T>) -> bool {
        let payload = dbg!(&token_payload.registered);

        match (&payload.issuer, &self.issuer) {
            (_, None) => (),
            (None, Some(_)) => return false,
            (Some(issuer), Some(valid_issuers)) if valid_issuers.contains(issuer) => (),
            (Some(_), Some(_)) => return false,
        }

        match (&payload.subject, &self.subject) {
            (_, None) => (),
            (None, Some(_)) => return false,
            (Some(subject), Some(valid_subjects)) if valid_subjects.contains(subject) => (),
            (Some(_), Some(_)) => return false,
        }

        match &payload.audience {
            // No audience is only ok if no scopes are specified.
            None if self.scopes.is_empty() => true,
            None => return false,

            // Otherwise, all the expected scopes must be listed.
            Some(scopes)
                if self
                    .scopes
                    .iter()
                    .all(|expected_scope| scopes.iter().any(|scope| scope == expected_scope)) =>
            {
                true
            }
            Some(_) => return false,
        }
    }
}

/// A source of JSON Web Keys. Used for validating JWTs when generating a [`VerifiedToken`].
#[rocket::async_trait]
pub trait KeySetSource: Send + Sync + 'static {
    type Ref: Deref<Target = JWKSet<()>> + Send + Sync;

    /// Return a known set of keys.
    ///
    /// If this is empty, or if it doesn't contain the requested key, it will trigger
    /// `refresh_key_set`.
    fn get_key_set(&self) -> Self::Ref;

    /// Refresh the key set. If new keys were loaded, the return value must be `Some`, with the new
    /// keys (all these keys will be checked, so it may also contain old keys). It must only return
    /// `None` if no new keys are loaded.
    async fn refresh_key_set(&self) -> Option<Self::Ref>;
}

/// Keys sourced from a URL pointing to a JSON Web Keys structure.
pub struct HttpKeySetSource<U: UrlSource = FixedUrl> {
    pub url: U,
    cache: Cache<JWKSet<()>>,
}

impl<U: UrlSource> HttpKeySetSource<U> {
    pub fn new(url: U) -> HttpKeySetSource<U> {
        HttpKeySetSource {
            url,
            cache: Cache::new(JWKSet { keys: Vec::new() }),
        }
    }
}

impl HttpKeySetSource<OidcJwksUri<FixedUrl>> {
    pub fn new_b2c(tenant: &str, policy: &str) -> HttpKeySetSource<OidcJwksUri<FixedUrl>> {
        HttpKeySetSource::new(OidcJwksUri::new_b2c(tenant, policy))
    }
}

#[rocket::async_trait]
impl<U: UrlSource> KeySetSource for HttpKeySetSource<U> {
    type Ref = Arc<JWKSet<()>>;

    fn get_key_set(&self) -> Self::Ref {
        self.cache.get_value()
    }

    async fn refresh_key_set(&self) -> Option<Self::Ref> {
        let refresh = || async {
            let url = self.url.update().await;
            reqwest::get(url.as_ref())
                .await
                .unwrap()
                .json()
                .await
                .unwrap()
        };
        self.cache.update(Duration::from_secs(15), refresh).await
    }
}

/// Source of a URL
#[rocket::async_trait]
pub trait UrlSource: Send + Sync + 'static {
    fn url<'a>(&'a self) -> Option<Cow<'a, str>>;

    async fn update<'a>(&'a self) -> Cow<'a, str>;
}

/// A fixed `UrlSource`.
pub struct FixedUrl {
    pub url: Cow<'static, str>,
}

impl From<&'static str> for FixedUrl {
    fn from(s: &'static str) -> FixedUrl {
        FixedUrl {
            url: Cow::Borrowed(s),
        }
    }
}

impl From<String> for FixedUrl {
    fn from(s: String) -> FixedUrl {
        FixedUrl { url: Cow::Owned(s) }
    }
}

impl From<Cow<'static, str>> for FixedUrl {
    fn from(s: Cow<'static, str>) -> FixedUrl {
        FixedUrl { url: s }
    }
}

#[rocket::async_trait]
impl UrlSource for FixedUrl {
    fn url<'a>(&'a self) -> Option<Cow<'a, str>> {
        Some(Cow::Borrowed(self.url.as_ref()))
    }

    async fn update<'a>(&'a self) -> Cow<'a, str> {
        Cow::Borrowed(self.url.as_ref())
    }
}

/// Fetch the URL for JSON web keys from OIDC Metadata URL.
pub struct OidcJwksUri<U: UrlSource> {
    pub oidc_configuration_url: U,
    cache: Cache<String>,
}

impl<U: UrlSource> OidcJwksUri<U> {
    pub fn new(oidc_configuration_url: U) -> OidcJwksUri<U> {
        OidcJwksUri {
            oidc_configuration_url,
            cache: Cache::new(String::new()),
        }
    }
}

impl OidcJwksUri<FixedUrl> {
    pub fn new_b2c(tenant: &str, policy: &str) -> OidcJwksUri<FixedUrl> {
        OidcJwksUri::new(FixedUrl {
            url: Cow::Owned(format!(
                "https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration",
            )),
        })
    }
}

#[derive(Deserialize)]
struct OidcJwksUriMetadata {
    jwks_uri: String,
}

#[rocket::async_trait]
impl<U: UrlSource> UrlSource for OidcJwksUri<U> {
    fn url<'a>(&'a self) -> Option<Cow<'a, str>> {
        let s = self.cache.get_value();
        if s.is_empty() {
            return None;
        }
        Some(Cow::Owned(s.deref().clone()))
    }

    async fn update<'a>(&'a self) -> Cow<'a, str> {
        let refresh = || async {
            let config_url = self.oidc_configuration_url.update().await;
            let config: OidcJwksUriMetadata = reqwest::get(config_url.as_ref())
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            config.jwks_uri
        };
        Cow::Owned(
            match self.cache.update(Duration::from_secs(15), refresh).await {
                Some(url) => url,
                None => self.cache.get_value(),
            }
            .deref()
            .to_owned(),
        )
    }
}

struct Cache<T> {
    cached: RwLock<Cached<T>>,
}

struct Cached<T> {
    value: Arc<T>,
    time: Instant,
}

impl<T> Cache<T> {
    fn new(initial_value: T) -> Cache<T> {
        Cache {
            cached: RwLock::new(Cached {
                value: Arc::new(initial_value),
                time: Instant::now(),
            }),
        }
    }

    fn get_value(&self) -> Arc<T> {
        self.cached.read().unwrap().value.clone()
    }

    fn get_time(&self) -> Instant {
        self.cached.read().unwrap().time
    }
}

impl<T: PartialEq> Cache<T> {
    async fn update<F: FnOnce() -> R, R: Future<Output = T>>(
        &self,
        min_time: Duration,
        update: F,
    ) -> Option<Arc<T>> {
        let last_update = self.get_time();
        let now = Instant::now();
        // Don't update if we updated <10s ago
        if now.duration_since(last_update) < min_time {
            return None;
        }

        let new_value = update().await;

        let mut cached = self.cached.write().unwrap();

        // Update the cache time, but don't replace a newer entry
        if now <= cached.time {
            return None;
        }
        cached.time = now;

        if new_value != *cached.value {
            // If the value has changed, update it and return the new value.
            cached.value = Arc::new(new_value);
            Some(cached.value.clone())
        } else {
            // Otherwise, it hasn't changed.
            None
        }
    }
}
