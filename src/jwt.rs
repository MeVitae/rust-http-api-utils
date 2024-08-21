use std::borrow::Cow;
use std::future::Future;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use biscuit::jwk::JWKSet;
use biscuit::jws;
use biscuit::{ClaimsSet, JWT};
use futures::future;
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
/// - `S` is the type of the [`KeySetSource`] to load the valid signing keys from. This must be
///   managed as state by rocket.
/// - `C` is the type of the [`JwtPayloadVerifier`] to validate the JWT payload with. This must be
///   managed as state by rocket.
/// - `U` is the type of the [`TagSource`] which can validate and return a tag for the token. For
///   valdation of the payload only, you should use `C: JwtPayloadVerifier` instead. This must be
///   managed as state by rocket. It defaults to [`EmptyTagSource`], which tags all tokens with
///   `()`.
/// - `T` is the type of the private token claims (the payload), and
/// - `H` is the type of the private token headers.
///
/// The verification flow is:
///
/// 1. Find the JWT from the `Authorization: Bearer <token>` HTTP header.
/// 2. Verify this token using the [`JWKSet`] from the `S: KeySetSource` state.
/// 3. Verify the token payload using the `C: JwtPayloadVerifier<T>` state.
/// 4. Attempt to generate a tag using the `U: TagSource<T, H>` state. If this returns `None`, the
///    token is rejected. If `Some`, that value becomes the token's `tag`.
pub struct VerifiedToken<
    S: KeySetSource,
    C: JwtPayloadVerifier<T> = DefaultJwtPayloadVerifier,
    U: TagSource<T, H> = EmptyTagSource,
    T: for<'de> Deserialize<'de> + Serialize = (),
    H: for<'de> Deserialize<'de> + Serialize = (),
> {
    pub jwt: JWT<T, H>,
    tag: U::Tag,

    /// A field that exists to prevent creation of a `VerifiedToken` outside of our control.
    ///
    /// We don't actually need this, since we also have the phantomdata, however we'll leave it
    /// here to express the intent of having it!
    _must_be_verified: (),

    phantom_tag_source: PhantomData<U>,
    phantom_source: PhantomData<S>,
    phantom_checker: PhantomData<C>,
}

impl<'r, S, U, C, T, H> VerifiedToken<S, C, U, T, H>
where
    S: KeySetSource,
    C: JwtPayloadVerifier<T>,
    U: TagSource<T, H>,
    T: for<'de> Deserialize<'de> + Serialize + Send,
    H: for<'de> Deserialize<'de> + Serialize + Send,
{
    pub fn tag(&self) -> &U::Tag {
        &self.tag
    }
}

#[rocket::async_trait]
impl<'r, S, U, C, T, H> FromRequest<'r> for VerifiedToken<S, C, U, T, H>
where
    S: KeySetSource,
    C: JwtPayloadVerifier<T>,
    U: TagSource<T, H>,
    T: for<'de> Deserialize<'de> + Serialize + Send,
    H: for<'de> Deserialize<'de> + Serialize + Send,
{
    type Error = ();

    async fn from_request(
        req: &'r Request<'_>,
    ) -> request::Outcome<VerifiedToken<S, C, U, T, H>, Self::Error> {
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
                    .filter_map(|token| {
                        token
                            .decode_with_jwks(
                                $key_set,
                                Some(biscuit::jwa::SignatureAlgorithm::RS256),
                            )
                            .ok()
                    })
                    // We only need to find the first token that is succesfully verified.
                    .next()
            };
        }

        let signed_token = loop {
            match get_verified_jwt!(key_set.deref()) {
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
        if checker.check(payload) {
            // Then load the tag source and attempt to get the tag.
            let tag_source = req.rocket().state::<U>().unwrap();
            if let Some(tag) = tag_source.tag(signed_token.header().unwrap(), payload) {
                return request::Outcome::Success(VerifiedToken {
                    tag,
                    jwt: signed_token,
                    _must_be_verified: (),
                    phantom_tag_source: PhantomData,
                    phantom_source: PhantomData,
                    phantom_checker: PhantomData,
                });
            }
        }
        request::Outcome::Error((rocket::http::Status::Unauthorized, ()))
    }
}

/// Generate tags for verified tokens from their header and payload.
pub trait TagSource<T, H>: Send + Sync + 'static {
    type Tag;

    /// Given the header and claims of an already verified token, return the tag.
    ///
    /// If this returns `None`, the token is rejected. Otherwise, the return value is used as the
    /// [`VerifiedToken`]s `tag`.
    fn tag(&self, jwt_header: &jws::Header<H>, jwt_claims: &ClaimsSet<T>) -> Option<Self::Tag>;
}

/// A tag source which always generates `()` as the tag.
pub struct EmptyTagSource;

impl<T, H> TagSource<T, H> for EmptyTagSource {
    type Tag = ();

    fn tag(&self, _jwt_header: &jws::Header<H>, _jwt_claims: &ClaimsSet<T>) -> Option<()> {
        Some(())
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

/// A key set source, with only a `get_keys` method.
///
/// This can be wrapped up using [`CachedKeySetSource`] to implement [`KeySetSource`].
#[rocket::async_trait]
pub trait SimpleKeySetSource: Send + Sync + 'static {
    async fn get_keys(&self) -> JWKSet<()>;
}

#[rocket::async_trait]
impl<T: SimpleKeySetSource> SimpleKeySetSource for Vec<T> {
    async fn get_keys(&self) -> JWKSet<()> {
        JWKSet {
            keys: future::join_all(self.iter().map(SimpleKeySetSource::get_keys))
                .await
                .into_iter()
                .flat_map(|jwks| jwks.keys)
                .collect(),
        }
    }
}

/// A source of JSON Web Keys. Used for validating JWTs when generating a [`VerifiedToken`].
///
/// This can be easily implemented by first implementing [`SimpleKeySetSource`], then wrapping that
/// type in [`CachedKeySetSource`].
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

/// Wrap a [`SimpleKeySetSource`] to implement [`KeySetSource`].
pub struct CachedKeySetSource<T: SimpleKeySetSource> {
    pub source: T,
    cache: Cache<JWKSet<()>>,
}

impl<T: SimpleKeySetSource> CachedKeySetSource<T> {
    pub fn new(source: T) -> CachedKeySetSource<T> {
        CachedKeySetSource {
            source,
            cache: Cache::new(JWKSet { keys: Vec::new() }),
        }
    }
}

#[rocket::async_trait]
impl<T: SimpleKeySetSource> KeySetSource for CachedKeySetSource<T> {
    type Ref = Arc<JWKSet<()>>;

    fn get_key_set(&self) -> Self::Ref {
        self.cache.get_value()
    }

    async fn refresh_key_set(&self) -> Option<Self::Ref> {
        self.cache
            .update(Duration::from_secs(15), || self.source.get_keys())
            .await
    }
}

/// Keys sourced from a URL pointing to a JSON Web Keys structure.
///
/// Wrap this with [`CachedKeySetSource`] to implement [`KeySetSource`].
pub struct HttpKeySetSource<U: UrlSource = FixedUrl> {
    pub url: U,
}

impl<U: UrlSource> HttpKeySetSource<U> {
    pub fn new(url: U) -> HttpKeySetSource<U> {
        HttpKeySetSource { url }
    }
}

impl HttpKeySetSource<OidcJwksUri<FixedUrl>> {
    pub fn new_b2c(tenant: &str, policy: &str) -> HttpKeySetSource<OidcJwksUri<FixedUrl>> {
        HttpKeySetSource::new(OidcJwksUri::new_b2c(tenant, policy))
    }
}

#[rocket::async_trait]
impl<U: UrlSource> SimpleKeySetSource for HttpKeySetSource<U> {
    async fn get_keys(&self) -> JWKSet<()> {
        let url = self.url.update().await;
        reqwest::get(url.as_ref())
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
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
        let now = Instant::now();
        Cache {
            cached: RwLock::new(Cached {
                value: Arc::new(initial_value),
                time: now
                    .checked_sub(Duration::from_secs(60 * 60 * 24 * 365))
                    .or_else(|| now.checked_sub(Duration::from_secs(60 * 60 * 24 * 30)))
                    .or_else(|| now.checked_sub(Duration::from_secs(60 * 60 * 24 * 7)))
                    .or_else(|| now.checked_sub(Duration::from_secs(60 * 60 * 24)))
                    .or_else(|| now.checked_sub(Duration::from_secs(60 * 60)))
                    .or_else(|| now.checked_sub(Duration::from_secs(60)))
                    .or_else(|| now.checked_sub(Duration::from_secs(30)))
                    .unwrap(),
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
