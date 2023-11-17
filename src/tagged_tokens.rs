use std::collections::HashMap;
use std::io;
use std::path::Path;

use rocket::{
    self, http,
    request::{self, FromRequest, Outcome, Request},
    State,
};

use serde::Deserialize;

/// A map of, fixed, allowable auth tokens, to their tags.
///
/// TODO: Replace this hashes of allowed tokens, and probably add some mechanism of time limiting
/// tokens.
pub struct TaggedTokens<T: Send + Sync> {
    tokens: HashMap<String, T>,
}

error_enum! {
    pub enum TaggedTokenLoadError {
        "error reading tagged tokens file" IO(io::Error),
        "error parsing tagged tokens file" Parse(serde_json::Error),
    }
}

impl<T: Send + Sync + for<'de> Deserialize<'de>> TaggedTokens<T> {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<TaggedTokens<T>, TaggedTokenLoadError> {
        Ok(TaggedTokens {
            tokens: serde_json::from_reader(std::fs::File::open(path)?)?,
        })
    }
}

impl<T: Send + Sync> TaggedTokens<T> {
    /// Attempt to verify a provided token, returning `Some(TaggedTokenAuth<T>)` if and only if the
    /// `provided_token` was valid.
    fn verify<'a>(&'a self, provided_token: &str) -> Option<TaggedTokenAuth<'a, T>> {
        self.tokens
            .get(provided_token)
            .map(|tag| TaggedTokenAuth { tag })
    }
}

/// A value generated only by `TaggedTokens::verify` - if you have a value of this type, a token
/// has been verified at some point!
///
/// It implements [`FromRequest`] so can be used as a request guard.
pub struct TaggedTokenAuth<'a, T> {
    tag: &'a T,
}

impl<'a, T: Send + Sync> TaggedTokenAuth<'a, T> {
    /// Return the tag of the token used to generate this `TaggedTokenAuth`.
    pub fn tag(&self) -> &'a T {
        self.tag
    }
}

#[rocket::async_trait]
impl<'r, T: Send + Sync + 'static> FromRequest<'r> for TaggedTokenAuth<'r, T> {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let tokens = rocket::outcome::try_outcome!(req.guard::<&State<TaggedTokens<T>>>().await,);
        match req
            .headers()
            .get_one("x-mevitae-token")
            .and_then(|token| tokens.verify(token))
        {
            Some(token) => Outcome::Success(token),
            None => Outcome::Error((http::Status::Forbidden, ())),
        }
    }
}
