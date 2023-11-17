use std::io;
use std::ops::Deref;
use std::path::Path;

use rocket::{
    self, http,
    request::{self, FromRequest, Outcome, Request},
    State,
};

/// A list of, fixed, allowable auth tokens
///
/// TODO: Replace this hashes of allowed tokens, and probably add some mechanism of time limiting
/// tokens.
pub struct Tokens {
    keys: Vec<String>,
}

error_enum! {
    pub enum TokenLoadError {
        "error reading tokens file" IO(io::Error),
        "error parsing tokens file" Parse(serde_json::Error),
    }
}

impl Tokens {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Tokens, TokenLoadError> {
        Ok(Tokens {
            keys: serde_json::from_reader(std::fs::File::open(path)?)?,
        })
    }

    /// Attempt to verify a provided token, returning `Some(TokenAuth)` if and only if the
    /// `provided_token` was valid.
    fn verify(&self, provided_token: &str) -> Option<TokenAuth> {
        if self
            .keys
            .iter()
            .any(|token| token.deref() == provided_token)
        {
            Some(TokenAuth { nothing: () })
        } else {
            None
        }
    }
}

/// A value generated only by `Tokens::verify` - if you have a value of this type, a token has been
/// verified at some point!
///
/// It implements [`FromRequest`] so can be used as a request guard.
pub struct TokenAuth {
    #[allow(dead_code)]
    nothing: (),
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for TokenAuth {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let tokens = rocket::outcome::try_outcome!(req.guard::<&State<Tokens>>().await);
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
