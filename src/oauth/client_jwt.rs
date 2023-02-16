use uuid::Uuid;
use rocket::request::{self, Outcome, Request, FromRequest};
use std::collections::BTreeMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use jwt::{Header, Token, VerifyWithKey, token as jwt_token};
use rocket::http::Status;

use crate::oauth::error::Error;


pub struct ClientJwt (Token<Header, BTreeMap<String, String>, jwt_token::Verified>);

impl ClientJwt {
	fn parse(token: &str) -> Result<Self, Error> {
		let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
		let token: Token<Header, BTreeMap<String, String>, _> = token.verify_with_key(&key)?;
		Ok(Self(token))
	}

	fn claims(&self) -> &BTreeMap<String, String> {
		self.0.claims()
	}

	pub fn authorize_for(&self, id: &Uuid) -> Result<(), Error> {
		match self.claims().get("client_id") {
			Some(client_id) => match *client_id == id.to_string() {
				true => Ok(()),
				false => Err(Error::InvalidResourceAccess),
			},
			None => Err(Error::InvalidResourceAccess),
		}
	}
}


// Rocket request guard for validating jwts
#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientJwt {
	type Error = Error;
	
	// I'm pretty sure I can just set Self::Error to (), seems like Rocket Outcomes just rely on the
	// Status code to set 4xx or 5xx errors
	async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
		let auth_header = request.headers().get_one("Authorization");
		let auth_header = match auth_header {
			Some(header) => header,
			None => return Outcome::Failure((Status::Unauthorized, Error::InvalidAuthHeader)),
		};

		let auth_header = auth_header.split(' ').collect::<Vec<&str>>();
		if auth_header.len() != 2 {
			return Outcome::Failure((Status::Unauthorized, Error::InvalidAuthHeader));
		}

		let (auth_type, token) = (auth_header[0], auth_header[1]);
		if auth_type != "Bearer" {
			return Outcome::Failure((Status::Unauthorized, Error::InvalidAuthType));
		}

		match ClientJwt::parse(token) {
			Ok(jwt) => Outcome::Success(jwt),
			Err(_) => Outcome::Failure((Status::Unauthorized, Error::InvalidClient)),
		}
	}
}
