use uuid::Uuid;
use rocket::serde::json::Json;
use rocket::serde::json::{Value, json};
use rocket::serde::{Serialize, Deserialize};
use rocket::http::Status;
use rocket::response::status::{BadRequest, NoContent};
use rocket::request::{self, Outcome, Request, FromRequest};
use jwt::{Header, Token, VerifyWithKey, token as jwt_token};
use std::borrow::Cow;
use std::collections::BTreeMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub mod error;
pub mod client;
pub mod grant_types;
pub mod forms;
mod server;

use error::Error;
use client::{Client, Clients};
use forms::TokenRequestForm;


#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct RegisterRequest<'r> {
	name: Cow<'r, str>,
	description: Cow<'r, str>,
}

struct ClientJwt (Token<Header, BTreeMap<String, String>, jwt_token::Verified>);

impl ClientJwt {
	fn parse(token: &str) -> Result<Self, Error> {
		let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
		let token: Token<Header, BTreeMap<String, String>, _> = token.verify_with_key(&key)?;
		Ok(Self(token))
	}

	fn claims(&self) -> &BTreeMap<String, String> {
		self.0.claims()
	}

	fn authorize_for(&self, id: &Uuid) -> Result<(), Error> {
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

		let auth_header = auth_header.split(" ").collect::<Vec<&str>>();
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


#[post("/token", data = "<token_request>")]
async fn token(token_request: TokenRequestForm<'_>, clients: Clients<'_>) -> Result<Value, Status> {
	let oauth_server = server::Server::new();
	let token = oauth_server.token(token_request, clients).await.map_err(|e: Error| e.into())?;
	Ok(json!(token))
}

#[post("/clients", data = "<client_request>")]
async fn register(client_request: Json<RegisterRequest<'_>>, clients: Clients<'_>) -> Result<Json<Client>, BadRequest<Value>> {
	let client = clients.register(client_request.name.to_string(), client_request.description.to_string()).await
		.map_err(|e| {
			match e {
				Error::InvalidClientName => BadRequest(Some(json!("name already taken?"))),
				_ => BadRequest(Some(json!("unknown error"))),
			}
		})?;
	Ok(Json(client))
}

#[get("/clients/<id>")]
async fn get_client(id: Uuid, clients: Clients<'_>, auth: ClientJwt) -> Result<Json<Client>, Status> {
	auth.authorize_for(&id).map_err(|e:Error| e.into())?;
	clients.get(&id).await.map_or(Err(Status::NotFound), |client| Ok(Json(client)))
}


#[delete("/clients/<id>")]
async fn delete_client(id: Uuid, clients: Clients<'_>, auth: ClientJwt) -> Result<NoContent, Status> {
	auth.authorize_for(&id).map_err(|e|<Error as Into<Status>>::into(e))?;
	clients.delete(id).await;
	Ok(NoContent)
}

pub async fn stage() -> rocket::fairing::AdHoc {
	let client_storage = client::init_state().await;
	rocket::fairing::AdHoc::on_ignite("oauth", |rocket| async {
		rocket.mount("/oauth", routes![token, register, get_client, delete_client])
			.manage(client_storage)
    })
}