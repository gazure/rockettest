use uuid::Uuid;
use rocket::serde::json::Json;
use rocket::serde::json::{Value, json};
use rocket::serde::{Serialize, Deserialize};
use rocket::http::Status;
use rocket::response::status::{BadRequest, NoContent};
use std::borrow::Cow;


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

#[post("/token", data = "<token_request>")]
async fn token(token_request: TokenRequestForm<'_>, clients: Clients<'_>) -> Result<Value, Status> {

	let oauth_server = server::Server::new();
	let token = oauth_server.token(token_request, clients).await.map_err(|e| {
		match e {
			Error::InvalidSecret => Status::Unauthorized,
			Error::InvalidClient => Status::Unauthorized,
			Error::RateLimited => Status::Forbidden,
			Error::InvalidGrantType => Status::BadRequest,
			Error::InvalidToken => Status::InternalServerError,
			Error::InvalidClientName => Status::BadRequest,
		}
	})?;
	Ok(json!(token))
}

#[post("/clients", data = "<client_request>")]
async fn register(client_request: Json<RegisterRequest<'_>>, clients: Clients<'_>) -> Result<Json<Client>, BadRequest<Value>> {
	let client = clients.register(client_request.name.to_string(), client_request.description.to_string())
		.await
		.map_err(|_| BadRequest(Some(json!("name already taken?"))))?;
	Ok(Json(client))
}

#[get("/clients/<id>")]
async fn get_client(id: Uuid, clients: Clients<'_>) -> Option<Json<Client>> {
	Some(Json(clients.get(&id).await?))
}


#[delete("/clients/<id>")]
async fn delete_client(id: Uuid, clients: Clients<'_>) -> NoContent {
	clients.delete(id).await;
	NoContent
}


#[catch(400)]
fn bad_request() -> Value {
	json!({
		"status": 400,
		"reason": "bad request"
	})
}

#[catch(404)]
fn not_found() -> Value {
    json!({
        "status": 404,
        "reason": "not found"
    })
}

#[catch(401)]
fn unauthorized() -> Value {
	json!({
		"status": 401,
		"reason": "unauthorized"
	})
}

#[catch(403)]
fn forbidden() -> Value {
	json!({
		"status": 403,
		"reason": "forbidden"
	})
}

#[catch(500)]
fn internal_server_error() -> Value {
	json!({
		"status": 500,
		"reason": "internal server error"
	})
}

pub fn stage() -> rocket::fairing::AdHoc {
	rocket::fairing::AdHoc::on_ignite("oauth", |rocket| async {
		rocket.mount("/oauth", routes![token, register, get_client, delete_client])
			.register("/oauth", catchers![not_found, unauthorized, forbidden, bad_request, internal_server_error])
			.manage(client::init_state())
    })
}