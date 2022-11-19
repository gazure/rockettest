use rocket::serde::uuid::Uuid;
use rocket::tokio::sync::Mutex;
use std::collections::HashMap;
use rocket::State;
use rocket::serde::json::Json;
use rocket::serde::json::{Value, json};
use rocket::serde::{Serialize, Deserialize};
use rocket::form::{Form};
use rocket::response::status::{Unauthorized, BadRequest, NoContent};
use std::borrow::Cow;

mod client;
use client::Client;


type ClientsMap = Mutex<HashMap<Uuid, client::Client>>;
type Clients<'r> = &'r State<ClientsMap>;

#[allow(dead_code)]
#[derive(Debug, FromForm)]
struct TokenRequest<'r> {
	client_id: Uuid,
	client_secret: String,
	grant_type: &'r str,
	scope: &'r str,
	user_id: Option<&'r str>,
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct RegisterRequest<'r> {
	name: Cow<'r, str>,
	description: Cow<'r, str>,
}

#[post("/token", data = "<token_request>")]
fn token(token_request: Option<Form<TokenRequest<'_>>>) -> Result<Value, Unauthorized<Value>>  {
	println!("{:?}", token_request);	
	match token_request {
		Some(token_request) => Ok(json!({
			"client_id": token_request.client_id,
			"route": "/token"
		})),
		None => Err(Unauthorized(Some(json!({
			"status": "unauthorized",
			"code": 401,
		}))))
	}
}

#[post("/clients", data = "<client_request>")]
async fn register(client_request: Json<RegisterRequest<'_>>, clients: Clients<'_>) -> Result <Json<Client>, BadRequest<Value>> {
	let client = client::Client::new(client_request.name.to_string(), client_request.description.to_string());

	let mut clients = clients.lock().await;
	clients.insert(client.client_id.clone(), client.clone());

	Ok(Json(client))
}

#[get("/clients/<id>")]
async fn get_client(id: Uuid, clients: Clients<'_>) -> Option<Json<Client>> {
	let clients = clients.lock().await;
	let client = clients.get(&id)?;
	Some(Json(client.clone()))
}


#[delete("/clients/<id>")]
async fn delete_client(id: Uuid, clients: Clients<'_>) -> NoContent {
	let mut clients = clients.lock().await;

	if clients.contains_key(&id) {
		clients.remove(&id);
	}

	NoContent
}

#[catch(404)]
fn not_found() -> Value {
    json!({
        "status": 404,
        "reason": "not found"
    })
}

pub fn stage() -> rocket::fairing::AdHoc {
	rocket::fairing::AdHoc::on_ignite("oauth", |rocket| async {
		rocket.mount("/oauth", routes![token, register, get_client, delete_client])
			.register("/oauth", catchers![not_found])
			.manage(ClientsMap::new(HashMap::new()))
    })
}