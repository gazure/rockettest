use rocket::serde::uuid::Uuid;
use rocket::serde::{Serialize, Deserialize};
use rocket::tokio::sync::Mutex;
use std::collections::HashMap;
use rand::Rng;
use hex::ToHex;
use rocket::State;

use crate::oauth::error::Error;

type ClientsMap = Mutex<HashMap<Uuid, Client>>;
pub type Clients<'r> = &'r State<ClientStorage>;

pub struct ClientStorage {
	pub map: ClientsMap,
}

impl ClientStorage {

	pub fn new() -> Self{
		Self {
			map: ClientsMap::new(HashMap::new()),
		}
	}

	pub async fn get(&self, client_id: &Uuid) -> Option<Client> {
		let clients = self.map.lock().await;
		Some(clients.get(&client_id)?.clone())
	}

	pub async fn update(&self, client: Client) {
		let mut clients = self.map.lock().await;
		clients.entry(client.id.clone()).and_modify(|c| *c = client);
	}

	pub async fn register(&self, name: String, description: String) -> Result<Client, Error> {
		if name == String::from("Grant Azure") {
			return Err(Error::InvalidClientName);
		}

		let mut clients = self.map.lock().await;
		let client = Client::new(name, description);
		clients.insert(client.id.clone(), client.clone());
		Ok(client)
	}

	pub async fn delete(&self, id: Uuid) {
		self.map.lock().await.remove(&id);
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Client {	
	pub id: Uuid,
	secret: String,
	pub name: String,
	pub description: String,
	#[serde(skip)]
	recent_login_count: u32,
}

impl Client {
	pub fn new(name: String, description: String) -> Self {
		Self {
			id: Uuid::new_v4(),
			secret: Self::generate_secret(),
			name: name,
			description: description,
			recent_login_count: 0,
		}
	}

	// return true if not rate-limited (I hate naming)
	fn assert_rate_limit(&self) -> bool {
		self.recent_login_count < 5
	}

	pub fn validate_secret(&self, secret: &String) -> Result<(), Error> {
		match (self.assert_rate_limit(), self.match_secret(secret)) {
			(true, true) => Ok(()),
			(false, true) => Err(Error::RateLimited),
			(_, false) => Err(Error::InvalidSecret),
		}
	}

	fn match_secret(&self, secret: &String) -> bool{
		*secret == self.secret
	}

	fn generate_secret() -> String {
		let secret = rand::thread_rng().gen::<[u8; 32]>();
		secret.encode_hex::<String>()	
	}

	pub fn increment_login_count(&mut self) {
		self.recent_login_count += 1;
	}
}

pub fn init_state() -> ClientStorage {
	ClientStorage::new()
}