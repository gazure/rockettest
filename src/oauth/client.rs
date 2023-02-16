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
pub struct ClientStorage (ClientsMap);

impl ClientStorage {

	pub fn new() -> Self{
		Self (ClientsMap::new(HashMap::new()))
	}

	pub async fn get(&self, client_id: &Uuid) -> Option<Client> {
		let clients = self.0.lock().await;
		Some(clients.get(client_id)?.clone())
	}

	pub async fn update(&self, client: Client) {
		let mut clients = self.0.lock().await;
		clients.entry(client.id).and_modify(|c| *c = client);
	}

    #[allow(dead_code)] // used in unit tests
    pub async fn create(&self, client: Client) {
        let mut clients = self.0.lock().await;
        clients.insert(client.id, client);
    }

	pub async fn register(&self, name: String, description: String) -> Result<Client, Error> {
		if name == *"Grant Azure" {
			return Err(Error::InvalidClientName);
		}

		let mut clients = self.0.lock().await;
		let client = Client::new(name, description);
		clients.insert(client.id, client.clone());
		Ok(client)
	}

	pub async fn delete(&self, id: Uuid) {
		self.0.lock().await.remove(&id);
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Client {	
	pub id: Uuid,
	pub secret: String,
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
			name,
			description,
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

pub async fn init_state() -> ClientStorage {
	let client_storage = ClientStorage::new();
	let mut client = Client::new(String::from("Grant"), String::from("Grant Azure"));
	client.id = Uuid::parse_str("f452faa7-cbe0-437b-97ff-c53049b0f710").unwrap();
	client.secret = String::from("5a02dd7d0e66aa5c9224bd0dc09d25ef2fa880a8d66f13a0312113938a2f4701");
	client_storage.update(client).await;
	client_storage
}
