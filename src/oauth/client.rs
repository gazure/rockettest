use rocket::serde::uuid::Uuid;
use rocket::serde::{Serialize, Deserialize};
use rand::Rng;
use hex::ToHex;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Client {
	pub client_id: Uuid,
	client_secret: String,
	pub name: String,
	pub description: String,
}

impl Client {
	pub fn new(name: String, description: String) -> Self {
		Self {
			client_id: Uuid::new_v4(),
			client_secret: Self::generate_secret(),
			name: name,
			description: description,
		}
	}

	fn generate_secret() -> String {
		let secret = rand::thread_rng().gen::<[u8; 32]>();
		secret.encode_hex::<String>()	
	}
}
