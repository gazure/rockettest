use crate::config::PASSWORD_COST;
use crate::oauth::error::Error;
use hex::ToHex;
use rand::Rng;
use rocket::serde::uuid::Uuid;
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use rocket::State;
use std::collections::HashMap;

type ClientsMap = Mutex<HashMap<Uuid, Client>>;
pub type Clients<'r> = &'r State<ClientStorage>;
pub struct ClientStorage(ClientsMap);

impl ClientStorage {
    pub fn new() -> Self {
        Self(ClientsMap::new(HashMap::new()))
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

    pub async fn register(
        &self,
        name: String,
        description: String,
    ) -> Result<(Client, String), Error> {
        if name == *"Grant Azure" {
            return Err(Error::InvalidClientName);
        }

        let mut clients = self.0.lock().await;
        let (client, secret) = Client::new(name, description);
        clients.insert(client.id, client.clone());
        Ok((client, secret))
    }

    pub async fn delete(&self, id: Uuid) {
        self.0.lock().await.remove(&id);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Client {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    #[serde(skip)]
    recent_login_count: u32,
    #[serde(skip)]
    pub secret: String,
}

impl Client {
    // return self and unencrypted secret for regstration
    pub fn new(name: String, description: String) -> (Self, String) {
        let secret = Self::generate_secret();

        let client = Self {
            id: Uuid::new_v4(),
            secret: bcrypt::hash(secret.as_bytes(), *PASSWORD_COST).unwrap(),
            name,
            description,
            recent_login_count: 0,
        };
        (client, secret)
    }

    #[allow(dead_code)] // used in unit tests
    pub fn new_no_secret(name: String, description: String) -> Self {
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

    pub fn validate_secret(&self, secret: &str) -> Result<(), Error> {
        match (self.assert_rate_limit(), self.match_secret(secret)) {
            (true, true) => Ok(()),
            (false, true) => Err(Error::RateLimited),
            (_, false) => Err(Error::InvalidSecret),
        }
    }

    fn match_secret(&self, secret: &str) -> bool {
        bcrypt::verify(secret, &self.secret).unwrap()
    }

    fn generate_secret() -> String {
        rand::thread_rng().gen::<[u8; 32]>().encode_hex::<String>()
    }

    pub fn increment_login_count(&mut self) {
        self.recent_login_count += 1;
    }

    pub fn reroll_secret(&mut self, secret: Option<String>) -> String {
        let new_secret = match secret {
            Some(secret) => secret,
            None => Self::generate_secret(),
        };

        self.secret = bcrypt::hash(new_secret.as_bytes(), *PASSWORD_COST).unwrap();
        new_secret
    }
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

pub async fn init_state() -> ClientStorage {
    let client_storage = ClientStorage::new();
    let mut client = Client::new_no_secret(String::from("Grant"), String::from("Grant Azure"));
    client.id = Uuid::parse_str("f452faa7-cbe0-437b-97ff-c53049b0f710").unwrap();
    client.reroll_secret(Some(String::from(
        "5a02dd7d0e66aa5c9224bd0dc09d25ef2fa880a8d66f13a0312113938a2f4701",
    )));
    client_storage.update(client).await;
    client_storage
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_client_secret() {
        let (client, secret) = Client::new(String::from("Grant"), String::from("Grant's client"));
        assert!(client.match_secret(&secret));
        assert!(!client.match_secret(""));
    }

    #[test]
    fn test_client_rate_limit() {
        let mut client =
            Client::new_no_secret(String::from("Grant"), String::from("Grant's client"));
        assert!(client.assert_rate_limit());
        client.recent_login_count = 5;
        assert!(!client.assert_rate_limit());
    }

    #[test]
    fn test_client_validate_secret() {
        let (mut client, secret) =
            Client::new(String::from("Grant"), String::from("Grant's client"));
        assert!(client.validate_secret(&secret).is_ok());
        client.recent_login_count = 5;
        assert!(client.validate_secret(&secret).is_err());
        client.recent_login_count = 0;
        assert!(client.validate_secret("").is_err());
    }

    #[test]
    fn test_client_increment_login_count() {
        let mut client =
            Client::new_no_secret(String::from("Grant"), String::from("Grant's client"));
        assert_eq!(client.recent_login_count, 0);
        client.increment_login_count();
        assert_eq!(client.recent_login_count, 1);
    }

    #[test]
    fn test_client_generate_secret() {
        let secret = Client::generate_secret();
        assert_eq!(secret.len(), 64);
    }

    #[test]
    fn test_client_new() {
        let (client, secret) = Client::new(String::from("Grant"), String::from("Grant's client"));
        assert_eq!(client.name, "Grant");
        assert_eq!(client.description, "Grant's client");
        assert_ne!(client.secret, secret);
        assert_eq!(client.recent_login_count, 0);
        assert_eq!(secret.len(), 64);
        assert!(client.match_secret(&secret));
    }

    #[rocket::async_test]
    async fn test_client_storage_new() {
        let client_storage = ClientStorage::new();
        assert_eq!(client_storage.0.lock().await.len(), 0);
    }

    #[rocket::async_test]
    async fn test_client_storage_create() {
        let client_storage = ClientStorage::new();
        let client = Client::new_no_secret(String::from("Grant"), String::from("Grant's client"));
        client_storage.create(client.clone()).await;
        assert_eq!(client_storage.0.lock().await.len(), 1);
        assert_eq!(
            client_storage.0.lock().await.get(&client.id).unwrap(),
            &client
        );
    }

    #[rocket::async_test]
    async fn test_client_storage_update() {
        let client_storage = ClientStorage::new();
        let mut client =
            Client::new_no_secret(String::from("Grant"), String::from("Grant's client"));
        client_storage.create(client.clone()).await;
        client.name = String::from("Grant Azure");
        client_storage.update(client.clone()).await;
        assert_eq!(client_storage.0.lock().await.len(), 1);
        assert_eq!(
            client_storage.0.lock().await.get(&client.id).unwrap(),
            &client
        );
    }

    #[rocket::async_test]
    async fn test_client_storage_delete() {
        let client_storage = ClientStorage::new();
        let client = Client::new_no_secret(String::from("Grant"), String::from("Grant's client"));
        client_storage.create(client.clone()).await;
        client_storage.delete(client.id).await;
        assert_eq!(client_storage.0.lock().await.len(), 0);
    }

    #[rocket::async_test]
    async fn test_client_storage_get() {
        let client_storage = ClientStorage::new();
        let client = Client::new_no_secret(String::from("Grant"), String::from("Grant's client"));
        client_storage.create(client.clone()).await;
        assert_eq!(client_storage.get(&client.id).await, Some(client));
    }
}
