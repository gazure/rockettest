use uuid::Uuid;
use crate::oauth::error::Error;
use crate::oauth::grant_types;
use crate::oauth::client::{Client, Clients};

pub struct Validator {}

impl Validator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn validate_grant_type(&self, grant_type: &str) -> Result<grant_types::GrantType, Error> {
        match grant_types::from_string(grant_type) {
            Some(gt) => Ok(gt),
            None => Err(Error::InvalidGrantType),
        }
    }

    pub async fn validate_client(&self, clients: Clients<'_>, client_id: &Uuid, client_secret: &String) -> Result<Client, Error> {
        let mut client = clients.get(client_id).await.ok_or(Error::InvalidClient)?.clone();
        client.validate_secret(client_secret)?;
        client.increment_login_count();
        clients.update(client.clone()).await;
        Ok(client)
    }
}
