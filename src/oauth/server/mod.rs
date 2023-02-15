use super::client::Clients;
use super::error::Error;
use super::forms::TokenRequestForm;

pub mod validators;
pub mod generators;
use validators::Validator;
use generators::{Generator, Token};


pub struct Server {
    pub validator: Validator,
    pub generator: Generator,
}

impl Server {
    pub fn new() -> Self {
        Self {
            validator: Validator::new(),
            generator: Generator::new(),
        }
    }

    pub async fn token(&self, trf: TokenRequestForm<'_>, clients: Clients<'_>) -> Result<Token, Error>{
        let grant_type = self.validator.validate_grant_type(trf.grant_type)?;
        let client = self.validator.validate_client(clients, &trf.client_id, &trf.client_secret).await?;
        let token = self.generator.generate(grant_type, client).await?;
        Ok(token)
    }
}

