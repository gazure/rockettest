use hmac::{Hmac, Mac};
use sha2::Sha256;
use jwt::SignWithKey;
use std::collections::BTreeMap;
use rocket::serde::{Serialize, Deserialize};

use crate::oauth::client::Client;
use crate::oauth::error::Error;
use crate::oauth::grant_types::GrantType;

pub struct Generator{}


impl Generator {
    pub fn new() -> Self {
        Self{}
    }

    pub async fn generate(&self, grant_type: GrantType, client: Client) -> Result<Token, Error> {
        match grant_type {
            GrantType::ClientCredentials => {
                // TODO: some-secret should be an RSA Key
                let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
                let mut claims = BTreeMap::new();
                let client_id_string = client.id.to_string();
                let iat = 0.to_string();
                let exp = 0.to_string();

                claims.insert("iat", &iat);
                claims.insert("exp", &exp);
                claims.insert("client_id", &client_id_string);
                let token_str = claims.sign_with_key(&key).map_err(|_| Error::InvalidToken)?;

                Ok(Token{
                    access_token: token_str,
                    expires_in: 3600,
                    refresh_token: "".to_string(),
                    scope: "".to_string(),
                })
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Token {
    pub access_token: String,
    pub expires_in: i32,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
}
