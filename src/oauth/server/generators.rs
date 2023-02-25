use chrono;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;
use std::collections::BTreeMap;

use crate::oauth::client::Client;
use crate::oauth::error::Error;
use crate::oauth::grant_types::GrantType;
use crate::oauth::scopes::Scope;
use crate::oauth::token::Token;

const TOKEN_TTL: i64 = 3600;

pub async fn generate(
    grant_type: GrantType,
    scopes: Vec<Scope>,
    client: Client,
) -> Result<Token, Error> {
    match grant_type {
        GrantType::ClientCredentials => {
            // TODO: some-secret should be an RSA Key
            let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
            let mut claims = BTreeMap::new();
            let client_id_string = client.id.to_string();
            let now = chrono::offset::Utc::now().timestamp();
            let iat = now.to_string();
            let exp = (now + TOKEN_TTL).to_string();

            claims.insert("iat", &iat);
            claims.insert("exp", &exp);
            claims.insert("client_id", &client_id_string);

            // gonna just assume all scopes are valid for now
            let scopes_string = scopes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
                .join(" ");
            claims.insert("scopes", &scopes_string);

            let token_str = claims
                .sign_with_key(&key)
                .map_err(|_| Error::InvalidToken)?;

            Ok(Token::new(token_str, TOKEN_TTL, scopes_string, None))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[rocket::async_test]
    async fn test_generate_client_credentials() {
        let client = Client::new_no_secret("name".to_string(), "test".to_string());
        let scopes = vec![Scope::OpenId, Scope::Profile];
        let token = generate(GrantType::ClientCredentials, scopes, client)
            .await
            .unwrap();

        assert_eq!(token.expires_in, TOKEN_TTL);
        assert_eq!(token.scope, "openid profile");
        assert!(token.refresh_token.is_none());
    }
}
