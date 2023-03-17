use chrono;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::oauth::client::Client;
use crate::oauth::error::Error;
use crate::oauth::scopes::Scope;
use crate::oauth::token::Token;

const TOKEN_TTL: i64 = 3600;

pub async fn generate(
    scopes: Vec<Scope>,
    client: Client,
    user_id: Option<Uuid>,
) -> Result<Token, Error> {
    // TODO: some-secret should be more secret than this
    let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
    let mut claims = BTreeMap::new();
    let now = chrono::offset::Utc::now().timestamp();
    let iat = now.to_string();
    let exp = (now + TOKEN_TTL).to_string();

    claims.insert("iat", iat);
    claims.insert("exp", exp);
    claims.insert("client_id", client.id.to_string());

    if let Some(user_id) = user_id {
        claims.insert("user_id", user_id.to_string());
    }

    // gonna just assume all scopes are valid for now
    let scopes_string = scopes
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
        .join(" ");
    claims.insert("scopes", scopes_string.clone());

    let token_str = claims
        .sign_with_key(&key)
        .map_err(|_| Error::InvalidToken)?;
    Ok(Token::new(token_str, TOKEN_TTL, scopes_string, None))
}

#[cfg(test)]
mod test {
    use super::*;

    #[rocket::async_test]
    async fn test_generate_client_credentials() {
        let client = Client::new_no_secret("name".to_string(), "test".to_string());
        let scopes = vec![Scope::OpenId, Scope::Profile];
        let token = generate(scopes, client, None).await.unwrap();

        assert_eq!(token.expires_in, TOKEN_TTL);
        assert_eq!(token.scope, "openid profile");
        assert!(token.refresh_token.is_none());
    }

    #[rocket::async_test]
    async fn test_generate_authorization_code() {
        let client = Client::new_no_secret("name".to_string(), "test".to_string());
        let scopes = vec![Scope::OpenId, Scope::Profile];
        let user_id = Uuid::new_v4();
        let token = generate(scopes, client, Some(user_id)).await.unwrap();

        assert_eq!(token.expires_in, TOKEN_TTL);
        assert_eq!(token.scope, "openid profile");
        assert!(token.refresh_token.is_none());
    }
}
