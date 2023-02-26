use super::client::Clients;
use super::error::Error;
use super::forms;

pub mod generators;
pub mod validators;
use crate::oauth::token::Token;

pub async fn token(trf: forms::TokenRequestForm<'_>, clients: Clients<'_>) -> Result<Token, Error> {
    let grant_type = validators::validate_grant_type(trf.grant_type)?;
    let scopes = validators::validate_scopes(trf.scope)?;
    let client = validators::validate_client(clients, &trf.client_id, &trf.client_secret).await?;
    let token = generators::generate(grant_type, scopes, client).await?;
    Ok(token)
}

#[derive(Debug)]
pub struct AuthContext {
    pub client_name: String,
}

pub async fn authorize(
    auth_request: forms::AuthorizationRequest<'_>,
    clients: Clients<'_>,
) -> Result<AuthContext, Error> {
    let client = clients
        .get(&auth_request.client_id)
        .await
        .ok_or(Error::InvalidClient)?;
    let auth_context = AuthContext {
        client_name: client.name,
    };
    Ok(auth_context)
}
