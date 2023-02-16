use super::client::Clients;
use super::error::Error;
use super::forms::TokenRequestForm;

pub mod generators;
pub mod validators;
use crate::oauth::token::Token;

pub async fn token(trf: TokenRequestForm<'_>, clients: Clients<'_>) -> Result<Token, Error> {
    let grant_type = validators::validate_grant_type(trf.grant_type)?;
    let scopes = validators::validate_scopes(trf.scope)?;
    let client = validators::validate_client(clients, &trf.client_id, &trf.client_secret).await?;
    let token = generators::generate(grant_type, scopes, client).await?;
    Ok(token)
}
