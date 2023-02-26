use super::client::Clients;
use super::error::Error;
use super::forms;
use uuid::Uuid;

pub mod generators;
pub mod validators;
use crate::oauth::pkce;
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
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub state: String,
    pub scope: String,
}

#[derive(Debug)]
pub struct ValidatedAuthContext {
    pub client_name: String,
    pub redirect_uri: String,
    pub state: String,
    pub code: String,
}

pub async fn authorize(
    auth_request: forms::AuthorizationRequestForm<'_>,
    clients: Clients<'_>,
) -> Result<AuthContext, Error> {
    let client = clients
        .get(&auth_request.client_id)
        .await
        .ok_or(Error::InvalidClient)?;
    let auth_context = AuthContext {
        client_name: client.name,
        client_id: client.id,
        redirect_uri: auth_request.redirect_uri.to_string(),
        state: auth_request.state.to_string(),
        scope: auth_request.scope.to_string(),
    };
    Ok(auth_context)
}

pub async fn submit_authorization(
    user_id: Uuid,
    auth_request: forms::AuthorizationRequest<'_>,
    clients: Clients<'_>,
    pkce_codes: pkce::PkceCodes<'_>,
) -> Result<ValidatedAuthContext, Error> {
    let client = clients
        .get(&auth_request.client_id)
        .await
        .ok_or(Error::InvalidClient)?;

    let validated_scopes = validators::validate_scopes(auth_request.scope)?;

    let pkce_code = pkce::Pkce::new(
        auth_request.client_id,
        user_id,
        auth_request.redirect_uri.to_string(),
        auth_request.state.to_string(),
        validated_scopes,
    );
    let authentication_code = pkce_code.authentication_code.clone();
    pkce_codes.insert(pkce_code).await;

    let validated_auth_context = ValidatedAuthContext {
        client_name: client.name,
        redirect_uri: auth_request.redirect_uri.to_string(),
        state: auth_request.state.to_string(),
        code: authentication_code,
    };
    Ok(validated_auth_context)
}
