use super::client::Clients;
use super::error::Error;
use super::forms;
use super::pkce::CodeChallengeMethod;
use uuid::Uuid;

pub mod generate;
pub mod validate;
use crate::oauth::grant_types::GrantType;
use crate::oauth::pkce::{Pkce, PkceCodes};
use crate::oauth::token::Token;

pub async fn token(
    trf: forms::TokenRequestForm<'_>,
    clients: Clients<'_>,
    pkce_codes: PkceCodes<'_>,
) -> Result<Token, Error> {
    let grant_type: GrantType = trf.grant_type.parse()?;
    let client = validate::validate_client(clients, &trf.client_id, &trf.client_secret).await?;

    let (scopes, user_id) = match grant_type {
        GrantType::AuthorizationCode => {
            let pkce = validate::validate_code(trf.code, client.id, pkce_codes).await?;
            (pkce.scope, Some(pkce.account_id))
        }
        GrantType::ClientCredentials => {
            let scope_param = trf.scope.unwrap_or("");
            (validate::validate_scopes(scope_param)?, None)
        }
    };
    let token = generate::generate(scopes, client, user_id).await?;
    Ok(token)
}

#[derive(Debug)]
pub struct AuthContext {
    pub client_name: String,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub state: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
}

pub async fn authorize(
    auth_request: forms::AuthorizationRequest<'_>,
    clients: Clients<'_>,
) -> Result<AuthContext, Error> {
    let client = clients
        .get(&auth_request.client_id)
        .await
        .ok_or(Error::InvalidClient)?;
    Ok(AuthContext {
        client_name: client.name,
        client_id: client.id,
        redirect_uri: auth_request.redirect_uri.to_string(),
        state: auth_request.state.to_string(),
        scope: auth_request.scope.to_string(),
        code_challenge: auth_request.code_challenge.to_string(),
        code_challenge_method: auth_request.code_challenge_method,
    })
}

#[derive(Debug)]
pub struct ValidatedAuthContext {
    pub client_name: String,
    pub redirect_uri: String,
    pub state: String,
    pub code: String,
}

pub async fn submit_authorization(
    user_id: Uuid,
    auth_request: forms::AuthorizationRequestForm<'_>,
    clients: Clients<'_>,
    pkce_codes: PkceCodes<'_>,
) -> Result<ValidatedAuthContext, Error> {
    let client = clients
        .get(&auth_request.client_id)
        .await
        .ok_or(Error::InvalidClient)?;

    let validated_scopes = validate::validate_scopes(auth_request.scope)?;

    let pkce_code = Pkce::new(
        auth_request.client_id,
        user_id,
        auth_request.redirect_uri.to_string(),
        auth_request.state.to_string(),
        validated_scopes,
        auth_request.code_challenge.to_string(),
        auth_request.code_challenge_method.clone(),
    );
    let authentication_code = pkce_code.authentication_code.clone();
    pkce_codes.insert(pkce_code).await;

    Ok(ValidatedAuthContext {
        client_name: client.name,
        redirect_uri: auth_request.redirect_uri.to_string(),
        state: auth_request.state.to_string(),
        code: authentication_code,
    })
}
