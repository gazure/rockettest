use crate::oauth::client::{Client, Clients};
use crate::oauth::error::Error;
use crate::oauth::grant_types;
use crate::oauth::pkce::{Pkce, PkceCodes};
use crate::oauth::scopes::Scope;
use uuid::Uuid;

pub fn validate_grant_type(grant_type: &str) -> Result<grant_types::GrantType, Error> {
    match grant_types::from_string(grant_type) {
        Some(gt) => Ok(gt),
        None => Err(Error::InvalidGrantType),
    }
}

pub async fn validate_code(
    code: Option<&str>,
    client_id: Uuid,
    pkce_codes: PkceCodes<'_>,
) -> Result<Pkce, Error> {
    let code = code.ok_or(Error::InvalidCode)?;
    let pkce_code = pkce_codes.get(code).await.ok_or(Error::InvalidCode)?;
    if pkce_code.client_id != client_id {
        return Err(Error::InvalidCode);
    }
    // this needs a lot more stuff
    // validate state, code challenge, etc.
    pkce_codes.delete(code).await;
    Ok(pkce_code)
}

pub async fn validate_client(
    clients: Clients<'_>,
    client_id: &Uuid,
    client_secret: &str,
) -> Result<Client, Error> {
    let mut client = clients
        .get(client_id)
        .await
        .ok_or(Error::InvalidClient)?
        .clone();
    client.validate_secret(client_secret)?;
    client.increment_login_count();
    clients.update(client.clone()).await;
    Ok(client)
}

pub fn validate_scopes(scopes: &str) -> Result<Vec<Scope>, Error> {
    let mut scopes_list = Vec::new();
    for scope in scopes.split_whitespace() {
        let scope_parsed = scope.parse::<Scope>();
        if let Ok(scope) = scope_parsed {
            scopes_list.push(scope);
        }
    }
    Ok(scopes_list)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::oauth::client::ClientStorage;
    use rocket::tokio;
    use rocket::State;

    #[tokio::test]
    async fn test_validate_grant_type() {
        let grant_type = "client_credentials";
        let grant_type_parsed = validate_grant_type(grant_type).unwrap();
        assert_eq!(grant_type_parsed, grant_types::GrantType::ClientCredentials);
    }

    #[tokio::test]
    async fn test_validate_client() {
        let client_storage = ClientStorage::new();
        let clients: Clients = State::from(&client_storage);
        let (client, client_secret) = Client::new("name".to_string(), "test".to_string());
        client_storage.create(client.clone()).await;

        let client_id = client.id;
        let result = validate_client(clients, &client_id, &client_secret)
            .await
            .unwrap();

        assert_eq!(result.id, client_id);
        assert!(result.validate_secret(&client_secret).is_ok());
        assert_eq!(result.name, "name");
        assert_eq!(result.description, "test");
    }

    #[test]
    fn test_validate_scopes() {
        let scopes = "openid profile email phone address offline_access";
        let scopes_parsed = validate_scopes(scopes).unwrap();
        assert_eq!(scopes_parsed.len(), 6);
        assert_eq!(scopes_parsed[0], Scope::OpenId);
        assert_eq!(scopes_parsed[1], Scope::Profile);
        assert_eq!(scopes_parsed[2], Scope::Email);
        assert_eq!(scopes_parsed[3], Scope::Phone);
        assert_eq!(scopes_parsed[4], Scope::Address);
        assert_eq!(scopes_parsed[5], Scope::OfflineAccess);

        let scopes = "";
        let scopes_parsed = validate_scopes(scopes).unwrap();
        assert_eq!(scopes_parsed.len(), 0);
    }
}
