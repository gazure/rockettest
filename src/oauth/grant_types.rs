#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum GrantType {
    ClientCredentials,
    AuthorizationCode,
}

pub fn from_string(s: &str) -> Option<GrantType> {
    match s {
        "client_credentials" => Some(GrantType::ClientCredentials),
        "authorization_code" => Some(GrantType::AuthorizationCode),
        _ => None,
    }
}
