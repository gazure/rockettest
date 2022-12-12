
pub enum GrantType {
    ClientCredentials,
}

pub fn from_string(s: &str) -> Option<GrantType> {
    match s {
        "client_credentials" => Some(GrantType::ClientCredentials),
        _ => None,
    }
}

