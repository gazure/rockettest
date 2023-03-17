use crate::oauth::Error;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum GrantType {
    ClientCredentials,
    AuthorizationCode,
}

impl FromStr for GrantType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            _ => Err(Self::Err::InvalidGrantType),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_str() {
        let gt: GrantType = "client_credentials".parse().unwrap();
        assert!(gt == GrantType::ClientCredentials);

        let gt: GrantType = "authorization_code".parse().unwrap();
        assert!(gt == GrantType::AuthorizationCode);

        let gt: Result<GrantType, Error> = "bad_grant_type".parse();
        assert!(gt.is_err());
    }
}
