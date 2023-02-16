use std::str::FromStr;
use std::fmt::Display;


#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Scope {
    OpenId,
    Profile,
    Email,
    Address,
    Phone,
    OfflineAccess,
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::OpenId => write!(f, "openid"),
            Scope::Profile => write!(f, "profile"),
            Scope::Email => write!(f, "email"),
            Scope::Address => write!(f, "address"),
            Scope::Phone => write!(f, "phone"),
            Scope::OfflineAccess => write!(f, "offline_access"),
        }
    }
}

impl FromStr for Scope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "openid" => Ok(Scope::OpenId),
            "profile" => Ok(Scope::Profile),
            "email" => Ok(Scope::Email),
            "address" => Ok(Scope::Address),
            "phone" => Ok(Scope::Phone),
            "offline_access" => Ok(Scope::OfflineAccess),
            _ => Err(()),
        }
    }
}
