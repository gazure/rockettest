use crate::oauth::Error;
use jwt::AlgorithmType;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use rocket::serde::{uuid::Uuid, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(crate = "rocket::serde")]
pub enum JwkKeyType {
    Rsa,
    // EC,
    // OCT,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(crate = "rocket::serde")]
pub enum PublicKeyUse {
    Sig,
    // ENC,
}

#[derive(Debug, Clone, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Jwk {
    pub kty: JwkKeyType,
    pub pk_use: PublicKeyUse,
    pub n: String,
    pub e: String,
    pub kid: uuid::Uuid,
    pub alg: AlgorithmType,
    #[serde(skip)]
    pub key: PKey<Private>,
}

impl Jwk {
    pub fn new() -> Result<Self, Error> {
        let key = Rsa::generate(2048)?;
        let n = key.n().to_dec_str()?.to_string();
        let e = key.e().to_dec_str()?.to_string();
        let kid = Uuid::new_v4();
        let key = PKey::from_rsa(key)?;
        Ok(Jwk {
            kty: JwkKeyType::Rsa,
            pk_use: PublicKeyUse::Sig,
            n,
            e,
            kid,
            alg: AlgorithmType::Rs256,
            key,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new() {
        let jwk = Jwk::new().unwrap();
        assert_eq!(jwk.kty, JwkKeyType::Rsa);
        assert_eq!(jwk.alg, AlgorithmType::Rs256);
        assert_eq!(jwk.pk_use, PublicKeyUse::Sig);
    }
}
