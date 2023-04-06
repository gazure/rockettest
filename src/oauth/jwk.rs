use std::str;
use crate::oauth::Error;
use jwt::AlgorithmType;
use lazy_static::__Deref;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use openssl::bn::BigNum;
use rocket::serde::{uuid::Uuid, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(crate = "rocket::serde")]
pub enum JwkKeyType {
    RSA,
    EC,
    OCT,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(crate = "rocket::serde")]
pub enum PublicKeyUse {
    SIG,
    ENC,
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
        let n = key.n().to_hex_str()?.to_string();
        let e = key.e().to_hex_str()?.to_string();
        let kid = Uuid::new_v4();
        let key = PKey::from_rsa(key)?;
        Ok(Jwk {
            kty: JwkKeyType::RSA,
            pk_use: PublicKeyUse::SIG,
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
        assert_eq!(jwk.kty, JwkKeyType::RSA);
        assert_eq!(jwk.alg, JwkAlg::RS256);
        assert_eq!(jwk.pk_use, PublicKeyUse::SIG);
    }
}
