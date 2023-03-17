use crate::oauth::scopes::Scope;
use hex::ToHex;
use rand::Rng;
use rocket::form::FromFormField;
use rocket::tokio::sync::Mutex;
use rocket::State;
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, FromFormField)]
pub enum CodeChallengeMethod {
    S256,
}

impl fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CodeChallengeMethod::S256 => "S256",
            }
        )
    }
}

#[derive(Debug, Clone)]
pub struct Pkce {
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub redirect_uri: String,
    pub state: String,
    pub scope: Vec<Scope>,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub authentication_code: String,
}

impl Pkce {
    pub fn new(
        client_id: Uuid,
        account_id: Uuid,
        redirect_uri: String,
        state: String,
        scope: Vec<Scope>,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
    ) -> Self {
        let authentication_code = Self::generate_authentication_code();

        Self {
            client_id,
            account_id,
            redirect_uri,
            state,
            scope,
            code_challenge,
            code_challenge_method,
            authentication_code,
        }
    }

    fn generate_authentication_code() -> String {
        rand::thread_rng().gen::<[u8; 32]>().encode_hex::<String>()
    }
}

type PkceMap = Mutex<HashMap<String, Pkce>>;
pub type PkceCodes<'r> = &'r State<PkceStorage>;
pub struct PkceStorage(PkceMap);

impl PkceStorage {
    pub fn new() -> Self {
        Self(PkceMap::new(HashMap::new()))
    }

    #[allow(unused)]
    pub async fn get(&self, code: &str) -> Option<Pkce> {
        let codes = self.0.lock().await;
        Some(codes.get(code)?.clone())
    }

    #[allow(unused)]
    pub async fn update(&self, code: Pkce) {
        let mut codes = self.0.lock().await;
        codes
            .entry(code.authentication_code.clone())
            .and_modify(|c| *c = code);
    }

    pub async fn insert(&self, code: Pkce) {
        let mut codes = self.0.lock().await;
        codes.insert(code.authentication_code.clone(), code);
    }

    #[allow(unused)]
    pub async fn delete(&self, code: &str) {
        self.0.lock().await.remove(code);
    }
}
