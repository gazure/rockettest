use crate::oauth::scopes::Scope;
use hex::ToHex;
use rand::Rng;
use rocket::tokio::sync::Mutex;
use rocket::State;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Pkce {
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub redirect_uri: String,
    pub state: String,
    pub scope: Vec<Scope>,
    pub code_verifier: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub authentication_code: String,
}

impl Pkce {
    pub fn new(
        client_id: Uuid,
        account_id: Uuid,
        redirect_uri: String,
        state: String,
        scope: Vec<Scope>,
    ) -> Self {
        let authentication_code = Self::generate_authentication_code();

        Self {
            client_id,
            account_id,
            redirect_uri,
            state,
            scope,
            code_verifier: "".to_string(),
            code_challenge: "".to_string(),
            code_challenge_method: "".to_string(),
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
