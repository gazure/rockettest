use rocket::serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Token {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl Token {
    pub fn new(
        access_token: String,
        expires_in: i64,
        scope: String,
        refresh_token: Option<String>,
    ) -> Self {
        Self {
            token_type: "Bearer".to_string(),
            access_token,
            expires_in,
            scope,
            refresh_token,
        }
    }
}
