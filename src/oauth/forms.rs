use rocket::form::Form;
use rocket::serde::{Deserialize, Serialize};
use std::borrow::Cow;
use uuid::Uuid;

pub type TokenRequestForm<'r> = Form<TokenRequest<'r>>;

#[allow(dead_code)]
#[derive(Debug, FromForm)]
pub struct TokenRequest<'r> {
    pub client_id: Uuid,
    pub client_secret: String,
    pub grant_type: &'r str,
    pub scope: &'r str,
    pub user_id: Option<&'r str>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct RegisterRequest<'r> {
    pub name: Cow<'r, str>,
    pub description: Cow<'r, str>,
}
