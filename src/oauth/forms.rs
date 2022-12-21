use uuid::Uuid;
use rocket::form::{Form};


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
	