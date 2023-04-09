use rocket::serde::json::{json, Value};

use crate::oauth::client_jwt;


#[get("/")]
async fn decks(auth: client_jwt::ClientJwt) -> Value {
    let cid = auth.get_claim("client_id").or(Some("none".to_string()));
    json!({
        "client_id": cid
    })
}

pub async fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("decks", |rocket| async {
        rocket.mount(
            "/decks",
            routes![
                decks,
            ],
        )}
    )
}
