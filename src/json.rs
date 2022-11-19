use rocket::State;
use rocket::response::status;
use rocket::tokio::sync::Mutex;
use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::{Json, Value, json};
use std::borrow::Cow;

type Id = usize;
type MessageList = Mutex<Vec<String>>;
type Messages<'r> = &'r State<MessageList>;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct Message<'r> {
    id: Option<Id>,
    message: Cow<'r, str>,
}

#[post("/", format = "json", data = "<message>")]
async fn new<'a>(message: Json<Message<'a>>, list: Messages<'_>) -> status::Created<Json<Message<'a>>> {
    let mut list = list.lock().await;
    let id = list.len();
    list.push(message.message.to_string());
    let message = Message{
        id: Some(id),
        message: message.message.to_string().into(),
    };
    
    status::Created::new("some_url").body(Json(message))
}

#[post("/<id>", format = "json", data = "<message>")]
async fn update<'a>(id: Id, message: Json<Message<'_>>, list: Messages<'a>) -> Option<Json<Message<'a>>> {
    match list.lock().await.get_mut(id) {
        Some(existing) => {
            *existing = message.message.to_string();
            Some(Json(Message{
                id: Some(id),
                message: existing.to_string().into()
            }))
        }
        None => None
    }
}

#[get("/<id>", format = "json")]
async fn get(id: Id, list: Messages<'_>) -> Option<Json<Message<'_>>> {
    let list = list.lock().await;

    Some(Json(Message{
        id: Some(id),
        message: list.get(id)?.to_string().into(),
    }))
}

#[catch(404)]
fn not_found() -> Value {
    json!({
        "status": "error",
        "reason": "not found"
    })
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("JSON", |rocket| async {
        rocket.mount("/json", routes![new, update, get])
            .register("/json", catchers![not_found])
            .manage(MessageList::new(vec![]))
    })
}