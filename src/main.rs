#[macro_use] extern crate rocket;


use rocket::tokio::time::{sleep, Duration};
use rocket::serde::json::{Value, json};

mod oauth;
mod json;

#[get("/delay/<seconds>")]
async fn delay(seconds: u64) -> String {
    sleep(Duration::from_secs(seconds)).await;
    format!("Waited for {} seconds", seconds)
}

#[get("/")]
fn index() -> Value {
    json!("Hello, World")
}

#[get("/health")]
fn health() -> Value {
    json!({
        "status": "ok"
    })
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(json::stage())
        .attach(oauth::stage())
        .mount("/", routes![index, delay, health])
}
