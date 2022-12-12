#[macro_use] extern crate rocket;

use rocket::response::status::Custom;
use rocket::http::Status;
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
    json!({
        "status": "ok"
    })
}

#[get("/astra")]
fn astra() -> Value {
    json!({
        "cat": "astra"
    })
}

#[get("/charlie")]
fn charlie() -> Value {
    json!({
        "cat": "charlie"
    })
}

#[get("/health")]
fn health() -> Value {
    json!({
        "status": "ok"
    })
}

// rocket route that returns dynamic status code
#[get("/status/<code>")]
fn status(code: u16) -> Custom<Value> {
    let status = match Status::from_code(code) {
        Some(status) => status,
        None => Status::BadRequest,
    };
    Custom(status, json!({
        "status": status.code,
    }))
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(json::stage())
        .attach(oauth::stage())
        .mount("/", routes![index, astra, charlie, delay, health, status])
}
