#[macro_use] extern crate rocket;

use rocket::response::status::Custom;
use rocket::http::Status;
use rocket::serde::json::{Value, json};

mod oauth;
mod account;

#[get("/")]
fn index() -> Value {
    json!({})
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


#[catch(400)]
fn bad_request() -> Value {
	json!({
		"status": 400,
		"reason": "bad request"
	})
}

#[catch(404)]
fn not_found() -> Value {
    json!({
        "status": 404,
        "reason": "not found"
    })
}

#[catch(401)]
fn unauthorized() -> Value {
	json!({
		"status": 401,
		"reason": "unauthorized"
	})
}

#[catch(403)]
fn forbidden() -> Value {
	json!({
		"status": 403,
		"reason": "forbidden"
	})
}

#[catch(500)]
fn internal_server_error() -> Value {
	json!({
		"status": 500,
		"reason": "internal server error"
	})
}


#[launch]
async fn rocket() -> _ {
    rocket::build()
        .attach(oauth::stage().await)
        .attach(account::stage().await)
        .register("/oauth", catchers![not_found, unauthorized, forbidden, bad_request, internal_server_error])
        .mount("/", routes![index, health, status])
}
