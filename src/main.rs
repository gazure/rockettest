#[macro_use]
extern crate rocket;

use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::{json, Value};
use rocket_dyn_templates::Template;
use sqlx::mysql::MySqlPool;

mod account;
mod config;
mod decks;
mod oauth;

#[get("/")]
fn index() -> Value {
    json!({})
}

#[get("/dbping")]
async fn ping() -> Value {
    let pool = MySqlPool::connect("mysql://root:secret@localhost:3336/oauth")
        .await
        .unwrap();

    let row: (i64,) = sqlx::query_as("SELECT ?")
        .bind(150_i64)
        .fetch_one(&pool)
        .await
        .unwrap();

    json!({
        "value": row
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
    Custom(
        status,
        json!({
            "status": status.code,
        }),
    )
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
        .attach(Template::fairing())
        .attach(oauth::stage().await)
        .attach(account::stage().await)
        .attach(decks::stage().await)
        .register(
            "/oauth",
            catchers![
                not_found,
                unauthorized,
                forbidden,
                bad_request,
                internal_server_error
            ],
        )
        .mount("/", routes![index, health, status, ping])
}

#[cfg(test)]
mod test {
    use super::*;
    use rocket::http::Status;
    use rocket::local::asynchronous::Client;
    use rocket::serde::json::Value;

    #[rocket::async_test]
    async fn test_index() {
        let client = Client::tracked(rocket().await).await.unwrap();
        let response = client.get(uri!(super::index)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().await.unwrap(), "{}");
    }

    #[rocket::async_test]
    async fn test_health() {
        let client = Client::tracked(rocket().await).await.unwrap();
        let response = client.get(uri!(super::health)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json::<Value>().await.unwrap(),
            json!({
                "status": "ok"
            })
        );
    }

    #[rocket::async_test]
    async fn test_status() {
        let client = Client::tracked(rocket().await).await.unwrap();
        let response = client.get(uri!(super::status(200))).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json::<Value>().await.unwrap(),
            json!({
                "status": 200,
            })
        );
        let response = client.get(uri!(super::status(401))).dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized);
        assert_eq!(
            response.into_json::<Value>().await.unwrap(),
            json!({
                "status": 401,
            })
        );
        let response = client.get(uri!(super::status(301))).dispatch().await;
        assert_eq!(response.status(), Status::MovedPermanently);
        assert_eq!(
            response.into_json::<Value>().await.unwrap(),
            json!({
                "status": 301,
            })
        );
        let response = client.get(uri!(super::status(418))).dispatch().await;
        assert_eq!(response.status(), Status::ImATeapot);
        assert_eq!(
            response.into_json::<Value>().await.unwrap(),
            json!({
                "status": 418,
            })
        );
        let response = client.get(uri!(super::status(504))).dispatch().await;
        assert_eq!(response.status(), Status::GatewayTimeout);
        assert_eq!(
            response.into_json::<Value>().await.unwrap(),
            json!({
                "status": 504,
            })
        );
    }
}
