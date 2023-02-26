use rocket::http::CookieJar;
use rocket::http::Status;
use rocket::response::status::{BadRequest, NoContent};
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::serde::json::{json, Value};
use rocket_dyn_templates::{context, Template};
use uuid::Uuid;

pub mod client;
pub mod client_jwt;
pub mod error;
pub mod forms;
pub mod grant_types;
pub mod scopes;
pub mod server;
pub mod token;

use client::{Client, Clients};
use error::Error;
use forms::{RegisterRequest, TokenRequestForm};

#[post("/token", data = "<token_request>")]
async fn token_endpoint(
    token_request: TokenRequestForm<'_>,
    clients: Clients<'_>,
) -> Result<Value, Status> {
    let token = server::token(token_request, clients)
        .await
        .map_err(|e| -> Status { e.into() })?;
    Ok(json!(token))
}

#[get("/authorize?<auth_request>")]
async fn authorize(
    auth_request: forms::AuthorizationRequest<'_>,
    clients: Clients<'_>,
    jar: &CookieJar<'_>,
) -> Result<Template, Redirect> {
    let user_cookie = jar.get("user_id");
    if user_cookie.is_none() {
        return Err(Redirect::to("/login"));
    }
    let auth_context = server::authorize(auth_request, clients)
        .await
        .map_err(|_| Redirect::to("/account/settings"))?;

    Ok(Template::render(
        "authorize",
        context! {client_name: auth_context.client_name},
    ))
}

#[post("/clients", data = "<client_request>")]
async fn register(
    client_request: Json<RegisterRequest<'_>>,
    clients: Clients<'_>,
) -> Result<Value, BadRequest<Value>> {
    let (client, secret) = clients
        .register(
            client_request.name.to_string(),
            client_request.description.to_string(),
        )
        .await
        .map_err(|e| match e {
            Error::InvalidClientName => BadRequest(Some(json!("name already taken?"))),
            _ => BadRequest(Some(json!("unknown error"))),
        })?;

    let mut client_value = serde_json::to_value(client)
        .map_err(|_| BadRequest(Some(json!("failed to serialize client"))))?;
    client_value["secret"] = Value::String(secret);
    Ok(client_value)
}

#[get("/clients/<id>")]
async fn get_client(
    id: Uuid,
    clients: Clients<'_>,
    auth: client_jwt::ClientJwt,
) -> Result<Json<Client>, Status> {
    auth.authorize_for(&id)
        .map_err(|e| -> Status { e.into() })?;
    clients
        .get(&id)
        .await
        .map_or(Err(Status::NotFound), |client| Ok(Json(client)))
}

#[delete("/clients/<id>")]
async fn delete_client(
    id: Uuid,
    clients: Clients<'_>,
    auth: client_jwt::ClientJwt,
) -> Result<NoContent, Status> {
    auth.authorize_for(&id)
        .map_err(|e| -> Status { e.into() })?;
    clients.delete(id).await;
    Ok(NoContent)
}

pub async fn stage() -> rocket::fairing::AdHoc {
    let client_storage = client::init_state().await;
    rocket::fairing::AdHoc::on_ignite("oauth", |rocket| async {
        rocket
            .mount(
                "/oauth",
                routes![
                    token_endpoint,
                    register,
                    get_client,
                    delete_client,
                    authorize
                ],
            )
            .manage(client_storage)
    })
}

#[cfg(test)]
mod test {
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::Client;
    use rocket::serde::json::json;
    use rocket::serde::json::Value;

    #[rocket::async_test]
    async fn test_get_client_unauthorized() {
        let rocket = rocket::build().attach(super::stage().await);
        let client = Client::tracked(rocket).await.unwrap();

        let response = client
            .get("/oauth/clients/00000000-0000-0000-0000-000000000000")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_manage_client_with_client_credentials() {
        let rocket = rocket::build().attach(super::stage().await);
        let test_client = Client::tracked(rocket).await.unwrap();

        let response = test_client
            .post("/oauth/clients")
            .header(ContentType::JSON)
            .body(
                json!({
                    "name": "test",
                    "description": "test"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let body: Value = response.into_json().await.unwrap();
        let secret = body["secret"].clone();
        let secret = secret.as_str().unwrap();
        let client: crate::oauth::client::Client = serde_json::from_value(body).unwrap();
        println!("client: {:?}", client);

        assert_eq!(client.name, "test");
        assert_eq!(client.description, "test");

        let response = test_client
            .post("/oauth/token")
            .header(ContentType::Form)
            .body(format!(
                "grant_type=client_credentials&scope=openid&client_id={}&client_secret={}",
                client.id, secret
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let token = response.into_json::<super::token::Token>().await.unwrap();

        // assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, 3600);
        assert_eq!(token.scope, "openid");

        let response = test_client
            .get(format!("/oauth/clients/{}", client.id))
            .header(Header::new(
                "Authorization",
                format!("Bearer {}", token.access_token),
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let retrieved_client = response.into_json::<super::client::Client>().await.unwrap();
        assert_eq!(retrieved_client.id, client.id);

        let delete_response = test_client
            .delete(format!("/oauth/clients/{}", client.id))
            .header(Header::new(
                "Authorization",
                format!("Bearer {}", token.access_token),
            ))
            .dispatch()
            .await;

        assert_eq!(delete_response.status(), Status::NoContent);
    }
}
