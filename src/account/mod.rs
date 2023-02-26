use rocket::fs::NamedFile;
use rocket::http::Status;
use rocket::http::{Cookie, CookieJar};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::Redirect;
use rocket::serde::uuid::Uuid;
use rocket_dyn_templates::{context, Template};

mod acc;
mod forms;

#[derive(Debug)]
struct LoggedIn {
    pub user_id: Uuid,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LoggedIn {
    type Error = acc::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let jar = request.cookies();
        let user_id_cookie = jar.get("user_id");
        match user_id_cookie {
            Some(user_id) => Outcome::Success(Self {
                user_id: Uuid::parse_str(user_id.value()).unwrap(),
            }),
            None => Outcome::Failure((Status::Unauthorized, acc::Error::Account)),
        }
    }
}

#[get("/login")]
async fn login_form(jar: &CookieJar<'_>) -> Result<NamedFile, Redirect> {
    let user_cookie = jar.get("user_id");
    if user_cookie.is_some() {
        Err(Redirect::to("/account/settings"))
    } else {
        Ok(NamedFile::open("templates/login.html").await.unwrap())
    }
}

#[post("/login", data = "<login_form>")]
async fn login(
    login_form: forms::LoginForm<'_>,
    accounts: acc::Accounts<'_>,
    jar: &CookieJar<'_>,
) -> Redirect {
    let user = accounts
        .login(login_form.username, login_form.password)
        .await;

    match user {
        Some(user) => {
            let cookie = Cookie::build("user_id", user.id.to_string());
            jar.add(cookie.finish());
            Redirect::to("/account/settings")
        }
        None => Redirect::to("/account/login"),
    }
}

#[get("/register")]
async fn register_form(jar: &CookieJar<'_>) -> Result<NamedFile, Redirect> {
    let user_cookie = jar.get("user_id");
    if user_cookie.is_some() {
        Err(Redirect::to("/account/settings"))
    } else {
        Ok(NamedFile::open("templates/register.html").await.unwrap())
    }
}

#[post("/register", data = "<login_form>")]
async fn register(
    login_form: forms::LoginForm<'_>,
    accounts: acc::Accounts<'_>,
    jar: &CookieJar<'_>,
) -> Result<Redirect, Status> {
    let account = accounts
        .register(login_form.username, login_form.password)
        .await
        .map_err(|e| -> Status { e.into() })?;
    jar.add(Cookie::build("user_id", account.id.to_string()).finish());
    Ok(Redirect::to("/account/settings"))
}

#[get("/settings")]
async fn settings(context: LoggedIn, accounts: acc::Accounts<'_>) -> Result<Template, Status> {
    let account = accounts
        .get(&context.user_id)
        .await
        .ok_or(Status::Unauthorized)?;
    Ok(Template::render(
        "settings",
        context! {username: account.username},
    ))
}

#[post("/logout")]
async fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove(Cookie::named("user_id"));
    Redirect::to("/account/login")
}

pub async fn stage() -> rocket::fairing::AdHoc {
    let account_storage = acc::AccountStorage::new();
    rocket::fairing::AdHoc::on_ignite("account", |rocket| async {
        rocket
            .mount(
                "/account",
                routes![login_form, login, logout, register, register_form, settings],
            )
            .manage(account_storage)
    })
}
