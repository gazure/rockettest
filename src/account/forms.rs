use rocket::form::Form;

#[derive(Debug, FromForm)]
pub struct LoginRequest<'r> {
    pub username: &'r str,
    pub password: &'r str,
}
pub type LoginForm<'r> = Form<LoginRequest<'r>>;
