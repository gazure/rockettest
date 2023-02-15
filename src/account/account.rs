use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use std::collections::HashMap;
use rocket::State;
use rocket::serde::uuid::Uuid;
use rocket::http::Status;
use bcrypt;

/// TODO: Move this
#[allow(dead_code)]
#[derive(Debug)]
pub enum Error{
    InvalidUsername,
    InvalidPassword,
    InvalidAccount,
}

impl Into<Status> for Error {
    fn into(self) -> Status {
        match self {
            Error::InvalidUsername => Status::BadRequest,
            Error::InvalidPassword => Status::BadRequest,
            Error::InvalidAccount => Status::BadRequest,
        }
    }
}
/// END TODO

type AccountMap = Mutex<HashMap<Uuid, Account>>;
pub type Accounts<'r> = &'r State<AccountStorage>;
pub struct AccountStorage (AccountMap);

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Account {
    pub id: Uuid,
    pub username: String,
    #[serde(skip)]
    password: String,
}

impl Account {
    pub fn new(username: String, password: String) -> Self {
        let password = bcrypt::hash(password.as_bytes(), bcrypt::DEFAULT_COST).unwrap();
        Self {
            id: Uuid::new_v4(),
            username,
            password
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        bcrypt::verify(password, &self.password).unwrap()
    }
}

impl AccountStorage {
    pub fn new() -> Self{
        Self (AccountMap::new(HashMap::new()))
    }

    #[allow(dead_code)]
    pub async fn get(&self, id: &Uuid) -> Option<Account> {
        let accounts = self.0.lock().await;
        Some(accounts.get(&id)?.clone())
    }

    pub async fn login(&self, username: &str, password: &str) -> Option<Account> {
        let accounts = self.0.lock().await;
        let account = accounts.values().find(|a| a.username == username)?;
        match account.verify_password(password) {
            true => Some(account.clone()),
            false => None,
        }
    }

    pub async fn register(&self, username: &str, password: &str) -> Result<Account, Error> {
        let mut accounts = self.0.lock().await;
        let account = Account::new(username.to_string(), password.to_string());
        accounts.insert(account.id.clone(), account.clone());
        Ok(account)
    }
}
