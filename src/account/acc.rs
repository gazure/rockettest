use rocket::http::Status;
use rocket::serde::uuid::Uuid;
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use rocket::State;
use std::collections::HashMap;

/// TODO: Move this
#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    Username,
    Password,
    Account,
}

impl From<Error> for Status {
    fn from(e: Error) -> Self {
        match e {
            Error::Username => Status::BadRequest,
            Error::Password => Status::BadRequest,
            Error::Account => Status::BadRequest,
        }
    }
}
/// END TODO

type AccountMap = Mutex<HashMap<Uuid, Account>>;
pub type Accounts<'r> = &'r State<AccountStorage>;
pub struct AccountStorage(AccountMap);

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
            password,
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        bcrypt::verify(password, &self.password).unwrap()
    }
}

impl AccountStorage {
    pub fn new() -> Self {
        Self(AccountMap::new(HashMap::new()))
    }

    #[allow(dead_code)]
    pub async fn get(&self, id: &Uuid) -> Option<Account> {
        let accounts = self.0.lock().await;
        Some(accounts.get(id)?.clone())
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
        accounts.insert(account.id, account.clone());
        Ok(account)
    }
}
