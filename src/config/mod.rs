use lazy_static::lazy_static;
use std::env::var;
use crate::oauth::jwk;

fn get_password_cost() -> u32 {
    let cost = var("PASSWORD_COST").unwrap_or("10".to_string());
    let parsed = cost.parse::<u32>();
    match parsed {
        Ok(cost) => cost,
        Err(e) => {
            eprintln!("Invalid cost {:?}, using default", e);
            10
        }
    }
}

lazy_static! {
    pub static ref PASSWORD_COST: u32 = get_password_cost();
    pub static ref KEY: jwk::Jwk = jwk::Jwk::new().unwrap();
}
