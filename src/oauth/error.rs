use jwt;
use rocket::http::Status;

#[derive(Debug)]
pub enum Error {
    InvalidGrantType,
    RateLimited,
    InvalidSecret,
    InvalidClient,
    InvalidToken,
    InvalidClientName,
    InvalidAuthHeader,
    InvalidAuthType,
    InvalidResourceAccess,
    JwtError(jwt::Error),
}

impl From<jwt::Error> for Error {
    fn from(e: jwt::Error) -> Self {
        Error::JwtError(e)
    }
}

impl Into<Status> for Error {
    fn into(self) -> Status {
        match self {
            Error::InvalidGrantType => Status::BadRequest,
            Error::RateLimited => Status::Forbidden,
            Error::InvalidSecret => Status::Unauthorized,
            Error::InvalidClient => Status::Unauthorized,
            Error::InvalidToken => Status::InternalServerError,  // can't remember why I did this
            Error::InvalidClientName => Status::BadRequest,
            Error::InvalidAuthHeader => Status::Unauthorized,
            Error::InvalidAuthType => Status::Unauthorized,
            Error::InvalidResourceAccess => Status::Forbidden,
            Error::JwtError(_) => Status::Unauthorized,
        }
    }
}