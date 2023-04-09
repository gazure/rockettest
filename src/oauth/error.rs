use jwt;
use openssl::error::ErrorStack;
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
    InvalidCode,
    InvalidCodeChallengeMethod,
    Jwt(jwt::Error),
    OpenSSLError(ErrorStack),
}

impl From<jwt::Error> for Error {
    fn from(e: jwt::Error) -> Self {
        Error::Jwt(e)
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Error::OpenSSLError(e)
    }
}

impl From<Error> for Status {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidGrantType => Status::BadRequest,
            Error::RateLimited => Status::TooManyRequests,
            Error::InvalidSecret => Status::Unauthorized,
            Error::InvalidClient => Status::Unauthorized,
            Error::InvalidToken => Status::Unauthorized,
            Error::InvalidClientName => Status::BadRequest,
            Error::InvalidAuthHeader => Status::BadRequest,
            Error::InvalidAuthType => Status::BadRequest,
            Error::InvalidResourceAccess => Status::Forbidden,
            Error::InvalidCode => Status::Forbidden,
            Error::InvalidCodeChallengeMethod => Status::BadRequest,
            Error::Jwt(_) => Status::Unauthorized,
            Error::OpenSSLError(_) => Status::InternalServerError,
        }
    }
}
