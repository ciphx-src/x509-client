use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::{io, result};

use crate::api::X509IteratorError;
use http::uri::InvalidUri;
use url::ParseError;

pub type X509ClientResult<T> = result::Result<T, X509ClientError>;

#[derive(Debug)]
pub enum X509ClientError {
    Error(String),
    IoError(io::Error),
    UrlParseError(String),
    ClientError(reqwest::Error),
    X509IteratorError(Box<dyn X509IteratorError>),
}

impl Display for X509ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            X509ClientError::Error(e) => write!(f, "x509-client -> error: {}", e),
            X509ClientError::IoError(e) => write!(f, "x509-client -> io error: {}", e),
            X509ClientError::UrlParseError(e) => write!(f, "x509-client -> url parse error: {}", e),
            X509ClientError::ClientError(e) => write!(f, "x509-client -> http client error: {}", e),
            X509ClientError::X509IteratorError(e) => write!(f, "x509-client -> {}", e),
        }
    }
}

impl Error for X509ClientError {}

impl X509IteratorError for X509ClientError {}

impl From<io::Error> for X509ClientError {
    fn from(e: io::Error) -> Self {
        X509ClientError::IoError(e)
    }
}

impl From<InvalidUri> for X509ClientError {
    fn from(e: InvalidUri) -> Self {
        X509ClientError::UrlParseError(e.to_string())
    }
}

impl From<ParseError> for X509ClientError {
    fn from(e: ParseError) -> Self {
        X509ClientError::UrlParseError(e.to_string())
    }
}

impl From<reqwest::Error> for X509ClientError {
    fn from(e: reqwest::Error) -> Self {
        X509ClientError::ClientError(e)
    }
}

impl From<Box<dyn X509IteratorError>> for X509ClientError {
    fn from(e: Box<dyn X509IteratorError>) -> Self {
        X509ClientError::X509IteratorError(e)
    }
}

impl X509IteratorError for Infallible {}

impl From<Infallible> for X509ClientError {
    fn from(e: Infallible) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
