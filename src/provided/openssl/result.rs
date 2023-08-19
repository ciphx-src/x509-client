use crate::api::X509IteratorError;
use crate::X509ClientError;
use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;

pub type OpenSSLX509IteratorResult<T> = result::Result<T, OpenSSLX509IteratorError>;

#[derive(Debug)]
pub enum OpenSSLX509IteratorError {
    Error(String),
    OpenSslErrorStack(ErrorStack),
    CmsDerError(cms::cert::x509::der::Error),
}

impl X509IteratorError for OpenSSLX509IteratorError {}

impl Display for OpenSSLX509IteratorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenSSLX509IteratorError::Error(e) => {
                write!(f, "openssl x509 iterator -> error: {}", e)
            }
            OpenSSLX509IteratorError::OpenSslErrorStack(e) => {
                write!(f, "openssl x509 iterator -> openssl error stack: {}", e)
            }
            OpenSSLX509IteratorError::CmsDerError(e) => {
                write!(f, "openssl x509 iterator -> cms der error: {}", e)
            }
        }
    }
}

impl Error for OpenSSLX509IteratorError {}

impl From<ErrorStack> for OpenSSLX509IteratorError {
    fn from(e: ErrorStack) -> Self {
        Self::OpenSslErrorStack(e)
    }
}

impl From<cms::cert::x509::der::Error> for OpenSSLX509IteratorError {
    fn from(e: cms::cert::x509::der::Error) -> Self {
        Self::CmsDerError(e)
    }
}

impl From<OpenSSLX509IteratorError> for X509ClientError {
    fn from(e: OpenSSLX509IteratorError) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
