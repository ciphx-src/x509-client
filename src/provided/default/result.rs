use crate::api::X509IteratorError;
use crate::X509ClientError;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;

pub type DefaultX509IteratorResult<T> = result::Result<T, DefaultX509IteratorError>;

#[derive(Debug)]
pub enum DefaultX509IteratorError {
    Error(String),
    DerError(cms::cert::x509::der::Error),
}

impl X509IteratorError for DefaultX509IteratorError {}

impl Display for DefaultX509IteratorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultX509IteratorError::Error(e) => {
                write!(f, "default x509 iterator -> error: {}", e)
            }
            DefaultX509IteratorError::DerError(e) => {
                write!(f, "default x509 iterator -> der error: {}", e)
            }
        }
    }
}

impl Error for DefaultX509IteratorError {}

impl From<cms::cert::x509::der::Error> for DefaultX509IteratorError {
    fn from(e: cms::cert::x509::der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<DefaultX509IteratorError> for X509ClientError {
    fn from(e: DefaultX509IteratorError) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
