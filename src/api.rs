use std::fmt::{Debug, Display};

/// X509 Deserializer API
pub trait X509Iterator: IntoIterator
where
    Self: Sized,
{
    /// Error type
    type X509IteratorError: X509IteratorError;

    /// Attempt to deserialize, assume input is a single DER-encoded certificate
    fn from_cer<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError>;
    /// Attempt to deserialize, assume input is a stack of zero or more PEM-encoded certificates
    fn from_pem<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError>;
    /// Attempt to deserialize, assume input is a DER-encoded PKCS7 certificate bundle
    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError>;
}

/// Error type bounds
pub trait X509IteratorError: Display + Debug {}
